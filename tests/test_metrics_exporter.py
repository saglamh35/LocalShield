"""
Tests for the Prometheus metrics exporter (modules/metrics_exporter.py).
Covers the pure render function (values + well-formedness) and the HTTP handler
(200 on /metrics, 404 elsewhere). Each test uses an isolated temporary database.
"""

import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import config
import db_manager
from modules import metrics_exporter as mx


@pytest.fixture
def seeded_db(tmp_path):
    path = str(tmp_path / "metrics.db")
    db_manager.init_db(path)
    # logs (one high-risk), an incident, a blocked IP, and vulnerabilities
    db_manager.insert_log(datetime.now(), "4625", "m", None, "High", None, db_path=path)
    db_manager.insert_log(datetime.now(), "4624", "m", None, "Low", None, db_path=path)
    db_manager.upsert_incident("203.0.113.7", "brute force", "high", db_path=path)
    db_manager.record_blocked_ip("203.0.113.7", db_path=path)
    db_manager.record_vulnerability(
        "CVE-1", "openssl", "img", fixed_version="1.1.1l-1", severity="Critical", db_path=path
    )
    db_manager.record_vulnerability("CVE-2", "bash", "img", fixed_version="5.1", severity="High", db_path=path)
    db_manager.record_vulnerability("CVE-3", "libc6", "img", fixed_version="", severity="Low", db_path=path)
    return path


def _metric_value(text, needle):
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(needle):
            return line[len(needle) :].strip()
    raise AssertionError(f"metric line not found: {needle!r}")


class TestRender:
    def test_values(self, seeded_db):
        out = mx.render_metrics(seeded_db)
        assert _metric_value(out, "localshield_up ") == "1"
        assert _metric_value(out, "localshield_logs_total ") == "2"
        assert _metric_value(out, "localshield_high_risk_total ") == "1"
        assert _metric_value(out, "localshield_open_incidents ") == "1"
        assert _metric_value(out, "localshield_blocked_ips ") == "1"
        assert _metric_value(out, 'localshield_vulnerabilities{severity="critical"} ') == "1"
        assert _metric_value(out, 'localshield_vulnerabilities{severity="high"} ') == "1"
        assert _metric_value(out, 'localshield_vulnerabilities{severity="low"} ') == "1"
        assert _metric_value(out, "localshield_vulnerabilities_total ") == "3"
        assert _metric_value(out, "localshield_vulnerabilities_fixable ") == "2"
        # 2 of 3 fixable
        assert _metric_value(out, "localshield_vulnerabilities_fixable_ratio ") == "0.6667"

    def test_every_metric_has_help_and_type(self, seeded_db):
        out = mx.render_metrics(seeded_db)
        for name in ("localshield_up", "localshield_vulnerabilities", "localshield_vulnerabilities_fixable_ratio"):
            assert f"# HELP {name} " in out
            assert f"# TYPE {name} gauge" in out

    def test_well_formed_sample_lines(self, seeded_db):
        out = mx.render_metrics(seeded_db)
        for line in out.splitlines():
            if not line or line.startswith("#"):
                continue
            # every sample line is "<name>[{labels}] <value>"
            name_part, _, value = line.rpartition(" ")
            assert name_part and value
            float(value)  # value must be numeric

    def test_empty_db_gives_zero_ratio(self, tmp_path):
        path = str(tmp_path / "empty.db")
        db_manager.init_db(path)
        out = mx.render_metrics(path)
        assert _metric_value(out, "localshield_vulnerabilities_total ") == "0"
        assert _metric_value(out, "localshield_vulnerabilities_fixable_ratio ") == "0.0000"


class TestServer:
    def test_metrics_endpoint_and_404(self, seeded_db, monkeypatch):
        # Point the handler's default db (config.DB_PATH) at the seeded temp DB.
        monkeypatch.setattr(config, "DB_PATH", seeded_db)
        server = mx.make_server(host="127.0.0.1", port=0)
        host, port = server.server_address[0], server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://{host}:{port}/metrics", timeout=5) as resp:
                assert resp.status == 200
                assert resp.headers.get("Content-Type", "").startswith("text/plain")
                body = resp.read().decode("utf-8")
            assert "localshield_vulnerabilities_total 3" in body

            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(f"http://{host}:{port}/nope", timeout=5)
            assert exc.value.code == 404
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
