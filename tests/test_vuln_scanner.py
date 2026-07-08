"""
Tests for the Trivy-based vulnerability scanner (modules/vuln_scanner.py) and
its db_manager storage helpers. Uses a canned Trivy JSON fixture, so it runs
without Trivy installed. Each test uses an isolated temporary database.
"""

import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import db_manager
from modules.vuln_scanner import VulnScanner

# Minimal but realistic `trivy image --format json` output.
TRIVY_FIXTURE = json.dumps(
    {
        "Results": [
            {
                "Target": "python:3.9-slim (debian 11.2)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-3711",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1k-1",
                        "FixedVersion": "1.1.1l-1",
                        "Severity": "CRITICAL",
                        "Title": "openssl: SM2 Decryption Buffer Overflow",
                        "CVSS": {"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 7.5}},
                    },
                    {
                        "VulnerabilityID": "CVE-2021-1234",
                        "PkgName": "libc6",
                        "InstalledVersion": "2.31",
                        "FixedVersion": "",
                        "Severity": "HIGH",
                        "Title": "example high with no fix",
                        "CVSS": {"redhat": {"V2Score": 6.4}},
                    },
                    {
                        "VulnerabilityID": "CVE-2020-0001",
                        "PkgName": "bash",
                        "InstalledVersion": "5.0",
                        "FixedVersion": "5.1",
                        "Severity": "LOW",
                    },
                    # Malformed entry (no ID) must be skipped, not crash.
                    {"PkgName": "ghost", "Severity": "HIGH"},
                ],
            },
            # A result with no vulnerabilities must be tolerated.
            {"Target": "empty", "Vulnerabilities": None},
        ]
    }
)


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test.db")
    db_manager.init_db(path)
    return path


class TestSchema:
    def test_vulnerabilities_table_exists(self, db):
        conn = sqlite3.connect(db)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        finally:
            conn.close()
        assert "vulnerabilities" in tables


class TestParsing:
    def test_parse_normalizes_and_skips_malformed(self):
        scanner = VulnScanner()
        findings = scanner._parse(TRIVY_FIXTURE, "python:3.9-slim", "image")
        # 3 valid findings; the ID-less entry and the empty result are dropped.
        assert len(findings) == 3
        by_cve = {f["cve_id"]: f for f in findings}
        crit = by_cve["CVE-2021-3711"]
        assert crit["package"] == "openssl"
        assert crit["severity"] == "Critical"
        assert crit["fixed_version"] == "1.1.1l-1"
        assert crit["target"] == "python:3.9-slim"
        assert crit["target_type"] == "image"

    def test_cvss_prefers_nvd_v3_then_falls_back(self):
        scanner = VulnScanner()
        findings = {f["cve_id"]: f for f in scanner._parse(TRIVY_FIXTURE, "img", "image")}
        assert findings["CVE-2021-3711"]["cvss"] == 9.8  # nvd V3 preferred over redhat
        assert findings["CVE-2021-1234"]["cvss"] == 6.4  # falls back to V2 score
        assert findings["CVE-2020-0001"]["cvss"] is None  # no CVSS at all

    def test_parse_invalid_json_returns_empty(self):
        assert VulnScanner()._parse("not json", "img", "image") == []


class TestStorage:
    def test_findings_land_in_db(self, db):
        scanner = VulnScanner(db_path=db)
        scanner._store(scanner._parse(TRIVY_FIXTURE, "python:3.9-slim", "image"), datetime.now())
        rows = db_manager.get_vulnerabilities(db_path=db)
        assert len(rows) == 3
        # Ordered most-severe-first: Critical CVE leads.
        assert rows[0][1] == "CVE-2021-3711"

    def test_rescan_upserts_not_duplicates(self, db):
        scanner = VulnScanner(db_path=db)
        findings = scanner._parse(TRIVY_FIXTURE, "python:3.9-slim", "image")
        scanner._store(findings, datetime.now())
        scanner._store(findings, datetime.now())  # scan again
        assert len(db_manager.get_vulnerabilities(db_path=db)) == 3  # no multiplication

    def test_counts_and_fixable(self, db):
        scanner = VulnScanner(db_path=db)
        scanner._store(scanner._parse(TRIVY_FIXTURE, "img", "image"), datetime.now())
        counts = db_manager.get_vulnerability_counts(db_path=db)
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["low"] == 1
        assert counts["total"] == 3
        assert counts["fixable"] == 2  # empty FixedVersion is not fixable

    def test_severity_filter(self, db):
        scanner = VulnScanner(db_path=db)
        scanner._store(scanner._parse(TRIVY_FIXTURE, "img", "image"), datetime.now())
        assert len(db_manager.get_vulnerabilities(severity="Critical", db_path=db)) == 1
        assert len(db_manager.get_vulnerabilities(fixable_only=True, db_path=db)) == 2


class TestGracefulDegradation:
    def test_unavailable_trivy_disables_scanning(self, db, monkeypatch):
        import modules.vuln_scanner as vs

        monkeypatch.setattr(vs.shutil, "which", lambda _: None)
        scanner = VulnScanner(db_path=db)
        assert scanner.is_available() is False
        # No exception, empty findings, and a clean "disabled" summary.
        assert scanner.scan_image("python:3.9-slim") == []
        result = scanner.scan_configured_targets()
        assert result["available"] is False
        assert result["findings"] == 0


class TestNotificationSummary:
    def test_one_summary_notification_above_threshold(self, db, monkeypatch):
        import modules.vuln_scanner as vs

        calls = []

        class FakeNotifier:
            def notify(self, **kwargs):
                calls.append(kwargs)

        monkeypatch.setattr(vs, "get_notifier", lambda: FakeNotifier())
        scanner = VulnScanner(db_path=db, notify_min_severity="High")
        findings = scanner._parse(TRIVY_FIXTURE, "img", "image")
        scanner._notify_summary(findings, scanner._count_by_severity(findings))
        assert len(calls) == 1  # exactly one alert for the whole scan, not per-CVE
        assert calls[0]["severity"] == "Critical"

    def test_no_notification_below_threshold(self, db, monkeypatch):
        import modules.vuln_scanner as vs

        calls = []

        class FakeNotifier:
            def notify(self, **kwargs):
                calls.append(kwargs)

        monkeypatch.setattr(vs, "get_notifier", lambda: FakeNotifier())
        scanner = VulnScanner(db_path=db, notify_min_severity="Critical")
        # Only a LOW finding -> below the Critical threshold -> no alert.
        low_only = [f for f in scanner._parse(TRIVY_FIXTURE, "img", "image") if f["severity"] == "Low"]
        scanner._notify_summary(low_only, scanner._count_by_severity(low_only))
        assert calls == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
