"""
Tests for the cross-platform SSH auth.log importer.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine
from modules.log_importer import import_auth_log, parse_auth_line


class TestParseAuthLine:
    def test_failed_password(self):
        line = "Jan 10 06:55:01 srv sshd[111]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"
        ev = parse_auth_line(line, default_year=2024)
        assert ev is not None
        assert ev["event_id"] == "4625"
        assert ev["outcome"] == "failure"
        assert ev["user"] == "admin"
        assert ev["source_ip"] == "203.0.113.5"
        assert ev["timestamp"].year == 2024
        assert ev["timestamp"].month == 1

    def test_accepted_password(self):
        line = "Jan 10 07:00:00 srv sshd[222]: Accepted password for alice from 10.0.0.9 port 22 ssh2"
        ev = parse_auth_line(line, default_year=2024)
        assert ev["event_id"] == "4624"
        assert ev["outcome"] == "success"
        assert ev["user"] == "alice"
        assert ev["source_ip"] == "10.0.0.9"

    def test_pam_authentication_failure(self):
        line = ("Jan 10 06:55:10 srv sshd[333]: pam_unix(sshd:auth): authentication failure; "
                "logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.7 user=root")
        ev = parse_auth_line(line, default_year=2024)
        assert ev["event_id"] == "4625"
        assert ev["source_ip"] == "198.51.100.7"

    def test_non_auth_line_returns_none(self):
        assert parse_auth_line("Jan 10 06:55:01 srv systemd[1]: Started Daily apt.", 2024) is None
        assert parse_auth_line("", 2024) is None


class TestImportAuthLog:
    def test_brute_force_detected_from_auth_log(self, tmp_path):
        # 5 failed logons from the same host within one minute -> brute force rule
        lines = [
            f"Jan 10 06:55:0{i} srv sshd[{100+i}]: "
            f"Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"
            for i in range(1, 6)
        ]
        log_file = tmp_path / "auth.log"
        log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        db_file = str(tmp_path / "test.db")
        import db_manager
        db_manager.init_db(db_file)

        rules_dir = Path(__file__).parent.parent / "rules"
        engine = DetectionEngine(rules_dir=str(rules_dir))

        summary = import_auth_log(
            str(log_file), engine=engine, db_path=db_file, default_year=2024
        )

        assert summary["parsed"] == 5
        assert summary["inserted"] == 5
        assert summary["detections"] >= 1, "brute force should trigger on the 5th failure"
        assert db_manager.get_total_log_count(db_file) == 5

    def test_import_without_insert(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "Jan 10 07:00:00 srv sshd[9]: Accepted password for alice from 10.0.0.9 port 22 ssh2\n",
            encoding="utf-8",
        )
        rules_dir = Path(__file__).parent.parent / "rules"
        engine = DetectionEngine(rules_dir=str(rules_dir))
        summary = import_auth_log(str(log_file), engine=engine, insert=False, default_year=2024)
        assert summary["parsed"] == 1
        assert summary["inserted"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
