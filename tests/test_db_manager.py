"""
Unit tests for db_manager: schema/indexes, audit actions and blocked-IP
persistence. Each test uses an isolated temporary database.
"""
import sqlite3
import sys
from pathlib import Path
from datetime import datetime

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import db_manager


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test.db")
    db_manager.init_db(path)
    return path


class TestSchema:
    def test_indexes_created(self, db):
        conn = sqlite3.connect(db)
        try:
            names = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
        finally:
            conn.close()
        assert "idx_logs_timestamp" in names
        assert "idx_logs_risk" in names

    def test_audit_tables_exist(self, db):
        conn = sqlite3.connect(db)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        finally:
            conn.close()
        assert {"security_logs", "actions", "blocked_ips"}.issubset(tables)


class TestActions:
    def test_record_and_read_action(self, db):
        db_manager.record_action("block_ip", target="8.8.8.8", details="Event 4625", db_path=db)
        rows = db_manager.get_recent_actions(db_path=db)
        assert len(rows) == 1
        _id, ts, atype, target, details = rows[0]
        assert atype == "block_ip"
        assert target == "8.8.8.8"

    def test_recent_actions_limit(self, db):
        for i in range(5):
            db_manager.record_action("block_ip", target=f"1.1.1.{i}", db_path=db)
        assert len(db_manager.get_recent_actions(limit=3, db_path=db)) == 3


class TestBlockedIPs:
    def test_persist_and_read(self, db):
        db_manager.record_blocked_ip("203.0.113.7", rule_name="T1110", reason="brute force", db_path=db)
        rows = db_manager.get_blocked_ips(db_path=db)
        assert len(rows) == 1
        ip, rule_name, blocked_at, reason = rows[0]
        assert ip == "203.0.113.7"
        assert rule_name == "T1110"

    def test_reblock_is_idempotent(self, db):
        db_manager.record_blocked_ip("203.0.113.7", reason="first", db_path=db)
        db_manager.record_blocked_ip("203.0.113.7", reason="second", db_path=db)
        rows = db_manager.get_blocked_ips(db_path=db)
        assert len(rows) == 1  # INSERT OR REPLACE keeps a single row
        assert rows[0][3] == "second"


class TestLogsStillWork:
    def test_insert_and_counts(self, db):
        db_manager.insert_log(datetime.now(), "4625", "m", "a", "High", "T1110", db_path=db)
        db_manager.insert_log(datetime.now(), "4624", "m", "a", "Low", None, db_path=db)
        assert db_manager.get_total_log_count(db) == 2
        assert db_manager.get_high_risk_count(db) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
