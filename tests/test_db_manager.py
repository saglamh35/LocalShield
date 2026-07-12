"""
Unit tests for db_manager: schema/indexes, audit actions and blocked-IP
persistence. Each test uses an isolated temporary database.
"""

import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

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
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
        finally:
            conn.close()
        assert "idx_logs_timestamp" in names
        assert "idx_logs_risk" in names

    def test_audit_tables_exist(self, db):
        conn = sqlite3.connect(db)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
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


class TestRetention:
    def test_zero_retention_deletes_nothing(self, db):
        db_manager.insert_log(datetime.now() - timedelta(days=365), "4625", "old", None, "Low", None, db_path=db)
        assert db_manager.purge_old_logs(retention_days=0, db_path=db) == 0
        assert db_manager.get_total_log_count(db) == 1

    def test_purge_deletes_only_expired_rows(self, db):
        now = datetime.now()
        db_manager.insert_log(now - timedelta(days=40), "4625", "old", None, "Low", None, db_path=db)
        db_manager.insert_log(now, "4624", "fresh", None, "Low", None, db_path=db)
        deleted = db_manager.purge_old_logs(retention_days=30, now=now, db_path=db)
        assert deleted == 1
        assert db_manager.get_total_log_count(db) == 1

    def test_purge_covers_actions_table(self, db):
        now = datetime.now()
        db_manager.record_action("block_ip", target="1.2.3.4", timestamp=now - timedelta(days=40), db_path=db)
        db_manager.record_action("block_ip", target="5.6.7.8", timestamp=now, db_path=db)
        assert db_manager.purge_old_logs(retention_days=30, now=now, db_path=db) == 1
        assert len(db_manager.get_recent_actions(db_path=db)) == 1

    def test_incidents_and_blocked_ips_are_kept(self, db):
        now = datetime.now()
        db_manager.record_blocked_ip("203.0.113.7", timestamp=now - timedelta(days=100), db_path=db)
        db_manager.upsert_incident(
            "203.0.113.7", "old incident", "high", timestamp=now - timedelta(days=100), db_path=db
        )
        db_manager.purge_old_logs(retention_days=30, now=now, db_path=db)
        assert len(db_manager.get_blocked_ips(db_path=db)) == 1
        assert len(db_manager.get_incidents(db_path=db)) == 1


class TestTimedBlocks:
    def test_expired_block_is_returned(self, db):
        now = datetime.now()
        db_manager.record_blocked_ip("203.0.113.7", expires_at=now - timedelta(minutes=5), db_path=db)
        assert db_manager.get_expired_blocked_ips(now=now, db_path=db) == ["203.0.113.7"]

    def test_future_expiry_is_not_returned(self, db):
        now = datetime.now()
        db_manager.record_blocked_ip("203.0.113.7", expires_at=now + timedelta(minutes=60), db_path=db)
        assert db_manager.get_expired_blocked_ips(now=now, db_path=db) == []

    def test_permanent_block_is_never_returned(self, db):
        db_manager.record_blocked_ip("203.0.113.7", db_path=db)  # expires_at=None
        assert db_manager.get_expired_blocked_ips(db_path=db) == []

    def test_remove_blocked_ip(self, db):
        db_manager.record_blocked_ip("203.0.113.7", db_path=db)
        db_manager.remove_blocked_ip("203.0.113.7", db_path=db)
        assert db_manager.get_blocked_ips(db_path=db) == []

    def test_expires_at_column_added_to_legacy_db(self, tmp_path):
        # Simulate a database created before timed blocks existed
        legacy = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(legacy)
        conn.execute(
            "CREATE TABLE blocked_ips (ip TEXT PRIMARY KEY, rule_name TEXT, blocked_at DATETIME NOT NULL, reason TEXT)"
        )
        conn.commit()
        conn.close()
        db_manager.init_db(legacy)  # migration adds expires_at
        db_manager.record_blocked_ip("203.0.113.7", expires_at=datetime.now(), db_path=legacy)
        assert db_manager.get_expired_blocked_ips(db_path=legacy) == ["203.0.113.7"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestHeartbeat:
    def test_no_heartbeat_returns_none(self, db):
        assert db_manager.get_heartbeat("log_watcher", db_path=db) is None

    def test_record_and_read_roundtrip(self, db):
        ts = datetime(2026, 7, 12, 10, 30, 0)
        db_manager.record_heartbeat("log_watcher", timestamp=ts, db_path=db)
        assert db_manager.get_heartbeat("log_watcher", db_path=db) == ts

    def test_upsert_keeps_latest(self, db):
        db_manager.record_heartbeat("log_watcher", timestamp=datetime(2026, 7, 12, 10, 0, 0), db_path=db)
        later = datetime(2026, 7, 12, 10, 5, 0)
        db_manager.record_heartbeat("log_watcher", timestamp=later, db_path=db)
        assert db_manager.get_heartbeat("log_watcher", db_path=db) == later

    def test_components_are_independent(self, db):
        db_manager.record_heartbeat("log_watcher", timestamp=datetime(2026, 7, 12, 10, 0, 0), db_path=db)
        assert db_manager.get_heartbeat("metrics_exporter", db_path=db) is None
