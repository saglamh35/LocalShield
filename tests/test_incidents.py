"""
Tests for incident grouping in db_manager: related high-risk detections for the
same key roll into one open incident within a window; different keys or events
outside the window open separate incidents.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import db_manager


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "inc.db")
    db_manager.init_db(path)
    return path


class TestIncidentGrouping:
    def test_same_key_within_window_groups(self, db):
        base = datetime.now()
        ids = []
        for i in range(4):
            ids.append(
                db_manager.upsert_incident(
                    key="203.0.113.5",
                    title="Brute force",
                    severity="High",
                    timestamp=base + timedelta(seconds=i * 10),
                    window_seconds=1800,
                    db_path=db,
                )
            )
        assert len(set(ids)) == 1  # all folded into one incident
        incidents = db_manager.get_incidents(db_path=db)
        assert len(incidents) == 1
        assert incidents[0][5] == 4  # event_count

    def test_different_keys_are_separate(self, db):
        now = datetime.now()
        db_manager.upsert_incident("1.1.1.1", "A", "High", timestamp=now, db_path=db)
        db_manager.upsert_incident("2.2.2.2", "B", "High", timestamp=now, db_path=db)
        assert len(db_manager.get_incidents(db_path=db)) == 2
        assert db_manager.get_open_incident_count(db) == 2

    def test_outside_window_opens_new_incident(self, db):
        base = datetime.now()
        db_manager.upsert_incident("5.5.5.5", "X", "High", timestamp=base, window_seconds=60, db_path=db)
        db_manager.upsert_incident(
            "5.5.5.5", "X", "High", timestamp=base + timedelta(seconds=600), window_seconds=60, db_path=db
        )
        assert len(db_manager.get_incidents(db_path=db)) == 2

    def test_max_severity_escalates(self, db):
        now = datetime.now()
        db_manager.upsert_incident("9.9.9.9", "X", "Medium", timestamp=now, db_path=db)
        db_manager.upsert_incident("9.9.9.9", "X", "Critical", timestamp=now + timedelta(seconds=5), db_path=db)
        inc = db_manager.get_incidents(db_path=db)[0]
        assert inc[6] == "Critical"  # max_severity escalated
        assert inc[5] == 2

    def test_open_incident_count(self, db):
        assert db_manager.get_open_incident_count(db) == 0
        db_manager.upsert_incident("k", "t", "High", db_path=db)
        assert db_manager.get_open_incident_count(db) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestIncidentTriage:
    def test_close_and_reopen(self, db):
        inc_id = db_manager.upsert_incident(
            key="203.0.113.9", title="Test", severity="High", timestamp=datetime.now(), db_path=db
        )
        assert db_manager.get_open_incident_count(db_path=db) == 1

        assert db_manager.set_incident_status(inc_id, "closed", db_path=db)
        assert db_manager.get_open_incident_count(db_path=db) == 0

        assert db_manager.set_incident_status(inc_id, "open", db_path=db)
        assert db_manager.get_open_incident_count(db_path=db) == 1

    def test_invalid_status_rejected(self, db):
        inc_id = db_manager.upsert_incident(
            key="203.0.113.10", title="Test", severity="High", timestamp=datetime.now(), db_path=db
        )
        assert not db_manager.set_incident_status(inc_id, "resolved; DROP TABLE incidents", db_path=db)
        assert db_manager.get_open_incident_count(db_path=db) == 1

    def test_unknown_id_returns_false(self, db):
        assert not db_manager.set_incident_status(999999, "closed", db_path=db)


class TestIncidentConcurrency:
    def test_concurrent_upserts_do_not_duplicate_or_lose_counts(self, db):
        # The watcher processes events in parallel; without serialization two
        # same-key events could both SELECT "no open incident" and both INSERT
        # (duplicates), or both read the same count (lost increment).
        from concurrent.futures import ThreadPoolExecutor

        now = datetime.now()

        def upsert(_):
            return db_manager.upsert_incident(
                key="203.0.113.9",
                title="Brute force",
                severity="High",
                timestamp=now,
                window_seconds=1800,
                db_path=db,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(upsert, range(20)))

        assert all(i > 0 for i in ids), "no upsert may fail"
        assert len(set(ids)) == 1, "all events must fold into a single incident"
        incidents = db_manager.get_incidents(db_path=db)
        assert len(incidents) == 1
        assert incidents[0][5] == 20, "every increment must be counted"
