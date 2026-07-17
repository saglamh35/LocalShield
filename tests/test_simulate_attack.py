"""
Tests that the attack simulator does what it advertises: events run through
the real detection engine, so 5+ attempts inside the rule window produce a
High / MITRE T1110 detection, and fewer attempts stay Medium.
"""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from simulate_attack import simulate_brute_force_attack


def _rows(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT risk_score, mitre_technique FROM security_logs ORDER BY id").fetchall()
    finally:
        conn.close()


def test_threshold_attack_fires_brute_force_rule(tmp_path):
    db = str(tmp_path / "sim.db")
    simulate_brute_force_attack(num_attempts=5, time_window_seconds=30, db_path=db)

    rows = _rows(db)
    assert len(rows) == 5
    detected = [r for r in rows if r[1] == "T1110"]
    assert detected, "the 5th attempt within the window must fire brute_force_001"
    assert all(r[0] == "High" for r in detected)
    # Attempts below the threshold stay individual Medium failures
    assert all(r == ("Medium", None) for r in rows[:4])


def test_below_threshold_attack_stays_medium(tmp_path):
    db = str(tmp_path / "sim.db")
    simulate_brute_force_attack(num_attempts=3, time_window_seconds=30, db_path=db)

    rows = _rows(db)
    assert len(rows) == 3
    assert all(r == ("Medium", None) for r in rows), "3 attempts must not trigger the 5-attempt rule"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
