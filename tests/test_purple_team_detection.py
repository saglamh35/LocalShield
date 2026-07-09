"""
Purple-team loop test: the VM-target DuckyScript payload's telemetry must be
caught by the shipped hid_injection rule. Loads the real rules/ directory so the
end-to-end attack -> detect path is exercised, mirroring
tests/test_hid_injection_rule.py, and drives the simulate_hid_attack replay.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import db_manager
from modules.detection_engine import DetectionEngine

TELEMETRY = ROOT / "payloads" / "duckyscript" / "vm" / "telemetry" / "win_recon_hidden.sysmon.json"


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine(rules_dir=str(ROOT / "rules"))


def _matched_ids(results):
    return {r["rule_id"] for r in results}


class TestPurpleTeamLoop:
    def test_sample_telemetry_exists_and_is_valid(self):
        data = json.loads(TELEMETRY.read_text(encoding="utf-8"))
        assert data["event_id"] == "1" and data["provider"] == "Sysmon"
        sysmon = data["sysmon"]
        assert "explorer.exe" in sysmon["ParentImage"].lower()
        assert "-w hidden" in sysmon["CommandLine"].lower()

    def test_payload_telemetry_trips_hid_injection(self, engine):
        """The VM payload's Sysmon telemetry must fire hid_injection_001 (T1200)."""
        data = json.loads(TELEMETRY.read_text(encoding="utf-8"))
        results = engine.check_event_all("1", datetime.now(), data["message"], "Sysmon", data["sysmon"])
        assert "hid_injection_001" in _matched_ids(results)
        hit = next(r for r in results if r["rule_id"] == "hid_injection_001")
        assert "T1200" in hit["mitre_techniques"]

    def test_benign_powershell_without_hidden_does_not_trip(self, engine):
        """A plain `powershell whoami` (no hidden/encoded flags) must NOT fire the rule."""
        sysmon = {
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe whoami",
        }
        results = engine.check_event_all("1", datetime.now(), "", "Sysmon", sysmon)
        assert "hid_injection_001" not in _matched_ids(results)


class TestSimulateReplay:
    def test_replay_stores_a_t1200_detection(self, tmp_path):
        from simulate_hid_attack import simulate_hid_attack

        db = str(tmp_path / "sim.db")
        result = simulate_hid_attack(telemetry_path=TELEMETRY, db_path=db)
        assert result.get("rule_id") == "hid_injection_001"
        # The detection was persisted with its MITRE technique.
        rows = db_manager.get_all_logs(db_path=db)
        assert len(rows) == 1
        assert rows[0][6] == "T1200"  # mitre_technique column
