"""
Unit Tests for Detection Engine
Tests rule loading, brute force detection, and time window functionality
"""

import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Add parent directory to path to import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine


class TestDetectionEngine:
    """Test suite for DetectionEngine"""

    @pytest.fixture
    def temp_rules_dir(self):
        """Create a temporary rules directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_rule_yaml(self):
        """Sample YAML rule content (current schema: severity + mitre list)"""
        return """
id: "brute_force_001"
name: "Brute Force Attack Detection"
description: "Brute force attack detection for EventID 4625 (Failed Logon)"
enabled: true
severity: "high"
mitre:
  - "T1110"
tags:
  - "brute_force"

conditions:
  event_id: "4625"
  time_window: 60  # seconds (1 minute)
  threshold: 5     # number of repeats within the window before triggering

match_message: "Detection Rule Match: Brute Force Attack - EventID 4625 threshold exceeded"

filters:
  exclude_users: []
  include_users: []
"""

    def test_rule_file_loading(self, temp_rules_dir, sample_rule_yaml):
        """Test: is the rule file loaded correctly?"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding="utf-8")

        # Initialize DetectionEngine with temp directory
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))

        # Assert that rule was loaded
        assert len(engine.rules) == 1, "Rule file could not be loaded"
        assert engine.rules[0].name == "Brute Force Attack Detection", "Rule name is wrong"
        assert engine.rules[0].event_id == "4625", "Event ID is wrong"
        assert engine.rules[0].threshold == 5, "Threshold value is wrong"
        assert engine.rules[0].time_window == 60, "Time window value is wrong"
        assert engine.rules[0].mitre == ["T1110"], "MITRE technique is wrong"

    def test_4_failed_logins_should_not_trigger(self, temp_rules_dir, sample_rule_yaml):
        """Test: 4 failed logins (Event 4625) within 1 minute must NOT trigger the rule"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding="utf-8")

        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        rule = engine.rules[0]

        # Simulate 4 failed logins within 1 minute
        base_time = datetime.now()
        message = "Account Name: ATTACKER"

        for i in range(4):
            timestamp = base_time + timedelta(seconds=i * 10)  # 10 seconds apart
            result = engine.check_event("4625", timestamp, message)
            # Should not trigger yet (threshold is 5)
            assert result is None, f"Must not trigger on failed login #{i + 1}"

        # Verify rule's internal state
        assert len(rule.event_history["4625"]) == 4, "Event history should contain 4 records"

    def test_5_failed_logins_should_trigger(self, temp_rules_dir, sample_rule_yaml):
        """Test: 5 failed logins within 1 minute MUST trigger the rule (Detection)"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding="utf-8")

        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))

        # Simulate 5 failed logins within 1 minute
        base_time = datetime.now()
        message = "Account Name: ATTACKER"

        detection_triggered = False
        for i in range(5):
            timestamp = base_time + timedelta(seconds=i * 10)  # 10 seconds apart
            result = engine.check_event("4625", timestamp, message)

            if i < 4:
                # First 4 should not trigger
                assert result is None, f"Must not trigger on failed login #{i + 1}"
            else:
                # 5th should trigger
                assert result is not None, "Must trigger on the 5th failed login"
                assert result["risk_level"] == "High", "Risk level should be 'High'"
                assert result["mitre_technique"] == "T1110", "MITRE technique should be 'T1110'"
                assert "Brute Force" in result["match_message"], "Match message should contain 'Brute Force'"
                detection_triggered = True

        assert detection_triggered, "Detection must trigger"

    def test_time_window_resets_counter(self, temp_rules_dir, sample_rule_yaml):
        """Test: are events outside the time window pruned from the counter?"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding="utf-8")

        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        rule = engine.rules[0]

        base_time = datetime.now()
        message = "Account Name: ATTACKER"

        # Add 3 events at T+0, T+11, T+22 (11 instead of 10 avoids the cutoff
        # boundary: with the cleanup at T+70 the cutoff is exactly T+10, so
        # the T+11 and T+22 events must survive while T+0 is pruned)
        timestamps = [
            base_time + timedelta(seconds=0),  # T+0
            base_time + timedelta(seconds=11),  # T+11 (avoids the boundary)
            base_time + timedelta(seconds=22),  # T+22
        ]
        for timestamp in timestamps:
            engine.check_event("4625", timestamp, message)

        # Verify we have 3 events initially
        assert len(rule.event_history["4625"]) == 3, "The first 3 events should be recorded"

        # Now add an event at time 70 (cutoff = 70 - 60 = 10)
        # The T+0 event must be pruned (< T+10); T+11 and T+22 must remain
        timestamp_70 = base_time + timedelta(seconds=70)
        engine.check_event("4625", timestamp_70, message)

        # Events at time 0 should be removed (outside window), but time 11, 22, and 70 should remain
        remaining_events = rule.event_history["4625"]
        assert len(remaining_events) == 3, f"3 events should remain (11, 22, 70), but {len(remaining_events)} remained"

        # Verify that old events (before cutoff) are removed
        cutoff_time = timestamp_70 - timedelta(seconds=60)  # T+10
        for ts, _ in remaining_events:
            assert ts > cutoff_time, f"Stale event was not pruned: {ts} should be > {cutoff_time}"

        # Verify specific timestamps are present
        remaining_times = [ts for ts, _ in remaining_events]
        assert base_time + timedelta(seconds=11) in remaining_times, "The T+11 event should remain"
        assert base_time + timedelta(seconds=22) in remaining_times, "The T+22 event should remain"
        assert base_time + timedelta(seconds=70) in remaining_times, "The T+70 event should remain"
        assert base_time + timedelta(seconds=0) not in remaining_times, "The T+0 event should be pruned"

    def test_different_event_id_should_not_match(self, temp_rules_dir, sample_rule_yaml):
        """Test: different Event IDs must not trigger the rule"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding="utf-8")

        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))

        # Try with different event IDs
        base_time = datetime.now()
        message = "Account Name: ATTACKER"

        # Event ID 4624 (successful logon) should not trigger
        result = engine.check_event("4624", base_time, message)
        assert result is None, "Event ID 4624 must not trigger"

        # Event ID 4625 should match
        result = engine.check_event("4625", base_time, message)
        # This alone shouldn't trigger (need 5), but it should be processed
        assert result is None, "A single 4625 event must not trigger (threshold 5)"

    def test_threshold_counting_is_thread_safe(self, temp_rules_dir, sample_rule_yaml):
        """Test: concurrent check_event calls (log_watcher runs the engine on a
        thread pool) must not lose threshold increments"""
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding="utf-8")

        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        rule = engine.rules[0]

        base_time = datetime.now()
        message = "Account Name: ATTACKER"
        num_events = 200  # all within the 60s window, so none get pruned

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(engine.check_event, "4625", base_time + timedelta(milliseconds=i), message)
                for i in range(num_events)
            ]
            for future in futures:
                future.result()

        # Without locking, the prune-and-reassign in matches() races with
        # concurrent appends and silently drops events.
        assert len(rule.event_history["4625"]) == num_events, (
            f"Expected {num_events} recorded events, got {len(rule.event_history['4625'])} (lost increments)"
        )

    def test_disabled_rule_should_not_trigger(self, temp_rules_dir):
        """Test: a disabled rule must not trigger"""
        # This fixture intentionally uses the legacy rule format (risk_level
        # with the pre-migration Turkish value) to keep the backward-compat
        # mapping in DetectionRule covered.
        disabled_rule_yaml = """
name: "Disabled Rule"
description: "Test disabled rule"
enabled: false
priority: "high"

conditions:
  event_id: "4625"
  time_window: 60
  threshold: 1

risk_level: "Yüksek"
mitre_technique: "T1110"
match_message: "Should not trigger"
"""
        rule_file = temp_rules_dir / "disabled_rule.yaml"
        rule_file.write_text(disabled_rule_yaml, encoding="utf-8")

        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        assert len(engine.rules) == 1

        # Even with threshold=1, disabled rule should not trigger
        result = engine.check_event("4625", datetime.now(), "Test message")
        assert result is None, "A disabled rule must not trigger"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
