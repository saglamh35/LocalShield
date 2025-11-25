"""
Unit Tests for Detection Engine
Tests rule loading, brute force detection, and time window functionality
"""
import pytest
import tempfile
import shutil
import sys
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Add parent directory to path to import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine, DetectionRule


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
        """Sample YAML rule content"""
        return """
name: "Brute Force Attack Detection"
description: "EventID 4625 (Failed Logon) için brute force saldırısı tespiti"
enabled: true
priority: "high"

conditions:
  event_id: "4625"
  time_window: 60  # saniye cinsinden (1 dakika)
  threshold: 5     # Bu süre içinde kaç tekrar olursa tetiklenir

risk_level: "Yüksek"
mitre_technique: "T1110"
match_message: "Detection Rule Match: Brute Force Attack - EventID 4625 tekrar sayısı eşiği aşıldı"

filters:
  exclude_users: []
  include_users: []
"""
    
    def test_rule_file_loading(self, temp_rules_dir, sample_rule_yaml):
        """Test: Kural dosyası doğru yükleniyor mu?"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding='utf-8')
        
        # Initialize DetectionEngine with temp directory
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        
        # Assert that rule was loaded
        assert len(engine.rules) == 1, "Kural dosyası yüklenemedi"
        assert engine.rules[0].name == "Brute Force Attack Detection", "Kural adı yanlış"
        assert engine.rules[0].event_id == "4625", "Event ID yanlış"
        assert engine.rules[0].threshold == 5, "Threshold değeri yanlış"
        assert engine.rules[0].time_window == 60, "Time window değeri yanlış"
        assert engine.rules[0].mitre_technique == "T1110", "MITRE tekniği yanlış"
    
    def test_4_failed_logins_should_not_trigger(self, temp_rules_dir, sample_rule_yaml):
        """Test: 1 dakika içinde 4 başarısız giriş (Event 4625) kuralı TETİKLEMEMELİ"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding='utf-8')
        
        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        rule = engine.rules[0]
        
        # Simulate 4 failed logins within 1 minute
        base_time = datetime.now()
        message = "Account Name: ATTACKER"
        
        for i in range(4):
            timestamp = base_time + timedelta(seconds=i * 10)  # 10 saniye arayla
            result = engine.check_event("4625", timestamp, message)
            # Should not trigger yet (threshold is 5)
            assert result is None, f"4. başarısız girişte tetiklenmemeli (i={i})"
        
        # Verify rule's internal state
        assert len(rule.event_history["4625"]) == 4, "Event history'de 4 kayıt olmalı"
    
    def test_5_failed_logins_should_trigger(self, temp_rules_dir, sample_rule_yaml):
        """Test: 1 dakika içinde 5 başarısız giriş kuralı TETİKLEMELİ (Detection)"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding='utf-8')
        
        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        
        # Simulate 5 failed logins within 1 minute
        base_time = datetime.now()
        message = "Account Name: ATTACKER"
        
        detection_triggered = False
        for i in range(5):
            timestamp = base_time + timedelta(seconds=i * 10)  # 10 saniye arayla
            result = engine.check_event("4625", timestamp, message)
            
            if i < 4:
                # First 4 should not trigger
                assert result is None, f"{i+1}. başarısız girişte tetiklenmemeli"
            else:
                # 5th should trigger
                assert result is not None, "5. başarısız girişte tetiklenmeli"
                assert result['risk_level'] == "Yüksek", "Risk seviyesi 'Yüksek' olmalı"
                assert result['mitre_technique'] == "T1110", "MITRE tekniği 'T1110' olmalı"
                assert "Brute Force" in result['match_message'], "Match message'da 'Brute Force' olmalı"
                detection_triggered = True
        
        assert detection_triggered, "Detection tetiklenmeli"
    
    def test_time_window_resets_counter(self, temp_rules_dir, sample_rule_yaml):
        """Test: Zaman penceresi (time window) dışındaki loglar sayacı sıfırlıyor mu?"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding='utf-8')
        
        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        rule = engine.rules[0]
        
        base_time = datetime.now()
        message = "Account Name: ATTACKER"
        
        # Add 3 events within time window
        for i in range(3):
            timestamp = base_time + timedelta(seconds=i * 10)
            engine.check_event("4625", timestamp, message)
        
        # Verify we have 3 events
        assert len(rule.event_history["4625"]) == 3, "İlk 3 event kaydedilmeli"
        
        # Add an event OUTSIDE the time window (more than 60 seconds later)
        old_timestamp = base_time + timedelta(seconds=70)  # 70 seconds later (outside 60s window)
        engine.check_event("4625", old_timestamp, message)
        
        # The old event should be cleaned up, but we still have the 3 recent ones
        # Actually, wait - the old event is added AFTER the window, so it should be the only one
        # Let me reconsider: if we add an event 70 seconds after base_time, and the window is 60 seconds,
        # then when we check that event, it should clean up events older than (old_timestamp - 60 seconds)
        # So events from base_time should be cleaned up
        
        # Actually, let's test it differently: add 3 events, wait, then add 2 more
        # The first 3 should be cleaned up if they're outside the window
        
        # Clear and restart
        rule.event_history.clear()
        
        # Add 3 events at time 0, 11, 22 (boundary condition'dan kaçınmak için 10 yerine 11 kullanıyoruz)
        # Bu şekilde T+70'te cleanup yapıldığında (cutoff = T+10), T+11 ve T+22 eventleri korunacak
        timestamps = [
            base_time + timedelta(seconds=0),   # T+0
            base_time + timedelta(seconds=11),  # T+11 (boundary'den kaçınmak için)
            base_time + timedelta(seconds=22)   # T+22
        ]
        for timestamp in timestamps:
            engine.check_event("4625", timestamp, message)
        
        # Verify we have 3 events initially
        assert len(rule.event_history["4625"]) == 3, "İlk 3 event kaydedilmeli"
        
        # Now add an event at time 70 (cutoff = 70 - 60 = 10)
        # T+0 eventi silinmeli (< T+10), T+11 ve T+22 kalmalı (> T+10)
        timestamp_70 = base_time + timedelta(seconds=70)
        engine.check_event("4625", timestamp_70, message)
        
        # Events at time 0 should be removed (outside window), but time 11, 22, and 70 should remain
        # Cutoff is timestamp_70 - 60 = 10, so events at T+0 are removed (< T+10)
        # Events at T+11, T+22, and T+70 remain (> T+10)
        remaining_events = rule.event_history["4625"]
        assert len(remaining_events) == 3, f"3 event kalmalı (11, 22, 70), ama {len(remaining_events)} event kaldı"
        
        # Verify that old events (before cutoff) are removed
        cutoff_time = timestamp_70 - timedelta(seconds=60)  # T+10
        for ts, _ in remaining_events:
            assert ts > cutoff_time, f"Eski event temizlenmemiş: {ts} > {cutoff_time} olmalı"
        
        # Verify specific timestamps are present
        remaining_times = [ts for ts, _ in remaining_events]
        assert base_time + timedelta(seconds=11) in remaining_times, "T+11 eventi kalmalı"
        assert base_time + timedelta(seconds=22) in remaining_times, "T+22 eventi kalmalı"
        assert base_time + timedelta(seconds=70) in remaining_times, "T+70 eventi kalmalı"
        assert base_time + timedelta(seconds=0) not in remaining_times, "T+0 eventi silinmeli"
    
    def test_different_event_id_should_not_match(self, temp_rules_dir, sample_rule_yaml):
        """Test: Farklı Event ID'ler kuralı tetiklememeli"""
        # Create a rule file
        rule_file = temp_rules_dir / "brute_force.yaml"
        rule_file.write_text(sample_rule_yaml, encoding='utf-8')
        
        # Initialize DetectionEngine
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        
        # Try with different event IDs
        base_time = datetime.now()
        message = "Account Name: ATTACKER"
        
        # Event ID 4624 (successful logon) should not trigger
        result = engine.check_event("4624", base_time, message)
        assert result is None, "Event ID 4624 tetiklenmemeli"
        
        # Event ID 4625 should match
        result = engine.check_event("4625", base_time, message)
        # This alone shouldn't trigger (need 5), but it should be processed
        assert result is None, "Tek bir 4625 event tetiklenmemeli (threshold 5)"
    
    def test_disabled_rule_should_not_trigger(self, temp_rules_dir):
        """Test: Disabled kural tetiklenmemeli"""
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
        rule_file.write_text(disabled_rule_yaml, encoding='utf-8')
        
        engine = DetectionEngine(rules_dir=str(temp_rules_dir))
        assert len(engine.rules) == 1
        
        # Even with threshold=1, disabled rule should not trigger
        result = engine.check_event("4625", datetime.now(), "Test message")
        assert result is None, "Disabled kural tetiklenmemeli"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

