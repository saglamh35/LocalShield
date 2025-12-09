"""
Test Suite for New Detection Engine Rules
Tests the new YAML schema with real rules from the rules/ directory
"""
import pytest
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path to import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.detection_engine import DetectionEngine


class TestNewRules:
    """Test suite for new detection engine rules"""
    
    @pytest.fixture
    def detection_engine(self):
        """Initialize DetectionEngine with real rules directory"""
        # Use the actual rules directory
        rules_dir = Path(__file__).parent.parent / "rules"
        engine = DetectionEngine(rules_dir=str(rules_dir))
        return engine
    
    def test_setup_rules_loaded(self, detection_engine):
        """Test Setup: Verify that DetectionEngine loads rules from rules/ directory"""
        assert detection_engine is not None, "DetectionEngine should be initialized"
        assert len(detection_engine.rules) > 0, "At least one rule should be loaded"
        
        # Check that we have the expected rules
        rule_names = [rule.name for rule in detection_engine.rules]
        rule_ids = [rule.id for rule in detection_engine.rules]
        
        print(f"\nLoaded {len(detection_engine.rules)} rules:")
        for rule in detection_engine.rules:
            print(f"  - {rule.name} (ID: {rule.id}, Enabled: {rule.enabled})")
        
        # Verify specific rules exist
        assert any("brute" in name.lower() for name in rule_names), "Brute force rule should be loaded"
        assert any("powershell" in name.lower() for name in rule_names), "PowerShell rule should be loaded"
        assert any("parent" in name.lower() or "child" in name.lower() for name in rule_names), "Parent-child rule should be loaded"
    
    def test_scenario_1_brute_force(self, detection_engine):
        """
        Senaryo 1 (Brute Force): 
        Event ID 4625 ile 1 dakika içinde 5 adet başarısız giriş logu gönder.
        Kuralın tetiklendiğini ve severity="high", mitre=["T1110", "T1110.001"] döndürdüğünü doğrula.
        """
        # Find the brute force rule
        brute_force_rule = None
        for rule in detection_engine.rules:
            if "brute" in rule.name.lower() or rule.id == "brute_force_001":
                brute_force_rule = rule
                break
        
        assert brute_force_rule is not None, "Brute force rule should exist"
        assert brute_force_rule.enabled, "Brute force rule should be enabled"
        
        # Simulate 5 failed logon attempts within 1 minute
        base_time = datetime.now()
        message = """An account failed to log on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		ATTACKER
	Account Domain:		WORKGROUP

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Process Information:
	Caller Process ID:	0x0
	Caller Process Name:	-

Network Information:
	Workstation Name:	ATTACKER-PC
	Source Network Address:	192.168.1.100
	Source Port:		0"""
        
        detection_triggered = False
        result = None
        
        # Send 5 failed logon events
        for i in range(5):
            timestamp = base_time + timedelta(seconds=i * 10)  # 10 seconds apart
            result = detection_engine.check_event(
                event_id="4625",
                timestamp=timestamp,
                message=message,
                log_source="Security"
            )
            
            if i < 4:
                # First 4 should not trigger (threshold is 5)
                assert result is None, f"{i+1}. başarısız girişte tetiklenmemeli (threshold 5)"
            else:
                # 5th should trigger
                assert result is not None, "5. başarısız girişte tetiklenmeli"
                detection_triggered = True
        
        assert detection_triggered, "Brute force detection should be triggered"
        
        # Verify result structure
        assert result is not None
        assert result['rule_id'] == "brute_force_001", f"Rule ID should be 'brute_force_001', got '{result['rule_id']}'"
        assert result['severity'] == "high", f"Severity should be 'high', got '{result['severity']}'"
        assert result['risk_level'] == "High", f"Risk level should be 'High', got '{result['risk_level']}'"
        
        # Verify MITRE techniques
        assert 'mitre_techniques' in result, "Result should contain 'mitre_techniques'"
        assert isinstance(result['mitre_techniques'], list), "mitre_techniques should be a list"
        assert "T1110" in result['mitre_techniques'], f"MITRE techniques should include 'T1110', got {result['mitre_techniques']}"
        assert "T1110.001" in result['mitre_techniques'], f"MITRE techniques should include 'T1110.001', got {result['mitre_techniques']}"
        
        # Verify tags
        assert 'tags' in result, "Result should contain 'tags'"
        assert isinstance(result['tags'], list), "tags should be a list"
        assert "brute_force" in result['tags'], f"Tags should include 'brute_force', got {result['tags']}"
        
        print(f"\n✅ Brute Force Test Passed:")
        print(f"   Rule ID: {result['rule_id']}")
        print(f"   Severity: {result['severity']}")
        print(f"   MITRE: {result['mitre_techniques']}")
        print(f"   Tags: {result['tags']}")
    
    def test_scenario_2_powershell_encoded(self, detection_engine):
        """
        Senaryo 2 (PowerShell Encoded): 
        Sysmon Event ID 1 formatında, CommandLine parametresi -EncodedCommand içeren bir log gönder.
        "Suspicious PowerShell" kuralının tetiklendiğini doğrula.
        """
        # Find the PowerShell encoded rule
        powershell_rule = None
        for rule in detection_engine.rules:
            if "powershell" in rule.name.lower() and "encoded" in rule.name.lower():
                powershell_rule = rule
                break
        
        assert powershell_rule is not None, "PowerShell encoded rule should exist"
        assert powershell_rule.enabled, "PowerShell encoded rule should be enabled"
        
        # Simulate Sysmon Event ID 1 with EncodedCommand
        timestamp = datetime.now()
        message = """Process Create:
RuleName: -
UtcTime: 2024-01-15 10:30:00.123
ProcessGuid: {12345678-1234-1234-1234-123456789ABC}
ProcessId: 1234
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
FileVersion: 10.0.19041.1
Description: Windows PowerShell
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe -EncodedCommand JABwAGEAcwBzACAAPQAgACcAUABhAHMAcwB3AG8AcgBkADEAMgAzACcA
CurrentDirectory: C:\\Users\\Test\\
User: DOMAIN\\user
LogonGuid: {ABCDEF12-3456-7890-ABCD-EF1234567890}
LogonId: 0x12345
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA256=ABC123DEF456...
ParentProcessGuid: {98765432-1098-7654-3210-987654321098}
ParentImage: C:\\Windows\\System32\\cmd.exe
ParentCommandLine: cmd.exe"""
        
        sysmon_data = {
            'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'CommandLine': 'powershell.exe -EncodedCommand JABwAGEAcwBzACAAPQAgACcAUABhAHMAcwB3AG8AcgBkADEAMgAzACcA',
            'User': 'DOMAIN\\user',
            'ParentImage': 'C:\\Windows\\System32\\cmd.exe'
        }
        
        # Check event
        result = detection_engine.check_event(
            event_id="1",
            timestamp=timestamp,
            message=message,
            log_source="Sysmon",
            sysmon_data=sysmon_data
        )
        
        assert result is not None, "PowerShell EncodedCommand rule should trigger"
        assert "powershell" in result['rule_name'].lower(), f"Rule name should contain 'powershell', got '{result['rule_name']}'"
        assert result['rule_id'] == "powershell_encoded_001", f"Rule ID should be 'powershell_encoded_001', got '{result['rule_id']}'"
        assert result['severity'] == "high", f"Severity should be 'high', got '{result['severity']}'"
        
        # Verify MITRE techniques
        assert 'mitre_techniques' in result, "Result should contain 'mitre_techniques'"
        assert "T1059.001" in result['mitre_techniques'], f"MITRE techniques should include 'T1059.001', got {result['mitre_techniques']}"
        
        # Verify tags
        assert 'tags' in result, "Result should contain 'tags'"
        assert "powershell" in [tag.lower() for tag in result['tags']], f"Tags should include 'powershell', got {result['tags']}"
        
        print(f"\n✅ PowerShell EncodedCommand Test Passed:")
        print(f"   Rule ID: {result['rule_id']}")
        print(f"   Rule Name: {result['rule_name']}")
        print(f"   Severity: {result['severity']}")
        print(f"   MITRE: {result['mitre_techniques']}")
        print(f"   Tags: {result['tags']}")
    
    def test_scenario_3_parent_child_suspicious(self, detection_engine):
        """
        Senaryo 3 (Parent-Child): 
        Sysmon Event ID 1 formatında, ParentImage="winword.exe" ve Image="cmd.exe" olan bir log gönder.
        "Suspicious Parent-Child" kuralının tetiklendiğini doğrula.
        """
        # Find the parent-child rule
        parent_child_rule = None
        for rule in detection_engine.rules:
            if ("parent" in rule.name.lower() and "child" in rule.name.lower()) or rule.id == "parent_child_001":
                parent_child_rule = rule
                break
        
        assert parent_child_rule is not None, "Parent-child rule should exist"
        assert parent_child_rule.enabled, "Parent-child rule should be enabled"
        
        # Simulate Sysmon Event ID 1 with suspicious parent-child combination
        timestamp = datetime.now()
        message = """Process Create:
RuleName: -
UtcTime: 2024-01-15 10:30:00.123
ProcessGuid: {12345678-1234-1234-1234-123456789ABC}
ProcessId: 5678
Image: C:\\Windows\\System32\\cmd.exe
FileVersion: 10.0.19041.1
Description: Windows Command Processor
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: cmd.exe
CommandLine: cmd.exe /c whoami
CurrentDirectory: C:\\Users\\Test\\
User: DOMAIN\\user
LogonGuid: {ABCDEF12-3456-7890-ABCD-EF1234567890}
LogonId: 0x12345
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA256=DEF456GHI789...
ParentProcessGuid: {98765432-1098-7654-3210-987654321098}
ParentImage: C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE
ParentCommandLine: WINWORD.EXE /n "C:\\Users\\Test\\document.doc" """
        
        sysmon_data = {
            'Image': 'C:\\Windows\\System32\\cmd.exe',
            'CommandLine': 'cmd.exe /c whoami',
            'User': 'DOMAIN\\user',
            'ParentImage': 'C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE'
        }
        
        # Check event
        result = detection_engine.check_event(
            event_id="1",
            timestamp=timestamp,
            message=message,
            log_source="Sysmon",
            sysmon_data=sysmon_data
        )
        
        assert result is not None, "Parent-child suspicious rule should trigger"
        assert result['rule_id'] == "parent_child_001", f"Rule ID should be 'parent_child_001', got '{result['rule_id']}'"
        assert result['severity'] == "high", f"Severity should be 'high', got '{result['severity']}'"
        
        # Verify MITRE techniques
        assert 'mitre_techniques' in result, "Result should contain 'mitre_techniques'"
        assert "T1059.001" in result['mitre_techniques'] or "T1204.002" in result['mitre_techniques'], \
            f"MITRE techniques should include 'T1059.001' or 'T1204.002', got {result['mitre_techniques']}"
        
        # Verify tags
        assert 'tags' in result, "Result should contain 'tags'"
        assert any("process" in tag.lower() or "execution" in tag.lower() for tag in result['tags']), \
            f"Tags should include process/execution related tags, got {result['tags']}"
        
        print(f"\n✅ Parent-Child Suspicious Test Passed:")
        print(f"   Rule ID: {result['rule_id']}")
        print(f"   Rule Name: {result['rule_name']}")
        print(f"   Severity: {result['severity']}")
        print(f"   MITRE: {result['mitre_techniques']}")
        print(f"   Tags: {result['tags']}")
        print(f"   Parent: {sysmon_data['ParentImage']}")
        print(f"   Child: {sysmon_data['Image']}")
    
    def test_non_matching_event_should_not_trigger(self, detection_engine):
        """Test: Normal event that doesn't match any rule should not trigger"""
        timestamp = datetime.now()
        message = "A normal successful logon event"
        
        result = detection_engine.check_event(
            event_id="4624",  # Successful logon
            timestamp=timestamp,
            message=message,
            log_source="Security"
        )
        
        assert result is None, "Normal successful logon should not trigger any rule"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

