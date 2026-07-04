"""
Demo Data Generator for LocalShield Dashboard
Creates realistic security events for LinkedIn screenshots
"""
import random
from datetime import datetime, timedelta
from typing import List

import config
from db_manager import clear_all_logs, init_db, insert_log

# Demo event templates
CRITICAL_EVENTS = [
    {
        "event_id": "1",
        "message": """Process Create:
RuleName: -
UtcTime: {timestamp}
ProcessGuid: {{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}}
ProcessId: 4567
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -EncodedCommand JABwAGEAcwBzACAAPQAgACcAUABhAHMAcwB3AG8AcgBkADEAMgAzACcA
User: CORP\\Admin
ParentImage: C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE
ParentCommandLine: WINWORD.EXE /n "C:\\Users\\Admin\\Documents\\invoice.doc" """,
        "ai_analysis": """🆔 Event ID Explained
Event ID 1 (Sysmon Process Creation) indicates a new process was launched on the system.

🕵️‍♂️ Analysis
User/Entity: CORP\\Admin
Summary: CRITICAL: Suspicious PowerShell execution detected with EncodedCommand parameter. Office application (WINWORD.EXE) spawned PowerShell, which is a common APT29 (Cozy Bear) attack pattern. The encoded command suggests obfuscated malicious payload execution.
Risk Level: High

💡 Recommendation
• Immediately isolate the affected machine from the network
• Terminate the suspicious PowerShell process (PID: 4567)
• Investigate the parent document (invoice.doc) for malicious macros
• Review network connections from this host for C2 communication
• Check for lateral movement indicators
• Consider this a potential APT29 intrusion and escalate to incident response team""",
        "risk_score": "High",
        "mitre_technique": "T1059.001, T1204.002, T1027"
    }
]

HIGH_RISK_EVENTS = [
    {
        "event_id": "4625",
        "message": """An account failed to log on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		Administrator
	Account Domain:		CORP

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Network Information:
	Workstation Name:	UNKNOWN
	Source Network Address:	185.220.101.45
	Source Port:		0""",
        "ai_analysis": """🆔 Event ID Explained
Event ID 4625 indicates a failed logon attempt to a Windows system.

🕵️‍♂️ Analysis
User/Entity: Administrator@CORP
Summary: Multiple failed logon attempts detected from Russian Federation IP address (185.220.101.45). This IP is associated with known threat actor infrastructure. Brute force attack pattern suggests automated credential stuffing attempt targeting privileged accounts.
Risk Level: High

💡 Recommendation
• Block IP address 185.220.101.45 at firewall level immediately
• Enable account lockout policy for Administrator account
• Review all authentication attempts from this source
• Consider implementing geo-blocking for high-risk regions
• Enable MFA for all privileged accounts
• Monitor for successful authentication from this IP range""",
        "risk_score": "High",
        "mitre_technique": "T1110, T1110.001"
    },
    {
        "event_id": "4625",
        "message": """An account failed to log on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		HR_User
	Account Domain:		CORP

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Network Information:
	Workstation Name:	UNKNOWN
	Source Network Address:	45.146.164.110
	Source Port:		0""",
        "ai_analysis": """🆔 Event ID Explained
Event ID 4625 indicates a failed logon attempt to a Windows system.

🕵️‍♂️ Analysis
User/Entity: HR_User@CORP
Summary: Failed RDP logon attempt from Chinese IP address (45.146.164.110). This IP belongs to a known APT group infrastructure. The targeting of HR_User account suggests reconnaissance phase of a targeted attack campaign.
Risk Level: High

💡 Recommendation
• Immediately block IP 45.146.164.110 at network perimeter
• Review HR_User account for any successful logons
• Check for data exfiltration indicators
• Implement IP reputation-based blocking
• Enable detailed logging for HR department accounts
• Consider this part of a larger APT campaign and escalate""",
        "risk_score": "High",
        "mitre_technique": "T1110, T1078"
    }
]

MEDIUM_RISK_EVENTS = [
    {
        "event_id": "4672",
        "message": """Special privileges assigned to new logon.

Subject:
	Security ID:		S-1-5-21-1234567890-123456789-123456789-500
	Account Name:		Admin
	Account Domain:		CORP
	Logon ID:		0x123456

Privileges:		SeDebugPrivilege
			SeTcbPrivilege
			SeBackupPrivilege
			SeRestorePrivilege""",
        "ai_analysis": """🆔 Event ID Explained
Event ID 4672 indicates that special privileges were assigned to a user account during logon.

🕵️‍♂️ Analysis
User/Entity: Admin@CORP
Summary: Privilege escalation detected. User 'Admin' was assigned sensitive privileges including SeDebugPrivilege and SeTcbPrivilege. While this may be legitimate for administrative tasks, the timing and context should be verified. SeDebugPrivilege allows process manipulation and is often abused by attackers.
Risk Level: Medium

💡 Recommendation
• Verify if this privilege assignment was authorized
• Review Admin account activity for suspicious behavior
• Check for any unauthorized process manipulation
• Ensure privilege assignment follows least privilege principle
• Monitor for abuse of elevated privileges""",
        "risk_score": "Medium",
        "mitre_technique": "T1078, T1548"
    },
    {
        "event_id": "4672",
        "message": """Special privileges assigned to new logon.

Subject:
	Security ID:		S-1-5-21-1234567890-123456789-123456789-1001
	Account Name:		HR_User
	Account Domain:		CORP
	Logon ID:		0x789ABC

Privileges:		SeChangeNotifyPrivilege
			SeImpersonatePrivilege""",
        "ai_analysis": """🆔 Event ID Explained
Event ID 4672 indicates that special privileges were assigned to a user account during logon.

🕵️‍♂️ Analysis
User/Entity: HR_User@CORP
Summary: Standard user account assigned impersonation privileges. SeImpersonatePrivilege can be abused for privilege escalation attacks (e.g., PrintSpoofer, RoguePotato). While this is common for service accounts, it should be monitored for abuse.
Risk Level: Medium

💡 Recommendation
• Verify HR_User account requires these privileges
• Monitor for privilege escalation attempts
• Review account for any unauthorized access
• Consider restricting SeImpersonatePrivilege if not required
• Implement additional monitoring for this account""",
        "risk_score": "Medium",
        "mitre_technique": "T1078, T1134"
    }
]

LOW_RISK_EVENTS = [
    {
        "event_id": "4624",
        "message": """An account was successfully logged on.

Subject:
	Security ID:		S-1-5-18
	Account Name:		SYSTEM
	Account Domain:		NT AUTHORITY
	Logon ID:		0x3E7

Logon Type:			5

New Logon:
	Security ID:		S-1-5-18
	Account Name:		SYSTEM
	Account Domain:		NT AUTHORITY
	Logon ID:		0x3E7
	Logon GUID:		{{00000000-0000-0000-0000-000000000000}}

Process Information:
	Process ID:		0x4
	Process Name:		C:\\Windows\\System32\\smss.exe

Network Information:
	Workstation Name:	CORP-DC-01
	Source Network Address:	-
	Source Port:		-""",
        "ai_analysis": """🆔 Event ID Explained
Event ID 4624 indicates a successful logon to a Windows system.

🕵️‍♂️ Analysis
User/Entity: SYSTEM@NT AUTHORITY
Summary: Normal system service logon. The SYSTEM account logged on via service (Logon Type 5) on domain controller CORP-DC-01. This is expected behavior for Windows system services and does not indicate a security concern.
Risk Level: Low

💡 Recommendation
• No action required - this is normal system activity
• Continue monitoring for any anomalies in system account behavior""",
        "risk_score": "Low",
        "mitre_technique": None
    },
    {
        "event_id": "4624",
        "message": """An account was successfully logged on.

Subject:
	Security ID:		S-1-5-21-1234567890-123456789-123456789-1105
	Account Name:		Admin
	Account Domain:		CORP
	Logon ID:		0x456789

Logon Type:			2

New Logon:
	Security ID:		S-1-5-21-1234567890-123456789-123456789-1105
	Account Name:		Admin
	Account Domain:		CORP
	Logon ID:		0x456789

Network Information:
	Workstation Name:	FINANCE-SRV
	Source Network Address:	192.168.1.100
	Source Port:		-""",
        "ai_analysis": """🆔 Event ID Explained
Event ID 4624 indicates a successful logon to a Windows system.

🕵️‍♂️ Analysis
User/Entity: Admin@CORP
Summary: Successful interactive logon (Logon Type 2) from internal network IP 192.168.1.100 to server FINANCE-SRV. This appears to be a legitimate administrative session from the corporate network.
Risk Level: Low

💡 Recommendation
• Verify this is an authorized administrative session
• Ensure MFA is enabled for administrative accounts
• Monitor for any unusual activity during this session""",
        "risk_score": "Low",
        "mitre_technique": None
    }
]


def generate_timestamps(count: int, hours_back: int = 24) -> List[datetime]:
    """Generate random timestamps within the last N hours"""
    now = datetime.now()
    timestamps = []
    for _ in range(count):
        hours_ago = random.uniform(0, hours_back)
        timestamp = now - timedelta(hours=hours_ago)
        timestamps.append(timestamp)
    return sorted(timestamps, reverse=True)  # Most recent first


def format_message_template(template: str, timestamp: datetime) -> str:
    """Format message template with timestamp"""
    return template.format(timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])


def generate_demo_data():
    """Generate and insert demo data into database"""
    print("=" * 60)
    print("🛡️  LocalShield - Demo Data Generator")
    print("=" * 60)
    print()

    # Confirm database clearing
    print("⚠️  WARNING: This will DELETE all existing log entries!")
    response = input("Do you want to continue? (yes/no): ").strip().lower()

    if response != 'yes':
        print("❌ Operation cancelled.")
        return

    # Clear database
    print("\n🗑️  Clearing existing database...")
    try:
        clear_all_logs(config.DB_PATH)
        print("✅ Database cleared successfully.")
    except Exception as e:
        print(f"❌ Error clearing database: {e}")
        return

    # Initialize database
    print("\n📊 Initializing database...")
    conn = init_db(config.DB_PATH)

    # Generate timestamps
    # Calculate total events needed
    total_events = len(CRITICAL_EVENTS) + len(HIGH_RISK_EVENTS) + len(MEDIUM_RISK_EVENTS) + 30
    print("\n⏰ Generating timestamps...")
    timestamps = generate_timestamps(total_events, hours_back=24)  # All events in last 24 hours

    inserted_count = 0

    # Insert Critical events (1)
    print("\n🔴 Inserting CRITICAL events...")
    for i, event in enumerate(CRITICAL_EVENTS):
        timestamp = timestamps[i]
        message = format_message_template(event["message"], timestamp)
        insert_log(
            timestamp=timestamp,
            event_id=event["event_id"],
            message=message,
            ai_analysis=event["ai_analysis"],
            risk_score=event["risk_score"],
            mitre_technique=event["mitre_technique"],
            conn=conn
        )
        inserted_count += 1
        print(f"  ✓ Critical event {i+1} inserted")

    # Insert High risk events (2)
    print("\n🟠 Inserting HIGH risk events...")
    for i, event in enumerate(HIGH_RISK_EVENTS):
        timestamp = timestamps[inserted_count + i]
        message = format_message_template(event["message"], timestamp)
        insert_log(
            timestamp=timestamp,
            event_id=event["event_id"],
            message=message,
            ai_analysis=event["ai_analysis"],
            risk_score=event["risk_score"],
            mitre_technique=event["mitre_technique"],
            conn=conn
        )
        inserted_count += 1
        print(f"  ✓ High risk event {i+1} inserted")

    # Insert Medium risk events (2)
    print("\n🟡 Inserting MEDIUM risk events...")
    for i, event in enumerate(MEDIUM_RISK_EVENTS):
        timestamp = timestamps[inserted_count + i]
        message = format_message_template(event["message"], timestamp)
        insert_log(
            timestamp=timestamp,
            event_id=event["event_id"],
            message=message,
            ai_analysis=event["ai_analysis"],
            risk_score=event["risk_score"],
            mitre_technique=event["mitre_technique"],
            conn=conn
        )
        inserted_count += 1
        print(f"  ✓ Medium risk event {i+1} inserted")

    # Insert Low risk events (30 - fill the rest)
    print("\n🟢 Inserting LOW risk events...")
    remaining_timestamps = len(timestamps) - inserted_count
    low_event_count = min(30, remaining_timestamps)  # Max 30 low risk events
    for i in range(low_event_count):
        event = random.choice(LOW_RISK_EVENTS)
        if inserted_count + i < len(timestamps):
            timestamp = timestamps[inserted_count + i]
        else:
            # Fallback: generate new timestamp if we run out
            timestamp = datetime.now() - timedelta(hours=random.uniform(0, 24))
        message = format_message_template(event["message"], timestamp)

        # Vary the message slightly for diversity
        if i % 3 == 0:
            message = message.replace("CORP-DC-01", random.choice(["CORP-DC-01", "FINANCE-SRV", "IT-SRV-02"]))
        if i % 5 == 0:
            message = message.replace("Admin", random.choice(["Admin", "SYSTEM", "ServiceAccount"]))

        insert_log(
            timestamp=timestamp,
            event_id=event["event_id"],
            message=message,
            ai_analysis=event["ai_analysis"],
            risk_score=event["risk_score"],
            mitre_technique=event["mitre_technique"],
            conn=conn
        )
        inserted_count += 1
        if (i + 1) % 10 == 0:
            print(f"  ✓ {i+1} low risk events inserted...")

    conn.close()

    print("\n" + "=" * 60)
    print("✅ Demo data generation complete!")
    print(f"📊 Total events inserted: {inserted_count}")
    print(f"   - Critical: {len(CRITICAL_EVENTS)}")
    print(f"   - High: {len(HIGH_RISK_EVENTS)}")
    print(f"   - Medium: {len(MEDIUM_RISK_EVENTS)}")
    print(f"   - Low: {low_event_count}")
    print("=" * 60)
    print("\n💡 You can now open the dashboard to see the demo data!")
    print("   Run: streamlit run dashboard.py")


if __name__ == "__main__":
    try:
        generate_demo_data()
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user.")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

