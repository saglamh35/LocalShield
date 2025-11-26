"""
Attack Simulation - Demo Tool
Injects fake brute force logs into database (Event ID 4625)
Purpose: Test MITRE T1110 tag appearance in Dashboard without waiting for Log Watcher
"""
import sys
import io
from datetime import datetime, timedelta
from pathlib import Path

# Windows terminal encoding sorunu için UTF-8 ayarı
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from db_manager import init_db, insert_log
import config


def simulate_brute_force_attack(
    num_attempts: int = 5,
    time_window_seconds: int = 60,
    attacker_name: str = "ATTACKER",
    db_path: str = None
):
    """
    Simulates a fake brute force attack.
    
    Args:
        num_attempts: Number of failed login attempts to simulate (default: 5)
        time_window_seconds: Time window in seconds for these attempts (default: 60)
        attacker_name: Attacker username (default: "ATTACKER")
        db_path: Database path (default: config.DB_PATH)
    """
    db_path = db_path or config.DB_PATH
    
    print("=" * 60)
    print("🛡️  LocalShield - Attack Simulation")
    print("=" * 60)
    print(f"📊 Number of attempts to simulate: {num_attempts}")
    print(f"⏰ Time window: {time_window_seconds} seconds")
    print(f"👤 Attacker: {attacker_name}")
    print(f"💾 Database: {db_path}")
    print("=" * 60)
    print()
    
    # Initialize database
    try:
        conn = init_db(db_path)
        print("✅ Database connection successful")
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return
    
    # Calculate time interval
    base_time = datetime.now()
    time_interval = time_window_seconds / num_attempts if num_attempts > 1 else 0
    
    print(f"🚀 Adding {num_attempts} fake log entries...")
    print()
    
    # Create log entry for each attempt
    for i in range(num_attempts):
        # Calculate time (distribute evenly)
        timestamp = base_time + timedelta(seconds=i * time_interval)
        
        # Create event message (realistic Windows Event 4625 format)
        message = f"""An account failed to log on.

Subject:
    Security ID:        S-1-5-18
    Account Name:       {attacker_name}
    Account Domain:      WORKGROUP
    Logon ID:           0x00000000

Logon Type:            3

Account For Which Logon Failed:
    Security ID:        NULL SID
    Account Name:       {attacker_name}
    Account Domain:     WORKGROUP

Failure Information:
    Failure Reason:     Unknown user name or bad password.
    Status:             0xC000006D
    Sub Status:         0xC000006A

Process Information:
    Caller Process ID:  0x00000000
    Caller Process Name: -

Network Information:
    Workstation Name:   {attacker_name}-PC
    Source Network Address: 192.168.1.100
    Source Port:       445

Detailed Authentication Information:
    Logon Process:      NtLmSsp
    Authentication Package: NTLM
    Transited Services: -
    Package Name (NTLM only): -
    Key Length:         0

This event is generated when a logon request fails. It is generated on the computer where access was attempted.

The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).

The Process Information fields indicate which account and process attempted the logon.

The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The authentication information fields provide detailed information about this specific logon request.
- Transited services indicate which intermediate services have participated in this logon request.
- Package name indicates which sub-protocol was used among the NTLM protocols.
- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."""
        
        # AI analysis (will be overridden if detection engine triggers)
        ai_analysis = f"Failed logon attempt detected. User: {attacker_name}"
        
        # Risk level (will be "High" if detection engine triggers)
        risk_score = "Medium"  # Medium for individual attempts, High for 5+ attempts
        
        # MITRE technique (will be "T1110" if detection engine triggers)
        mitre_technique = None  # None until detection engine triggers
        
        try:
            log_id = insert_log(
                timestamp=timestamp,
                event_id="4625",
                message=message[:500],  # First 500 characters
                ai_analysis=ai_analysis,
                risk_score=risk_score,
                mitre_technique=mitre_technique,
                conn=conn
            )
            
            print(f"  ✅ Log #{i+1} added (ID: {log_id}, Time: {timestamp.strftime('%H:%M:%S')})")
            
        except Exception as e:
            print(f"  ❌ Error adding log #{i+1}: {e}")
    
    # Close connection
    conn.close()
    
    print()
    print("=" * 60)
    print("✅ Simulation completed!")
    print()
    print("💡 Now open the Dashboard and check:")
    print("   - Are Event ID 4625 logs visible?")
    print("   - If 5+ attempts, is MITRE T1110 tag visible?")
    print("   - Is risk level marked as 'High'?")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="LocalShield - Brute Force Attack Simulation"
    )
    parser.add_argument(
        "-n", "--num-attempts",
        type=int,
        default=5,
        help="Number of failed login attempts to simulate (default: 5)"
    )
    parser.add_argument(
        "-t", "--time-window",
        type=int,
        default=60,
        help="Time window in seconds (default: 60)"
    )
    parser.add_argument(
        "-u", "--user",
        type=str,
        default="ATTACKER",
        help="Attacker username (default: ATTACKER)"
    )
    parser.add_argument(
        "-d", "--db-path",
        type=str,
        default=None,
        help="Database path (default: config.DB_PATH)"
    )
    
    args = parser.parse_args()
    
    simulate_brute_force_attack(
        num_attempts=args.num_attempts,
        time_window_seconds=args.time_window,
        attacker_name=args.user,
        db_path=args.db_path
    )

