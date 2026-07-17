"""
Attack Simulation - Demo Tool
Runs fake brute force events (Event ID 4625) through the real detection
engine and stores the results, so the Dashboard shows exactly what a live
attack would produce: Medium single failures, then a High / MITRE T1110
detection once the brute_force_001 threshold (5 attempts within its time
window, same source IP) is reached.
"""

import io
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# UTF-8 setup for the Windows terminal encoding issue
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

import config
from db_manager import init_db, insert_log
from modules.detection_engine import DetectionEngine


def simulate_brute_force_attack(
    num_attempts: int = 5,
    time_window_seconds: int = 60,
    attacker_name: str = "ATTACKER",
    db_path: Optional[str] = None,
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

    # Same rule engine the live watcher uses — the demo shows real detections
    engine = DetectionEngine(rules_dir=str(Path(__file__).parent / "rules"))
    detections = 0

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

        # Run the event through the real detection engine (same as the
        # live watcher) so risk/MITRE reflect what an actual attack yields
        result = engine.check_event("4625", timestamp, message, "Security")

        if result:
            detections += 1
            ai_analysis = result.get("match_message") or f"Failed logon attempt detected. User: {attacker_name}"
            risk_score = result.get("risk_level", "High")
            mitre_technique = result.get("mitre_technique")
        else:
            ai_analysis = f"Failed logon attempt detected. User: {attacker_name}"
            risk_score = "Medium"  # Single failure below the rule threshold
            mitre_technique = None

        try:
            log_id = insert_log(
                timestamp=timestamp,
                event_id="4625",
                message=message[:500],  # First 500 characters
                ai_analysis=ai_analysis,
                risk_score=risk_score,
                mitre_technique=mitre_technique,
                conn=conn,
            )

            status = f"🚨 DETECTED ({result['rule_id']}, {mitre_technique}, {risk_score})" if result else "no detection"
            print(f"  ✅ Log #{i + 1} added (ID: {log_id}, Time: {timestamp.strftime('%H:%M:%S')}) — {status}")

        except Exception as e:
            print(f"  ❌ Error adding log #{i + 1}: {e}")

    # Close connection
    conn.close()

    print()
    print("=" * 60)
    print("✅ Simulation completed!")
    print()
    if detections:
        print(f"🚨 {detections} detection(s) fired — open the Dashboard and check:")
        print("   - Event ID 4625 logs are visible")
        print("   - The MITRE T1110 tag appears on the detected attempt")
        print("   - Its risk level is marked 'High'")
    else:
        print("ℹ️  No detection fired: the brute_force_001 rule needs 5+ attempts")
        print("   within its 60-second window from the same source IP.")
        print("   Try again with e.g.: python simulate_attack.py -n 5 -t 30")
    print("=" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="LocalShield - Brute Force Attack Simulation")
    parser.add_argument(
        "-n", "--num-attempts", type=int, default=5, help="Number of failed login attempts to simulate (default: 5)"
    )
    parser.add_argument("-t", "--time-window", type=int, default=60, help="Time window in seconds (default: 60)")
    parser.add_argument("-u", "--user", type=str, default="ATTACKER", help="Attacker username (default: ATTACKER)")
    parser.add_argument("-d", "--db-path", type=str, default=None, help="Database path (default: config.DB_PATH)")

    args = parser.parse_args()

    simulate_brute_force_attack(
        num_attempts=args.num_attempts,
        time_window_seconds=args.time_window,
        attacker_name=args.user,
        db_path=args.db_path,
    )
