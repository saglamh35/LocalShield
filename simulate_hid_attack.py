"""
HID-injection attack simulation (purple-team demo).

Replays the Sysmon telemetry that the O.MG/DuckyScript payload
`payloads/duckyscript/vm/win_recon_hidden.txt` produces on a Windows VM, runs it
through LocalShield's detection engine, and stores the result — so you can see the
attack -> detect -> (dashboard) loop WITHOUT a real Windows VM.

Lab/education only. The replayed command is benign (`whoami`); the detectable
signal is the hidden-window PowerShell spawned by explorer.exe (MITRE T1200 /
T1059.001), caught by rules/hid_injection.yaml.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import config
from db_manager import init_db, insert_log
from modules.detection_engine import DetectionEngine

DEFAULT_TELEMETRY = (
    Path(__file__).parent / "payloads" / "duckyscript" / "vm" / "telemetry" / "win_recon_hidden.sysmon.json"
)


def simulate_hid_attack(telemetry_path: Path = DEFAULT_TELEMETRY, db_path: str | None = None) -> dict:
    """
    Replay one HID-injection telemetry sample through the detection engine and
    persist any detection. Returns the matched rule result (or {} if none).
    """
    db_path = db_path or config.DB_PATH
    data = json.loads(Path(telemetry_path).read_text(encoding="utf-8"))

    event_id = str(data.get("event_id", "1"))
    provider = str(data.get("provider", "Sysmon"))
    message = str(data.get("message", ""))
    sysmon = data.get("sysmon", {})

    print("=" * 60)
    print("🛡️  LocalShield - HID Injection (BadUSB) Simulation")
    print("=" * 60)
    print(f"📄 Telemetry : {telemetry_path}")
    print(f"🖥️  Parent    : {sysmon.get('ParentImage')}")
    print(f"⚙️  Image     : {sysmon.get('Image')}")
    print(f"⌨️  CommandLine: {sysmon.get('CommandLine')}")
    print("=" * 60)

    init_db(db_path)
    engine = DetectionEngine(rules_dir=str(Path(__file__).parent / "rules"))
    result = engine.check_event(event_id, datetime.now(), message, provider, sysmon) or {}

    if result:
        insert_log(
            timestamp=datetime.now(),
            event_id=event_id,
            message=message[:500],
            ai_analysis=result.get("match_message", ""),
            risk_score=result.get("risk_level", "High"),
            mitre_technique=result.get("mitre_technique"),
            db_path=db_path,
        )
        print(
            f"🔴 DETECTED by rule '{result.get('rule_id')}' — "
            f"{result.get('risk_level')} / MITRE {', '.join(result.get('mitre_techniques', []))}"
        )
        print("   Stored to the DB — open the dashboard's Log Analysis tab to see it.")
    else:
        print("🟢 No rule matched (unexpected for this sample).")

    print("=" * 60)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LocalShield - HID injection attack simulation")
    parser.add_argument("-f", "--telemetry", type=Path, default=DEFAULT_TELEMETRY, help="Telemetry JSON to replay")
    parser.add_argument("-d", "--db-path", type=str, default=None, help="Database path (default: config.DB_PATH)")
    args = parser.parse_args()
    simulate_hid_attack(telemetry_path=args.telemetry, db_path=args.db_path)
