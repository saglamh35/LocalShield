"""
Cross-platform log importer.

Parses Linux SSH authentication logs (auth.log / secure) and feeds them through
the same DetectionEngine used for Windows events, mapping SSH auth outcomes onto
Windows-style Event IDs so existing rules (e.g. brute force on 4625) apply:

    Failed password    -> Event ID 4625 (failed logon)
    Accepted password  -> Event ID 4624 (successful logon)

This lets LocalShield run and be tested on non-Windows hosts.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from modules import iputils

logger = logging.getLogger(__name__)

# SSH auth.log line shapes we care about. The address group is deliberately
# loose (IPv4 or IPv6 shaped); every candidate is validated with iputils
# before the line is accepted.
_IP = r"[0-9A-Fa-f:.]+"
_SYSLOG_PREFIX = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s")
_FAILED = re.compile(rf"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>{_IP})")
_ACCEPTED = re.compile(rf"Accepted password for (?P<user>\S+) from (?P<ip>{_IP})")
_AUTH_FAILURE = re.compile(rf"authentication failure;.*rhost=(?P<ip>{_IP})(?:.*user=(?P<user>\S+))?")


def parse_auth_line(line: str, default_year: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """
    Parse a single SSH auth log line.

    Args:
        line: Raw log line
        default_year: Year to attach to the (year-less) syslog timestamp
                      (defaults to the current year)

    Returns:
        dict with keys {timestamp, event_id, user, source_ip, outcome, message}
        or None if the line is not a recognized SSH auth event.
    """
    if not line:
        return None

    failed = _FAILED.search(line)
    accepted = _ACCEPTED.search(line)
    auth_fail = _AUTH_FAILURE.search(line)

    if failed:
        user, raw_ip, event_id, outcome = failed.group("user"), failed.group("ip"), "4625", "failure"
    elif auth_fail:
        user = auth_fail.group("user") or "unknown"
        raw_ip, event_id, outcome = auth_fail.group("ip"), "4625", "failure"
    elif accepted:
        user, raw_ip, event_id, outcome = accepted.group("user"), accepted.group("ip"), "4624", "success"
    else:
        return None

    # The loose pattern can capture non-address tokens; require a real IP
    ip = iputils.normalize_ip(raw_ip)
    if ip is None:
        return None

    # Parse the syslog timestamp (year-less); fall back to now() on failure
    timestamp = datetime.now()
    prefix = _SYSLOG_PREFIX.match(line)
    if prefix:
        year = default_year or datetime.now().year
        stamp = f"{prefix.group('mon')} {prefix.group('day')} {prefix.group('time')} {year}"
        try:
            timestamp = datetime.strptime(stamp, "%b %d %H:%M:%S %Y")
        except ValueError:
            pass

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "user": user,
        "source_ip": ip,
        "outcome": outcome,
        "message": line.strip(),
    }


def import_auth_log(
    path: str,
    engine: Optional[Any] = None,
    db_path: Optional[str] = None,
    insert: bool = True,
    default_year: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Import an SSH auth log file: parse events, run them through the detection
    engine, and optionally persist them to the database.

    Args:
        path: Path to the auth.log / secure file
        engine: A DetectionEngine (created from ./rules if not supplied)
        db_path: Database path for insertion (default: config.DB_PATH)
        insert: If True, write parsed events to the database
        default_year: Year for the year-less syslog timestamps

    Returns:
        Summary dict: {parsed, inserted, detections, events}
    """
    from modules.detection_engine import DetectionEngine

    if engine is None:
        engine = DetectionEngine()

    summary: Dict[str, Any] = {"parsed": 0, "inserted": 0, "detections": 0, "events": []}

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Could not read log file {path}: {e}")
        return summary

    for line in lines:
        event = parse_auth_line(line, default_year=default_year)
        if not event:
            continue

        summary["parsed"] += 1

        detection = engine.check_event(event["event_id"], event["timestamp"], event["message"], "Security")
        risk = detection["risk_level"] if detection else ("Medium" if event["outcome"] == "failure" else "Low")
        mitre = detection["mitre_technique"] if detection else None
        if detection:
            summary["detections"] += 1

        event["risk"] = risk
        event["mitre"] = mitre
        summary["events"].append(event)

        if insert:
            from db_manager import insert_log

            insert_log(
                timestamp=event["timestamp"],
                event_id=event["event_id"],
                message=event["message"],
                ai_analysis=(detection["match_message"] if detection else None),
                risk_score=risk,
                mitre_technique=mitre,
                db_path=db_path,
            )
            summary["inserted"] += 1

    logger.info(f"Imported {summary['parsed']} SSH auth events from {path} ({summary['detections']} rule detections)")
    return summary


if __name__ == "__main__":
    import logging as _logging
    import sys

    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    target = sys.argv[1] if len(sys.argv) > 1 else "/var/log/auth.log"
    result = import_auth_log(target)
    print(f"Parsed: {result['parsed']}  Inserted: {result['inserted']}  Detections: {result['detections']}")
