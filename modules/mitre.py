"""
MITRE ATT&CK lookup - offline technique -> (name, tactic) mapping.

Covers the techniques referenced by LocalShield's detection rules plus a few
common neighbours. Unknown IDs degrade gracefully (sub-techniques fall back to
their parent, otherwise the ID is returned with an "Unknown" tactic), so the
dashboard never breaks on an unseen technique.
"""

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

# technique id -> (human name, ATT&CK tactic)
TECHNIQUES: Dict[str, tuple] = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1204": ("User Execution", "Execution"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1197": ("BITS Jobs", "Defense Evasion"),
    "T1543": ("Create or Modify System Process", "Persistence"),
    "T1543.003": ("Windows Service", "Persistence"),
    "T1136": ("Create Account", "Persistence"),
    "T1136.001": ("Local Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1078.003": ("Local Accounts", "Defense Evasion"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1053": ("Scheduled Task/Job", "Execution"),
    "T1053.005": ("Scheduled Task", "Execution"),
}

# Stable order for display (roughly the ATT&CK kill-chain progression)
TACTIC_ORDER: List[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Unknown",
]


def technique_info(technique_id: Optional[str]) -> Dict[str, str]:
    """
    Return {'id', 'name', 'tactic'} for a technique id.
    Sub-techniques fall back to their parent; unknowns get tactic 'Unknown'.
    """
    if not technique_id:
        return {"id": "", "name": "Unknown", "tactic": "Unknown"}

    tid = str(technique_id).strip().upper()
    if tid in TECHNIQUES:
        name, tactic = TECHNIQUES[tid]
        return {"id": tid, "name": name, "tactic": tactic}

    # Sub-technique fallback (e.g. T1110.999 -> T1110)
    if "." in tid:
        parent = tid.split(".")[0]
        if parent in TECHNIQUES:
            name, tactic = TECHNIQUES[parent]
            return {"id": tid, "name": name, "tactic": tactic}

    return {"id": tid, "name": tid, "tactic": "Unknown"}


def summarize(techniques: Iterable[Optional[str]]) -> List[Dict[str, Any]]:
    """
    Aggregate an iterable of technique ids into a per-technique summary list:
    [{'id', 'name', 'tactic', 'count'}], sorted by count desc.
    Blank/None entries are ignored.
    """
    counts: Counter = Counter()
    for t in techniques:
        if t is None:
            continue
        tid = str(t).strip()
        if not tid or tid.lower() in ("none", "nan", "n/a"):
            continue
        counts[tid.upper()] += 1

    rows: List[Dict[str, Any]] = []
    for tid, count in counts.items():
        info = technique_info(tid)
        rows.append(
            {
                "id": info["id"],
                "name": info["name"],
                "tactic": info["tactic"],
                "count": count,
            }
        )

    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows
