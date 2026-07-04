# Architecture

LocalShield is an offline SIEM. Everything runs locally — a local LLM (Ollama),
local YAML rules, a local CSV threat feed, a local SQLite database, and a
localhost dashboard. **No feature requires an internet connection.**

## Data flow

```
Windows Event Log (Security + Sysmon)          Linux auth.log (cross-platform)
                │                                          │
                ▼                                          ▼
        log_watcher.py  ◄──────────────────────  modules/log_importer.py
        (async watcher)                           (SSH → Event ID mapping)
                │
                ├─► modules/detection_engine.py   (YAML rules, thresholds,
                │        │                          per-source & correlation)
                │        └─ modules/rule_schema.py (load-time validation)
                │
                ├─► modules/threat_intel.py        (malicious IPs / CIDR ranges)
                │
                ├─► modules/ai_engine.py           (Ollama, JSON output, cache,
                │        └─ modules/knowledge_base.py  RAG + timeout)
                │
                ├─► modules/response_engine.py     (SOAR: firewall block,
                │                                    allowlist, safe targets)
                ├─► modules/notifier.py            (alert-log / toast / webhook)
                │
                ▼
           db_manager.py  ──►  SQLite (logs, actions, blocked_ips, incidents)
                │
                ▼
           dashboard.py (Streamlit, localhost)  ──►  Logs · Incidents ·
                                                      Active Response · Network ·
                                                      AI Assistant
```

## Components

| Module | Responsibility |
|--------|----------------|
| `log_watcher.py` | Async loop reading Windows event logs; orchestrates detection → AI → response → persistence → notify/incident. Entry point: `localshield-watch`. |
| `modules/detection_engine.py` | YAML rule engine: selection, thresholds, per-source grouping, cross-event correlation, MITRE mapping. |
| `modules/rule_schema.py` | Pydantic schema; validates rules at load, skips malformed ones. |
| `modules/ai_engine.py` | Local-LLM analysis with strict JSON output, a repeat-event cache, and a hard request timeout. |
| `modules/knowledge_base.py` | Hybrid RAG: local + external Event-ID knowledge feeding the AI prompt. |
| `modules/threat_intel.py` | CSV IP reputation (single IPs + CIDR ranges). |
| `modules/response_engine.py` | Windows Firewall SOAR with an allowlist and structured-source-only targeting. |
| `modules/notifier.py` | Offline-first alerting (alert-log always on; desktop toast / webhook opt-in). |
| `modules/network_scanner.py`, `modules/packet_capture.py` | Open-port scan and live packet capture (Scapy). |
| `db_manager.py` | SQLite schema, indexes, and helpers for logs, audit actions, blocked IPs, and incidents. |
| `dashboard.py` | Streamlit SOC console (localhost-bound, no auth by design). |

## Design principles

- **Offline-first:** no runtime feature depends on outbound network.
- **Local & single-user:** the dashboard binds to `localhost`; expose it only
  behind an authenticating reverse proxy.
- **Safe automation:** auto-block targets come only from structured
  source-address fields, private IPs and an allowlist are never blocked, and
  every action is audited.
- **Cross-platform core:** detection/correlation/notify/incidents are exercised
  on Linux via the `auth.log` importer and the test-suite, even though live
  Windows capture is Windows-only.
