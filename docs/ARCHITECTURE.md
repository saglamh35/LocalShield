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
| `modules/threat_intel.py` | CSV IP reputation (single IPs + CIDR ranges, IPv4 and IPv6). |
| `modules/iputils.py` | Shared family-neutral IP helpers (validation, canonicalisation, structured source-field extraction) used by both engines. |
| `modules/response_engine.py` | Windows Firewall SOAR with an allowlist, structured-source-only targeting, optional timed blocks and a dry-run mode. |
| `modules/notifier.py` | Offline-first alerting (alert-log always on; desktop toast / webhook opt-in). |
| `modules/network_scanner.py`, `modules/packet_capture.py` | Open-port scan and live packet capture (Scapy). |
| `db_manager.py` | SQLite schema, indexes, and helpers for logs, audit actions, blocked IPs, and incidents. |
| `dashboard.py` | Thin Streamlit entry point; the SOC console UI lives in the `ui/` package (theme, data loaders, components, charts, one view per tab). Localhost-bound, no auth by design. |

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

## SQLite concurrency & scaling limits

The store is a single SQLite file (`config.DB_PATH`) opened with WAL mode,
`timeout=10.0` and short-lived connections. That is the right choice for the
single-host, learning-scale use case — but it has a ceiling worth knowing.

**Who writes today.** The log watcher is the main writer (security_logs,
actions, blocked_ips, incidents, component_status, correlation_state). The
dashboard writes only on rare, human-triggered clicks (clear DB, close
incident, unblock IP), and the vuln scanner / Ansible remediation write when
manually run. The Prometheus metrics exporter is read-only.

**Failure mode under load.** WAL allows many readers but only one writer at a
time: concurrent writers serialize on the write lock, and a writer that cannot
acquire it within the 10s busy timeout surfaces as `SQLITE_BUSY` (logged and,
for best-effort paths, dropped). A long-lived reader — e.g. the dashboard on
auto-refresh — can also pin the WAL checkpoint and grow the `-wal` file. At
learning-scale event rates none of this bites; at sustained bursts
(~50+ events/s) or with multiple hosts feeding one DB it will.

**Design rule: single writer.** Keep the watcher the sole steady-state writer.
Any new component must either hand its writes to the watcher process or stay
read-only; do not add a second continuous writer to the same file.

**PostgreSQL migration path.** All SQL lives behind `db_manager.py` (plain SQL,
no ORM), so a migration is localized:

1. Swap `sqlite3.connect(...)` for a `psycopg` connection pool behind the same
   function signatures.
2. Replace SQLite-isms: `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL`/
   `IDENTITY`, `INSERT OR REPLACE` → `INSERT ... ON CONFLICT ... DO UPDATE`,
   `PRAGMA journal_mode=WAL` → not needed.
3. Move `DB_PATH` to a `DATABASE_URL`-style setting; keep SQLite as the
   default so the offline single-host experience is unchanged.

The trigger point for that migration is multi-host ingestion or sustained
write contention — not something a single monitored machine will reach.
