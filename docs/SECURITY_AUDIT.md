# 🔍 Security Audit — Self-Assessment

> During development I stopped adding features and instead sat down to attack
> LocalShield the way an adversary would. A defensive tool that can be turned
> against its own user is worse than no tool at all — so before trusting the
> automated response layer, I audited it.
>
> This document records the three issues that audit surfaced, the attack
> scenario behind each, the root cause, the fix, and the regression test that
> now guards against it. Every finding below has a corresponding test in
> [`tests/test_security_fixes.py`](../tests/test_security_fixes.py).

---

## Threat model

LocalShield ingests **untrusted input from two directions** and can take a
**privileged, automated action** (modifying the Windows Firewall) in response:

- **Log content** (usernames, workstation names, messages) is fully
  attacker-influenced. An attacker who can generate a failed logon controls
  parts of the very record LocalShield analyses.
- **The automated response (SOAR)** blocks source IPs at the firewall with no
  human in the loop.

The dangerous combination is obvious once stated: *if attacker-controlled log
text can steer a privileged, unattended action, the tool becomes a weapon
pointed at its own operator.* That framing drove the whole audit.

---

## LS-01 — Auto-response block-list poisoning

| | |
|---|---|
| **Severity** | High |
| **Class** | Improper neutralization of untrusted input → privileged action (CWE-77 flavour) |
| **Component** | `modules/response_engine.py` |
| **Status** | Fixed ✅ · Regression test: `TestSourceIPExtraction` |

### Description

The automated-response layer picked IPs to block by scanning the **entire** log
message for anything shaped like an IPv4 address. But a Windows failed-logon
record contains several free-text fields — `Account Name`, `Workstation Name` —
that are populated with values chosen by the party attempting to log on.

### Attack scenario

An attacker triggers a failed logon while setting their **username** to
`8.8.8.8` (or embedding `1.2.3.4` in the workstation name). The blanket IP scan
extracts that address from the attacker-controlled field and the SOAR component
dutifully adds a **firewall block rule against a third-party IP the attacker
chose** — e.g. a public DNS resolver, a partner network, or an internal
gateway. The result is an attacker-driven denial of service executed *by the
defender's own tooling*.

### Root cause

Trusting position-agnostic pattern matching (`any IP anywhere in the text`)
over structured field semantics. The code could not distinguish "the IP the OS
recorded as the source of the connection" from "an IP a human typed into a name
field."

### Fix

Blocking candidates are now extracted **only from known source-address fields**,
never from a blanket scan:

```python
patterns = [
    r"Source Network Address:\s*(\d{1,3}(?:\.\d{1,3}){3})",  # Windows Security
    r"rhost=(\d{1,3}(?:\.\d{1,3}){3})",                       # Linux PAM
    r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})",                    # SSH auth.log
]
```

An IP that appears only inside a username or workstation name is now ignored
entirely. This is layered on top of the pre-existing defences: a critical-IP
allowlist (DNS/gateway are never blocked), private-IP filtering, and a persisted
audit trail of every automated action.

### Regression test

```python
def test_ip_inside_attacker_controlled_string_is_ignored(self):
    fw = FirewallManager(allowlist=[])
    text = "An account failed to log on.\n\tAccount Name:\t8.8.8.8\n\tWorkstation Name:\tEVIL-1.2.3.4\n"
    assert fw.extract_source_ips_from_text(text) == []
```

---

## LS-02 — Cross-host false-positive brute-force alerts

| | |
|---|---|
| **Severity** | Medium |
| **Class** | Detection-logic flaw → alert fatigue / masking |
| **Component** | `modules/detection_engine.py` |
| **Status** | Fixed ✅ · Regression test: `TestPerSourceBruteForce` |

### Description

The brute-force rule counted failed-logon events against a **single global
counter per Event ID**. Five *unrelated* single failures — one each from five
different hosts, none of them an actual attack — summed past the threshold and
raised a brute-force alert.

### Why it matters

This is not merely cosmetic. In a real SOC, **false positives are a security
problem**: they cause alert fatigue, and an analyst who has learned to dismiss
"brute-force" alerts as noise will dismiss the real one too. A detector that
cries wolf is a detector that gets muted.

### Root cause

Conflating "N failures were observed" with "N failures came from one actor."
Brute force is defined by a *single source* hammering a target; the counter has
to reflect that.

### Fix

Threshold rules gained an optional `group_by: source_ip` dimension. The engine
extracts the attacker IP from the same structured source-address fields used in
LS-01 and keeps **one counter per source**. Events with no extractable source IP
fall back to the global counter, so nothing is silently dropped.

```yaml
conditions:
  event_id: "4625"
  threshold: 5
  time_window: 300
  group_by: "source_ip"   # count per attacker, not globally
```

### Regression tests

- `test_five_failures_from_five_hosts_do_not_trigger` — no false alert
- `test_five_failures_from_same_host_trigger` — real attack still fires
- `test_message_without_ip_falls_back_to_global_counter` — safe fallback

---

## LS-03 — Duplicate event processing via read-overlap

| | |
|---|---|
| **Severity** | Low (integrity) |
| **Class** | Idempotency / double-processing |
| **Component** | `log_watcher.py` |
| **Status** | Fixed ✅ · Regression test: `TestRecordNumberDedup` |

### Description

The log watcher polls the Windows Event Log on an interval, reading events newer
than `now − interval` with a small **5-second overlap buffer** so nothing slips
through the gap between polls. The side effect: an event landing inside that
overlap window is returned on **two consecutive reads** and processed twice.

### Why it matters

Double-processing quietly corrupts everything downstream: the same event is
stored twice, and — worse — it is counted twice against threshold rules. A
duplicated failure inflates the brute-force counter and can manufacture an alert
(and, via LS-01's response layer, a firewall action) from activity that never
actually crossed the threshold.

### Root cause

A time-window filter is inherently non-idempotent across overlapping reads.
Time alone cannot answer "have I already seen this specific record?"

### Fix

Deduplication by **RecordNumber** — Windows assigns each log entry a
monotonically increasing record number. The watcher remembers the highest one
seen **per channel** and skips anything at or below it; events lacking a
RecordNumber fall back to the time filter. Channels are tracked independently,
so the same record number on `Security` and `Sysmon` is correctly treated as two
distinct events.

### Regression tests

- `test_same_event_not_selected_twice` — overlap no longer double-counts
- `test_new_records_still_selected` — genuinely new events pass through
- `test_channels_tracked_independently` — per-channel state
- `test_old_events_filtered_by_time` — RecordNumber-less fallback intact

---

## LS-04 — Event loss under burst load

| | |
|---|---|
| **Severity** | Medium (availability of detection) |
| **Class** | Detection gap / silent data loss |
| **Component** | `log_watcher.py` |
| **Status** | Fixed ✅ · Regression test: `TestChannelDrain` |

### Description

Each watch cycle issued a **single** `ReadEventLog` call, which returns at most
~1000 of the newest events. During a burst — say, a brute-force flood producing
thousands of 4625s in one interval — everything beyond that first batch was
never read. Because the LS-03 high-water mark then advanced to the newest
RecordNumber, the skipped middle was never re-read either: the events were lost
permanently, and precisely when detection mattered most.

### Fix

`_read_channel_events` drains the channel newest-to-oldest, batch by batch,
until it reaches the previous high-water mark (or a hard cap of
`_MAX_READ_BATCHES` batches per cycle, so a flooding channel cannot pin the
watcher). No gap can open between the last processed record and the newest.

### Regression tests

- `test_burst_larger_than_one_batch_is_fully_drained` — 3000-event burst, zero loss
- `test_drain_stops_at_high_water_mark` — no re-reading of processed records
- `test_drain_is_bounded` — flood cannot cause unbounded work

---

## LS-05 — Post-log-clear blindness (anti-forensics window)

| | |
|---|---|
| **Severity** | Medium (availability of detection) |
| **Class** | Detection gap / state desynchronization |
| **Component** | `log_watcher.py` |
| **Status** | Fixed ✅ · Regression test: `TestRecordNumberReset` |

### Description

Clearing the event log is a classic attacker anti-forensics move (Event 1102).
Windows then restarts RecordNumbers from 1 — but the LS-03 dedup still held the
old high-water mark, so **every** post-clear event was treated as
"already processed" until the counter climbed back past the old maximum. The
attacker's clear didn't just erase history; it blinded future detection too.
A related edge: the startup time filter also applied in steady state, dropping
events delivered late (queued > 5 s) despite their fresh RecordNumbers.

### Fix

`_select_new_events` detects the reset (newest RecordNumber below the stored
mark), logs a warning and re-baselines the channel. The time filter now applies
only to the baseline read, so in steady state the RecordNumber alone — which
proves whether a record was seen — decides.

### Regression tests

- `test_log_clear_rebaselines` — post-clear events are processed again
- `test_late_delivered_event_survives_time_threshold` — no steady-state time drops
- `test_baseline_read_still_skips_history` — startup backlog still skipped

---

## Takeaways

Five findings, one common thread: **trusting the shape of data over its
provenance.** An IP is an IP, a failure is a failure, an event is an event —
until you ask *where it came from* and *whether you've acted on it already.*

- **LS-01** — sanitize the *source* of a privileged action, not just its format.
- **LS-02** — a detector's job is to model the *actor*, not tally raw events.
- **LS-03** — any at-least-once pipeline needs an idempotency key.
- **LS-04** — a reader that can fall behind must know how to catch up.
- **LS-05** — persistent state needs a story for when its anchor resets.

Each fix ships with regression tests that fail on the old behaviour, so the
audit is not a one-time cleanup but a permanent guardrail. That is the point of
writing it down: the next person to touch this code — including future me —
inherits both the fix and the reason for it.

*LocalShield remains an educational prototype (see the Scope & Limitations
section of the [README](../README.md)); this audit hardens the components most
likely to cause real-world harm, not a claim of production readiness.*
