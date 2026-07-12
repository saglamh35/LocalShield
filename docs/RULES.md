# Detection Rule Authoring Guide

LocalShield rules are YAML files in `rules/`. Each file is one rule (or a list
of rules). At load time every rule is validated against a schema
(`modules/rule_schema.py`); a malformed rule is **skipped with a logged error**,
never crashing the engine.

## Schema

```yaml
id: "my_rule_001"          # optional (auto-generated from filename if omitted)
name: "Human-readable name" # required
description: "What it detects and why"
enabled: true               # default true
severity: "high"            # low | medium | high | critical
mitre:                      # string or list of ATT&CK technique IDs
  - "T1059.001"
tags: ["execution", "powershell"]
match_message: "🔴 Message shown when the rule fires"

conditions:
  # --- selection ---
  provider: "Security"          # Security | Sysmon (matches the log channel)
  event_id: "4625"              # single ID, or a list ["4625", "4771"] = OR
  message_regex: "logon"        # regex on the event message
  command_line_regex: "-enc"    # regex on Sysmon CommandLine
  image_regex: "powershell"     # regex on Sysmon Image
  parent_image_regex: "winword" # regex on Sysmon ParentImage

  # --- negation (rule does NOT fire if these match) ---
  not_message_regex: "ANONYMOUS"
  not_command_line_regex: "-File C:\\\\approved\\\\"

  # --- thresholds (counting) ---
  time_window: 60               # seconds
  threshold: 5                  # fire on the Nth match within the window
  group_by: "source_ip"         # count per attacker IP, not one global counter

  # --- cross-event correlation ---
  correlation:
    prior_event_id: "4625"      # a prior pattern...
    count: 5                    # ...seen this many times...
    within: 300                 # ...within this many seconds, same source IP
```

All conditions are combined with **AND** (every specified condition must pass).
Use `event_id` as a list for OR, and `not_*` for exclusions.

## Field reference

| Field | Meaning |
|-------|---------|
| `provider` | Log channel: `Security` or `Sysmon`. |
| `event_id` | Windows Event ID; a list matches any of them. |
| `*_regex` | Case-insensitive regex against the named field. |
| `not_*_regex` | Exclusion: the rule fails if this matches. |
| `threshold` / `time_window` | Fire only after `threshold` matches within the window. |
| `group_by: source_ip` | Count separately per attacker IP (extracted from the message). |
| `correlation` | Fire the `event_id` (trigger) only after `count` `prior_event_id`s from the same source IP within `within` seconds. |

## Examples

- **Brute force (per source):** `rules/brute_force.yaml` — 4625 × 5 in 60s, `group_by: source_ip`.
- **Successful brute force (correlation):** `rules/brute_force_success.yaml` — 4624 after ≥5 prior 4625 from the same IP.
- **RDP brute force (regex + threshold):** `rules/rdp_brute_force.yaml` — 4625 with `Logon Type: 10` × 5 in 120s, per source IP.
- **LOLBin download:** `rules/lolbin_download.yaml` — Sysmon 1 + certutil/bitsadmin command line.
- **Log tampering (single event):** `rules/audit_log_cleared.yaml` (1102, critical) and `rules/audit_policy_change.yaml` (4719).
- **Persistence:** `rules/scheduled_task_created.yaml` (4698) and `rules/new_service_install.yaml` (7045).

## Testing a rule

Add a test in `tests/` (see `tests/test_extended_rules.py` for the pattern):
build a `DetectionEngine(rules_dir=...)`, then call `check_event(...)` or the
rule's `matches(...)` with a synthetic event and assert the result.
