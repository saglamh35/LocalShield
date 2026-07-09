# VM-target DuckyScript payloads — the *detectable* half (LAB ONLY)

These payloads target a **Windows VM you own** (with Sysmon installed), not an iPad.
Where the scripts in [`payloads/duckyscript/`](../) prove HID injection on an iPad
(which sandboxes an O.MG cable to *just typing*), these launch a **command
interpreter** — which is what produces real, SIEM-visible telemetry. This is the
red→blue bridge: an attack that LocalShield actually detects.

> ⚠️ **Ethics & scope.** Lab-only, on hardware you own. The payload here runs a
> **benign** command (`whoami`); the only "tradecraft" is the hidden window
> (`-w hidden`), which is exactly the signal a detection should catch. Nothing
> downloads code, exfiltrates data, opens a shell/C2, or touches credentials.

## Files

| File | What it does |
|------|--------------|
| `win_recon_hidden.txt` | Run dialog → `powershell -w hidden -nop whoami`. Produces a Sysmon Event 1 (`explorer.exe` → `powershell.exe`, hidden) that trips [`rules/hid_injection.yaml`](../../../rules/hid_injection.yaml). |
| `telemetry/win_recon_hidden.sysmon.json` | The Sysmon record the payload generates — the artifact the SIEM consumes. |

## The purple-team loop

1. **Attack** — flash `win_recon_hidden.txt` to your O.MG cable, attach to your VM.
2. **Telemetry** — Sysmon logs Event 1 (`telemetry/win_recon_hidden.sysmon.json` shows its shape).
3. **Detect** — `rules/hid_injection.yaml` matches the `explorer → hidden powershell` lineage
   (MITRE **T1200** + **T1059.001**).
4. **Respond** — the detection surfaces in the dashboard / Notifier, where the existing SOAR acts.

No VM handy? Replay the loop offline: `python simulate_hid_attack.py` injects the sample
telemetry through the detection engine and into the DB. See
[`docs/DUCKYSCRIPT.md`](../../../docs/DUCKYSCRIPT.md) for the full walkthrough.
