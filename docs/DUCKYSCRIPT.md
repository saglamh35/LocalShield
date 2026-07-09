# DuckyScript & HID Injection — A Learning Guide

This guide accompanies the benign example payloads in
[`payloads/duckyscript/`](../payloads/duckyscript/). It explains what an O.MG
cable does, how HID injection ("BadUSB") works, the DuckyScript keywords the
examples use, **why the scary payloads you find on GitHub don't run on an iPad**,
and — because LocalShield is a defensive project — how a blue team detects this
class of attack.

> ⚠️ **Ethics & scope.** Everything here is for education and defensive awareness,
> to be used on **hardware you own**. Keystroke-injection tools are legal to study
> and misuse to deploy against others. None of the example payloads exfiltrate
> data, steal credentials, open a shell, or hide their activity — they only type
> text or open an app, which is all a keyboard can do on a locked device.

---

## 1. What is an O.MG Cable and HID injection?

An **O.MG Cable** looks and charges like a normal USB cable, but hides a tiny
computer with Wi-Fi. When plugged in, it registers itself with the host as a
**HID keyboard** (Human Interface Device). The host trusts it exactly like any
keyboard you'd plug in — because at the protocol level, it *is* one.

That trust is the whole attack. The cable "types" a pre-written script of
keystrokes far faster than a human, so it can drive the UI: open a launcher,
start a program, type a command, press Enter. This technique is **BadUSB**, and
in the MITRE ATT&CK framework it is **[T1200 — Hardware Additions](https://attack.mitre.org/techniques/T1200/)**.
The keystrokes then typically launch a command interpreter, which is
**[T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)**.

The script language these devices speak is **DuckyScript**, originally from the
Hak5 USB Rubber Ducky. The O.MG cable runs a compatible dialect.

---

## 2. DuckyScript keyword reference

The example payloads deliberately stick to the widely-supported core keywords so
they run across firmware versions:

| Keyword | Meaning |
|---------|---------|
| `REM <text>` | Comment. Ignored by the device. |
| `STRING <text>` | Type the literal text that follows. |
| `DELAY <ms>` | Pause for N milliseconds. |
| `DEFAULT_DELAY <ms>` | Insert this pause *before every* subsequent command. |
| `ENTER` | Press Return/Enter. |
| `GUI <key>` | Hold the GUI/Command key (⌘ on Apple, Win key on Windows) with `<key>`. `GUI` alone presses it solo. |
| `SHIFT` / `CTRL` / `ALT` | Modifier keys, combinable, e.g. `GUI SHIFT 3`. |
| `ESCAPE`, `TAB`, `SPACE` | The named keys. `GUI SPACE` = Command+Space (Spotlight). |
| `REPEAT <n>` | Re-run the **previous** command N more times. |

Timing note: a keyboard has no feedback channel. It cannot tell whether the target
is ready, so **`DELAY` is how you stay in sync** — type too early and keystrokes
are dropped. `payloads/duckyscript/05_timing_and_repeat.txt` demonstrates this.

---

## 3. iPadOS 26 reality check — what actually runs on an iPad

This is the most important section for the iPad use case.

On **iPadOS 26**, an attached O.MG cable is treated as nothing more than a
**keyboard**. That is a hard sandbox boundary. From a keyboard, an iPad gives you:

- ✅ Typing into whatever text field currently has focus.
- ✅ System keyboard shortcuts: `GUI SPACE` (Spotlight), `GUI H` (Home),
  `GUI TAB` (app switcher), `GUI L` (Safari address bar), etc.
- ✅ Opening apps and navigating to URLs through those shortcuts.

And that is the entire toolbox. Notably **absent**:

- ❌ No terminal, shell, or command prompt to open.
- ❌ No scripting host (no PowerShell, bash, `cmd`, `wscript`, Python REPL).
- ❌ No filesystem a keyboard can read or write.
- ❌ No way to run downloaded code, install background processes, or persist.

### Why the GitHub payloads don't work here

Search "O.MG cable payloads" or "USB Rubber Ducky payloads" and you'll find
hundreds of scripts. The overwhelming majority are written for **Windows, macOS,
or Linux** and follow a shape like:

1. Open the OS launcher (`GUI r` Run dialog on Windows, Spotlight on macOS).
2. Launch a **command interpreter** (PowerShell / Terminal / `cmd`).
3. Paste a one-liner that **downloads and executes** more code, or reads files
   and sends them somewhere.

Step 2 is where they die on an iPad: **there is no interpreter to launch.** Typing
`powershell -enc ...` into an iPad just... types that text into a note. The
payload category "type a command into a shell" has no target surface on iPadOS.

So for the iPad, the honest and complete demonstration set is the benign one in
this repo: prove HID injection works (it types by itself), open an app, navigate
Safari, drive shortcuts, and understand timing. That fully covers the *concept*
without pretending capabilities the platform doesn't grant.

### Structure of desktop payloads (for syntax literacy only)

So you can *read* the desktop payloads you'll encounter — not run them — here is
their skeleton, with the dangerous line intentionally left as a placeholder:

```
REM  (Windows) - open the Run dialog
GUI r
DELAY 500
REM  launch an interpreter, then type a command into it
STRING powershell
ENTER
DELAY 800
STRING <a command would go here>
ENTER
```

The interesting part on the offensive side is always the `<command>` — and that
is a *Windows/PowerShell* problem, not a DuckyScript one. DuckyScript is just the
keyboard. Studying detection (next section) is the more valuable half anyway.

---

## 4. Blue-team tie-in — detecting HID injection

LocalShield is a defensive SIEM, so the natural question is: *if a BadUSB device
ran against a Windows host, what would the logs look like, and can we catch it?*

The tell is the **process ancestry and speed**. A ducky payload on Windows almost
always produces a launcher (`explorer.exe`, the Run dialog's host) spawning a
**command interpreter** with suspicious flags, milliseconds after a new USB HID
device appeared. In Sysmon process-creation (Event ID 1) terms:

- `ParentImage` = `explorer.exe`
- `Image` = `powershell.exe` / `cmd.exe` / `wscript.exe`
- `CommandLine` carrying `-enc`, `-w hidden`, `iwr`, `DownloadString`, etc.

LocalShield ships a rule for exactly this pattern:
[`rules/hid_injection.yaml`](../rules/hid_injection.yaml), mapped to **T1200**
(Hardware Additions) and **T1059.001** (PowerShell). See
[`docs/RULES.md`](RULES.md) for the rule schema and how matching works, and
`tests/test_hid_injection_rule.py` for worked matching examples.

Defensive takeaways that generalize beyond this one rule:

- **Process lineage beats keywords.** `explorer.exe → powershell.exe` is rare and
  suspicious; alert on the relationship, not just the binary name.
- **Correlate with device events.** A brand-new HID keyboard (Windows Event
  `6416` / driver install) immediately followed by an interpreter launch is a
  strong BadUSB signal.
- **Physical > logical.** The real fix is hygiene: USB port control / device
  allow-listing, data-blocker adapters, and never trusting found or gifted cables.

---

## 5. VM-target purple-team walkthrough (attack → detect → respond)

Section 3 explained why the *iPad* payloads can only type. To actually exercise the
blue-team side you need a target that runs an interpreter — a **Windows VM you own**
with Sysmon. That is the *detectable* half of the loop, and it ships in
[`payloads/duckyscript/vm/`](../payloads/duckyscript/vm/).

The payload `win_recon_hidden.txt` opens the Run dialog and types:

```
powershell -w hidden -nop whoami
```

This is deliberately **benign** — `whoami` prints a username and nothing else. The
only tradecraft is `-w hidden` (a hidden window), which is *exactly* the signal a
detection should catch. So there is no weaponization, yet the telemetry is real.

**The loop:**

1. **Attack** — flash the payload to your O.MG cable, attach it to your VM.
2. **Telemetry** — Sysmon records a Process Create (Event ID 1) with
   `ParentImage=explorer.exe`, `Image=powershell.exe`, and the hidden-window command
   line. Its shape is captured in `payloads/duckyscript/vm/telemetry/win_recon_hidden.sysmon.json`.
3. **Detect** — [`rules/hid_injection.yaml`](../rules/hid_injection.yaml) matches the
   `explorer → hidden powershell` lineage → **T1200** (Hardware Additions) +
   **T1059.001** (PowerShell).
4. **Respond** — the detection surfaces in the dashboard and through the `Notifier`,
   where the existing SOAR (firewall / Ansible remediation) can act.

**No VM handy?** Replay it offline — the same detection path, no hardware:

```bash
python simulate_hid_attack.py
```

This runs the sample telemetry through the detection engine and stores the T1200
detection in the DB (see `tests/test_purple_team_detection.py` for the asserted
attack→detect proof).

> The command stays benign on purpose. A *weaponized* payload (encoded download,
> credential dump, C2) is out of scope for this project — the valuable, career-relevant
> skill is the **detection**, which this loop demonstrates in full.

## 6. See also

- Example payloads: [`payloads/duckyscript/`](../payloads/duckyscript/)
- Detection rule: [`rules/hid_injection.yaml`](../rules/hid_injection.yaml)
- Rule authoring: [`docs/RULES.md`](RULES.md)
- MITRE: [T1200](https://attack.mitre.org/techniques/T1200/) ·
  [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
