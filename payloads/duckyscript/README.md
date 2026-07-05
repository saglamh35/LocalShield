# DuckyScript Payloads (Educational)

Benign **DuckyScript** examples for learning how HID injection ("BadUSB") works,
written for an **O.MG Cable Elite** driving an **iPad Air on iPadOS 26**.

> ⚠️ **Lab use only — your own devices only.** These scripts are provided for
> education and defensive awareness as part of the LocalShield learning project.
> Running keystroke-injection hardware against a device you do not own, or without
> explicit permission, is illegal in most jurisdictions. Nothing here exfiltrates
> data, steals credentials, opens a shell, or hides itself — every payload only
> *types text* or *opens an app*, which is the full extent of what a keyboard can
> do on a locked-down iPad.

## Why these are iPad-shaped

On iPadOS 26 an O.MG cable is seen purely as a **USB/Bluetooth keyboard**. It can
type characters and send keyboard shortcuts — nothing more. There is no terminal,
no scripting host, and no filesystem a keyboard can reach. The PowerShell / bash /
reverse-shell payloads you will find in most O.MG and Hak5 GitHub repos target
Windows/macOS/Linux and **do not execute on an iPad at all**. See
[`docs/DUCKYSCRIPT.md`](../../docs/DUCKYSCRIPT.md) for the full explanation and a
DuckyScript keyword reference.

## Files

| File | What it teaches |
|------|-----------------|
| `01_hello_world.txt` | The minimum viable payload: `DELAY`, `STRING`, `ENTER`. |
| `02_awareness_banner_notes.txt` | Open **Notes** via Spotlight and type a security-awareness banner. |
| `03_safari_open_url.txt` | Open **Safari** and navigate to a safe URL — app launch + URL timing. |
| `04_keyboard_shortcuts_demo.txt` | iPadOS hardware-keyboard shortcuts (`GUI SPACE`, `GUI H`, `GUI TAB`). |
| `05_timing_and_repeat.txt` | `DEFAULT_DELAY`, `REPEAT`, and *why* timing matters. |

## How to run

1. Flash the script to your O.MG Cable via its web UI / programmer (see the O.MG
   documentation for your firmware version).
2. Pair/attach the cable to **your own** iPad.
3. Open the target app manually first if a payload assumes one (each header says so),
   then trigger the payload and **watch the screen** — that is the whole test.

Start with `01_hello_world.txt`; if the iPad types "hello from ...", your setup works
and you can move on.
