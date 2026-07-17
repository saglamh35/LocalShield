# Contributing to LocalShield

LocalShield is an educational, offline SIEM. Contributions that keep it simple,
offline, and well-tested are welcome.

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
pre-commit install              # optional: run lint/format on commit
```

`pywin32` is Windows-only (installed via an environment marker), so the
detection core, tests, and tooling all work on Linux/macOS too.

## Development workflow

```bash
pytest                          # run the test suite
ruff check .                    # lint
ruff format .                   # auto-format
mypy modules/                   # type-check the modules package
```

CI runs the same three checks (lint, type, tests on Python 3.10–3.12). Please
keep them green and add tests for new behavior.

## Adding a detection rule

1. Create a YAML file in `rules/` — see **[docs/RULES.md](docs/RULES.md)** for
   the schema and examples.
2. Add a test in `tests/` (follow `tests/test_extended_rules.py`).
3. Run `pytest` and `ruff check .`.

## Ground rules

- **Stay offline.** No feature may require an internet connection. The only
  networked backend (the webhook notifier) is strictly opt-in and offline-safe.
- **Keep the dashboard localhost-bound.** It has no authentication by design.
- **Automation must stay safe.** Preserve the firewall allowlist and the
  structured-source-only block targeting.
- **Match the surrounding style** (English comments/docstrings, type hints).

## Suppressing linter/scanner findings

Every `# noqa` / `# nosec` must carry a one-line justification on the same
line. For ruff, append it after the code; for bandit, the reason goes *before*
the marker (bandit parses everything after `# nosec` as test IDs):

```python
proc = subprocess.run(cmd, ...)  # noqa: S603 - fixed argv, no shell; trivy path from operator config
root = ET.fromstring(xml)  # XML from the local event subsystem, not a network peer  # nosec B314
```

A suppression without a reason is a review blocker — if the reason is hard to
write, the finding probably deserves a fix instead.

## Project layout

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the component map and
data flow.
