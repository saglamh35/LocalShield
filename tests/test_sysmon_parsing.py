"""
Tests for Sysmon field parsing (log_watcher): named XML is the primary path,
positional StringInserts is the fallback. Verifies the fix for silent field
misalignment when optional StringInserts fields are empty.
"""
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# log_watcher imports pywin32 at module load; stub it so parsing is testable
# on any platform.
for _name in ("win32evtlog", "win32evtlogutil", "win32con"):
    sys.modules.setdefault(_name, types.ModuleType(_name))

import log_watcher


def _watcher():
    # Build a bare LogWatcher without running __init__ (needs Windows/DB).
    return log_watcher.LogWatcher.__new__(log_watcher.LogWatcher)


# Real Sysmon XML carries a default namespace — include it to prove the parser
# is namespace-agnostic.
NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


def _sysmon_xml(fields: dict) -> str:
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
    return f'<Event xmlns="{NS}"><System></System><EventData>{data}</EventData></Event>'


class TestEventDataXml:
    def test_extracts_named_fields_with_namespace(self):
        w = _watcher()
        event = SimpleNamespace(XML=_sysmon_xml({
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd /c whoami",
        }))
        got = w._parse_eventdata_xml(event, ["Image", "CommandLine"])
        assert got == {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"}

    def test_returns_none_without_xml(self):
        w = _watcher()
        assert w._parse_eventdata_xml(SimpleNamespace(XML=None), ["Image"]) is None
        assert w._parse_eventdata_xml(SimpleNamespace(), ["Image"]) is None


class TestEvent1:
    def test_xml_is_primary(self):
        w = _watcher()
        event = SimpleNamespace(
            XML=_sysmon_xml({
                "Image": "powershell.exe",
                "CommandLine": "powershell -enc AAAA",
                "User": "DOMAIN\\alice",
                "ParentImage": "explorer.exe",
            }),
            # Deliberately WRONG positional data to prove XML wins:
            StringInserts=["x"] * 25,
        )
        got = w.parse_sysmon_event_1(event)
        assert got["Image"] == "powershell.exe"
        assert got["CommandLine"] == "powershell -enc AAAA"
        assert got["User"] == "DOMAIN\\alice"
        assert got["ParentImage"] == "explorer.exe"

    def test_positional_fallback_when_no_xml(self):
        w = _watcher()
        # Real StringInserts carry a value at every position (not empty), so use
        # non-empty fillers; the parser drops falsy entries.
        inserts = [f"f{i}" for i in range(20)]
        inserts[4] = "C:\\cmd.exe"
        inserts[10] = "cmd /c calc"
        inserts[12] = "WORK\\bob"
        inserts[19] = "winword.exe"
        event = SimpleNamespace(XML=None, StringInserts=inserts)
        got = w.parse_sysmon_event_1(event)
        assert got["Image"] == "C:\\cmd.exe"
        assert got["CommandLine"] == "cmd /c calc"
        assert got["ParentImage"] == "winword.exe"


class TestEvent5:
    def test_xml_is_primary(self):
        w = _watcher()
        event = SimpleNamespace(
            XML=_sysmon_xml({"Image": "notepad.exe", "ProcessId": "4321"}),
            StringInserts=["wrong"] * 6,
        )
        got = w.parse_sysmon_event_5(event)
        assert got["Image"] == "notepad.exe"
        assert got["ProcessId"] == "4321"

    def test_positional_fallback(self):
        w = _watcher()
        inserts = [f"f{i}" for i in range(5)]
        inserts[3] = "9999"
        inserts[4] = "svchost.exe"
        event = SimpleNamespace(XML=None, StringInserts=inserts)
        got = w.parse_sysmon_event_5(event)
        assert got["ProcessId"] == "9999"
        assert got["Image"] == "svchost.exe"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
