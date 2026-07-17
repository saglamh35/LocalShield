"""
Tests for the Ansible remediation SOAR (modules/ansible_remediation.py).
Covers playbook generation (pure), DB-driven generation, and the dry-run
orchestrator (which must generate + audit but never execute ansible-playbook).
Each test uses an isolated temporary database.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import db_manager
from modules import ansible_remediation as ar


def _find(cve, package, target, fixed):
    return {"cve_id": cve, "package": package, "target": target, "fixed_version": fixed}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test.db")
    db_manager.init_db(path)
    return path


class TestGenerate:
    def test_no_fixable_returns_none(self):
        # A finding without a fixed_version is not remediable.
        assert ar.generate_remediation_playbook([_find("CVE-1", "openssl", "img", None)]) is None
        assert ar.generate_remediation_playbook([]) is None

    def test_generates_valid_playbook_grouped_by_target(self):
        findings = [
            _find("CVE-1", "openssl", "python:3.9-slim", "1.1.1l-1"),
            _find("CVE-2", "bash", "python:3.9-slim", "5.1"),
            _find("CVE-3", "nginx", "web-host", "1.20"),
        ]
        pb = ar.generate_remediation_playbook(findings)
        plays = yaml.safe_load(pb)
        assert isinstance(plays, list) and len(plays) == 2  # two targets -> two plays
        by_host = {p["hosts"]: p for p in plays}
        assert "python_3.9-slim" in by_host  # target sanitized into a host label
        assert by_host["python_3.9-slim"]["become"] is True
        assert len(by_host["python_3.9-slim"]["tasks"]) == 2  # openssl + bash
        task = by_host["web-host"]["tasks"][0]
        assert task["ansible.builtin.package"] == {"name": "nginx", "state": "latest"}

    def test_multiple_cves_same_package_merge_into_one_task(self):
        findings = [
            _find("CVE-1", "openssl", "img", "1.1.1l-1"),
            _find("CVE-2", "openssl", "img", "1.1.1l-1"),
        ]
        plays = yaml.safe_load(ar.generate_remediation_playbook(findings))
        tasks = plays[0]["tasks"]
        assert len(tasks) == 1  # one task for the package
        assert "CVE-1" in tasks[0]["name"] and "CVE-2" in tasks[0]["name"]

    def test_only_fixable_included(self):
        findings = [
            _find("CVE-1", "openssl", "img", "1.1.1l-1"),
            _find("CVE-2", "libc6", "img", None),  # no fix -> excluded
        ]
        plays = yaml.safe_load(ar.generate_remediation_playbook(findings))
        assert len(plays[0]["tasks"]) == 1


class TestDbDriven:
    def test_playbook_for_db_reads_fixable(self, db):
        db_manager.record_vulnerability(
            "CVE-1", "openssl", "img", fixed_version="1.1.1l-1", severity="Critical", db_path=db
        )
        db_manager.record_vulnerability("CVE-2", "libc6", "img", fixed_version="", severity="High", db_path=db)
        pb = ar.playbook_for_db(db_path=db)
        plays = yaml.safe_load(pb)
        assert len(plays) == 1
        assert len(plays[0]["tasks"]) == 1  # only the fixable openssl finding


class TestRemediateDryRun:
    def test_dry_run_generates_and_audits_but_does_not_execute(self, db, tmp_path, monkeypatch):
        db_manager.record_vulnerability(
            "CVE-1", "openssl", "img", fixed_version="1.1.1l-1", severity="Critical", db_path=db
        )

        # Fail loudly if execution is ever attempted in dry-run.
        monkeypatch.setattr(ar, "_run_playbook", lambda p: pytest.fail("must not execute in dry-run"))

        out = str(tmp_path / "out")
        result = ar.remediate(dry_run=True, output_dir=out, db_path=db)

        assert result["executed"] is False
        assert result["plays"] == 1
        assert result["playbook_path"] and Path(result["playbook_path"]).exists()
        # A generated playbook must be valid YAML.
        yaml.safe_load(Path(result["playbook_path"]).read_text())
        # The run is recorded in the audit trail.
        actions = db_manager.get_recent_actions(db_path=db)
        assert any(a[2] == "generate_remediation_playbook" for a in actions)

    def test_nothing_fixable_is_a_noop(self, db, tmp_path):
        db_manager.record_vulnerability("CVE-2", "libc6", "img", fixed_version="", severity="High", db_path=db)
        result = ar.remediate(dry_run=True, output_dir=str(tmp_path), db_path=db)
        assert result["playbook_path"] is None
        assert result["plays"] == 0

    def test_not_dry_run_without_ansible_degrades_gracefully(self, db, tmp_path, monkeypatch):
        db_manager.record_vulnerability(
            "CVE-1", "openssl", "img", fixed_version="1.1.1l-1", severity="Critical", db_path=db
        )
        # ansible-playbook not installed -> generate, warn, do not execute, no raise.
        monkeypatch.setattr(ar.shutil, "which", lambda _: None)
        result = ar.remediate(dry_run=False, output_dir=str(tmp_path), db_path=db)
        assert result["executed"] is False
        assert Path(result["playbook_path"]).exists()


class _FakeProc:
    def __init__(self, returncode):
        self.returncode = returncode
        self.stderr = "boom" if returncode else ""


class TestRunPlaybookPreflight:
    """The execute path must run ansible's own dry run (--check) first and
    abort the real run when the pre-flight fails."""

    @pytest.fixture
    def recorded(self, monkeypatch):
        calls = []
        monkeypatch.setattr(ar.shutil, "which", lambda _: "/usr/bin/ansible-playbook")

        def fake_run(argv, **kwargs):
            calls.append(argv)
            rc = self._rc_for(argv, calls)
            return _FakeProc(rc)

        monkeypatch.setattr(ar.subprocess, "run", fake_run)
        return calls

    # Overridden per-test via closure state
    _rc_map = {}

    def _rc_for(self, argv, calls):
        return self._rc_map.get("check" if "--check" in argv else "run", 0)

    def test_check_then_real_run_in_order(self, db, recorded):
        self._rc_map = {"check": 0, "run": 0}
        assert ar._run_playbook("pb.yml", db_path=db) is True
        assert len(recorded) == 2
        assert "--check" in recorded[0]
        assert "--check" not in recorded[1]

    def test_failing_check_aborts_and_audits(self, db, recorded):
        self._rc_map = {"check": 1}
        assert ar._run_playbook("pb.yml", db_path=db) is False
        # Only the pre-flight ran; the hosts were never touched.
        assert len(recorded) == 1
        assert "--check" in recorded[0]
        actions = db_manager.get_recent_actions(db_path=db)
        assert any(a[2] == "remediation_preflight_failed" for a in actions)

    def test_failing_real_run_returns_false(self, db, recorded):
        self._rc_map = {"check": 0, "run": 2}
        assert ar._run_playbook("pb.yml", db_path=db) is False
        assert len(recorded) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
