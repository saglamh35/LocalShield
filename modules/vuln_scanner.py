"""
Vulnerability Scanner Module - Trivy-based CVE detection (offline-first).

LocalShield's day-job feature: find *which CVE affects which package* on a
container image or a host filesystem, so an operator can decide what to patch.

Design principles (consistent with the rest of the codebase):
- **Offline-first.** Trivy's vulnerability DB is downloaded once and then used
  air-gapped (``--skip-db-update``), exactly like the local Ollama model.
- **Graceful degradation.** If the Trivy binary is absent the scanner logs a
  warning and disables itself — it never raises into the caller (mirrors
  ``modules/threat_intel.py`` when its CSV is missing).
- **De-spammed alerting.** A scan can surface hundreds of CVEs; we emit exactly
  ONE summary notification per scan through the existing ``Notifier``, not one
  alert per CVE.

Trivy JSON shape consumed here (``trivy image|rootfs --format json``)::

    {"Results": [{"Target": "...", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-...", "PkgName": "...",
         "InstalledVersion": "...", "FixedVersion": "...",
         "Severity": "CRITICAL", "Title": "...",
         "CVSS": {"nvd": {"V3Score": 9.8}}}]}]}
"""

import json
import logging
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

import config
import db_manager
from modules.notifier import get_notifier

logger = logging.getLogger(__name__)

# Trivy severities -> LocalShield's canonical Title-case labels.
_SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Unknown",
}
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class VulnScanner:
    """Scans container images / filesystems with Trivy and stores CVE findings."""

    def __init__(
        self,
        trivy_path: Optional[str] = None,
        cache_dir: Optional[str] = None,
        notify_min_severity: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        # str() coercion keeps these concretely typed (getattr returns Any),
        # so shutil.which() and subprocess.run() receive plain str arguments.
        self.trivy_path: str = str(trivy_path or getattr(config, "TRIVY_PATH", "trivy"))
        self.cache_dir: str = str(cache_dir if cache_dir is not None else getattr(config, "TRIVY_CACHE_DIR", ""))
        self.notify_min_severity: str = str(notify_min_severity or getattr(config, "VULN_NOTIFY_MIN_SEVERITY", "High"))
        self.db_path: Optional[str] = db_path

    # -- availability -------------------------------------------------------

    def is_available(self) -> bool:
        """True if the Trivy binary can be resolved. Never raises."""
        try:
            return shutil.which(self.trivy_path) is not None
        except Exception:
            return False

    def is_db_present(self) -> bool:
        """
        True if a Trivy vulnerability DB is available locally. This is what makes
        offline scanning meaningful: without a pre-downloaded DB a scan errors out
        and looks identical to a clean "no vulnerabilities" result. Callers use
        this to tell "DB missing" apart from "target is clean". Never raises.
        """
        if not self.is_available():
            return False
        cmd = [self.trivy_path, "version", "--format", "json"]
        if self.cache_dir:
            cmd += ["--cache-dir", self.cache_dir]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)  # noqa: S603
            if proc.returncode != 0:
                return False
            return self._db_present_from_version(proc.stdout)
        except Exception:
            return False

    @staticmethod
    def _db_present_from_version(version_json: str) -> bool:
        """Parse `trivy version --format json`; True if it reports a vuln DB."""
        try:
            data = json.loads(version_json)
        except (ValueError, TypeError):
            return False
        vdb = data.get("VulnerabilityDB")
        return isinstance(vdb, dict) and vdb.get("UpdatedAt") is not None

    # -- public scanning API ------------------------------------------------

    def scan_image(self, image: str, store: bool = True, notify: bool = True) -> List[Dict[str, Any]]:
        """Scan a container image. Returns normalized findings (possibly empty)."""
        return self._scan("image", image, "image", store=store, notify=notify)

    def scan_filesystem(self, path: str, store: bool = True, notify: bool = True) -> List[Dict[str, Any]]:
        """Scan a host filesystem / rootfs path. Returns normalized findings."""
        return self._scan("rootfs", path, "filesystem", store=store, notify=notify)

    def scan_configured_targets(self) -> Dict[str, Any]:
        """
        Scan every image/path from config (VULN_SCAN_IMAGES / VULN_SCAN_PATHS),
        store findings, and emit ONE summary notification for the whole run.
        Returns a summary dict {scanned, findings, counts, available}.
        """
        if not self.is_available():
            logger.warning(
                "⚠️  Trivy binary '%s' not found — vulnerability scanning disabled. "
                "Install Trivy and pre-download its DB to enable this feature.",
                self.trivy_path,
            )
            return {"scanned": 0, "findings": 0, "counts": {}, "available": False, "db_present": False}

        # A scan without a local DB errors out and would look like "no findings".
        # Surface that distinctly instead of silently reporting a clean result.
        if not self.is_db_present():
            logger.warning(
                "⚠️  Trivy is installed but no local vulnerability DB was found. "
                "Run `trivy image --download-db-only` once, then scans run offline."
            )
            return {"scanned": 0, "findings": 0, "counts": {}, "available": True, "db_present": False}

        scan_time = datetime.now()
        all_findings: List[Dict[str, Any]] = []
        scanned = 0

        for image in getattr(config, "VULN_SCAN_IMAGES", []):
            all_findings += self._scan("image", image, "image", store=True, notify=False, scan_time=scan_time)
            scanned += 1
        for path in getattr(config, "VULN_SCAN_PATHS", []):
            all_findings += self._scan("rootfs", path, "filesystem", store=True, notify=False, scan_time=scan_time)
            scanned += 1

        counts = self._count_by_severity(all_findings)
        self._notify_summary(all_findings, counts)
        logger.info("Vulnerability scan complete: %d target(s), %d finding(s)", scanned, len(all_findings))
        return {
            "scanned": scanned,
            "findings": len(all_findings),
            "counts": counts,
            "available": True,
            "db_present": True,
        }

    # -- internals ----------------------------------------------------------

    def _scan(
        self,
        subcommand: str,
        target: str,
        target_type: str,
        store: bool,
        notify: bool,
        scan_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        raw = self._run_trivy(subcommand, target)
        if raw is None:
            return []
        findings = self._parse(raw, target, target_type)
        scan_time = scan_time or datetime.now()
        if store:
            self._store(findings, scan_time)
        if notify:
            self._notify_summary(findings, self._count_by_severity(findings))
        return findings

    def _run_trivy(self, subcommand: str, target: str) -> Optional[str]:
        """
        Run Trivy and return its raw JSON stdout, or None on any failure.
        Offline-safe: ``--skip-db-update`` forces air-gapped operation.
        """
        if not self.is_available():
            logger.warning("⚠️  Trivy not available — skipping scan of %s", target)
            return None

        cmd = [self.trivy_path, subcommand, "--format", "json", "--skip-db-update", "--quiet"]
        if self.cache_dir:
            cmd += ["--cache-dir", self.cache_dir]
        cmd.append(target)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # noqa: S603
            if proc.returncode != 0:
                stderr = proc.stderr.strip()
                if "db" in stderr.lower() and ("download" in stderr.lower() or "need to be updated" in stderr.lower()):
                    logger.error(
                        "Trivy scan of %s failed: vulnerability DB unavailable. "
                        "Run `trivy image --download-db-only` once for offline scans. (%s)",
                        target,
                        stderr,
                    )
                else:
                    logger.error("Trivy scan of %s failed (rc=%s): %s", target, proc.returncode, stderr)
                return None
            return proc.stdout
        except FileNotFoundError:
            logger.warning("⚠️  Trivy binary disappeared — scanning disabled")
            return None
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan of %s timed out", target)
            return None
        except Exception as e:
            logger.error("Unexpected error scanning %s: %s", target, e, exc_info=True)
            return None

    def _parse(self, raw_json: str, target: str, target_type: str) -> List[Dict[str, Any]]:
        """Normalize Trivy JSON into LocalShield finding dicts. Never raises."""
        findings: List[Dict[str, Any]] = []
        try:
            data = json.loads(raw_json)
        except (ValueError, TypeError) as e:
            logger.error("Could not parse Trivy JSON for %s: %s", target, e)
            return findings

        for result in data.get("Results") or []:
            # Prefer the per-result target label (e.g. the OS/lib name) but keep
            # the scanned image/path as the stored target for grouping.
            for vuln in result.get("Vulnerabilities") or []:
                cve_id = vuln.get("VulnerabilityID")
                package = vuln.get("PkgName")
                if not cve_id or not package:
                    continue
                findings.append(
                    {
                        "cve_id": cve_id,
                        "package": package,
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": _SEVERITY_MAP.get(str(vuln.get("Severity", "")).upper(), "Unknown"),
                        "target": target,
                        "target_type": target_type,
                        "cvss": self._extract_cvss(vuln.get("CVSS")),
                        # Title, falling back to (often long) Description — truncate
                        # so it can't bloat the dashboard table.
                        "title": self._short_title(vuln.get("Title") or vuln.get("Description")),
                    }
                )
        return findings

    @staticmethod
    def _short_title(title: Any, limit: int = 300) -> Optional[str]:
        """Trim an over-long title/description so it can't bloat the UI table."""
        if not title:
            return None
        text = str(title)
        return text if len(text) <= limit else text[: limit - 1] + "…"

    @staticmethod
    def _extract_cvss(cvss: Any) -> Optional[float]:
        """Best-effort CVSS base score: prefer NVD V3, then any V3, then V2."""
        if not isinstance(cvss, dict):
            return None
        nvd = cvss.get("nvd")
        if isinstance(nvd, dict) and nvd.get("V3Score") is not None:
            return float(nvd["V3Score"])
        for source in cvss.values():
            if isinstance(source, dict) and source.get("V3Score") is not None:
                return float(source["V3Score"])
        for source in cvss.values():
            if isinstance(source, dict) and source.get("V2Score") is not None:
                return float(source["V2Score"])
        return None

    def _store(self, findings: List[Dict[str, Any]], scan_time: datetime) -> None:
        # Single connection / one commit for the whole batch (see db_manager).
        db_manager.record_vulnerabilities(findings, scan_time=scan_time, db_path=self.db_path)

    @staticmethod
    def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for f in findings:
            sev = f.get("severity", "Unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _notify_summary(self, findings: List[Dict[str, Any]], counts: Dict[str, int]) -> None:
        """
        Emit ONE notification summarizing the scan, only if the most severe
        finding meets the configured threshold. Reuses the existing Notifier.
        """
        if not findings:
            return
        # Highest severity present in this scan.
        top = max(findings, key=lambda f: _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0))
        top_sev = str(top.get("severity", "Unknown"))
        if _SEVERITY_RANK.get(top_sev.lower(), 0) < _SEVERITY_RANK.get(str(self.notify_min_severity).lower(), 0):
            return
        detail = (
            f"{counts.get('Critical', 0)} Critical, {counts.get('High', 0)} High, "
            f"{counts.get('Medium', 0)} Medium across {len({f['target'] for f in findings})} target(s)"
        )
        try:
            get_notifier().notify(
                severity=top_sev,
                title=f"Vulnerability scan: {len(findings)} CVE finding(s)",
                detail=detail,
            )
        except Exception as e:  # notifications must never break a scan
            logger.debug("vuln summary notification failed (ignored): %s", e)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    db_manager.init_db()
    scanner = VulnScanner()
    print(scanner.scan_configured_targets())
