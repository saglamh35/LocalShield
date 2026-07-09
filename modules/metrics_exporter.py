"""
Metrics Exporter Module - Prometheus text-exposition for LocalShield.

Phase 3 of the DevSecOps direction. Exposes LocalShield's SIEM + vulnerability
KPIs as Prometheus metrics so the fleet-standard **Prometheus scrape → Grafana
dashboard** stack (as used at the user's day job) can observe LocalShield.

Design principles (consistent with the rest of the project):
- **Offline-first, no new deps.** Metrics are rendered as plain text and served
  by the Python standard-library ``http.server`` — no prometheus_client, no
  network egress. Binds ``127.0.0.1`` by default.
- **Reuse.** Every value comes from an existing ``db_manager`` KPI getter; this
  module adds no new SQL.
- **Never crash the scrape.** A render failure returns HTTP 500 rather than
  taking the server down.

Run it as its own process, like the log watcher::

    python -m modules.metrics_exporter
"""

import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Optional

import config
import db_manager

logger = logging.getLogger(__name__)

# Prometheus text-exposition content type (format version 0.0.4).
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def render_metrics(db_path: Optional[str] = None) -> str:
    """
    Render the current LocalShield KPIs as a Prometheus text-exposition payload.
    Pure read-only function — reuses db_manager getters, adds no new queries.
    """
    counts = db_manager.get_vulnerability_counts(db_path)
    total = int(counts.get("total", 0))
    fixable = int(counts.get("fixable", 0))
    ratio = (fixable / total) if total else 0.0

    logs_total = db_manager.get_total_log_count(db_path)
    high_risk = db_manager.get_high_risk_count(db_path)
    open_incidents = db_manager.get_open_incident_count(db_path)
    blocked = len(db_manager.get_blocked_ips(db_path))

    lines: List[str] = []

    def add(name: str, help_text: str, samples: List[str]) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        lines.extend(samples)

    add("localshield_up", "1 if the metrics exporter is serving.", ["localshield_up 1"])
    add("localshield_logs_total", "Total security log entries stored.", [f"localshield_logs_total {logs_total}"])
    add("localshield_high_risk_total", "High-risk log entries.", [f"localshield_high_risk_total {high_risk}"])
    add("localshield_open_incidents", "Currently open incidents.", [f"localshield_open_incidents {open_incidents}"])
    add(
        "localshield_blocked_ips",
        "IPs currently blocked by the response engine.",
        [f"localshield_blocked_ips {blocked}"],
    )
    add(
        "localshield_vulnerabilities",
        "Stored vulnerabilities by severity.",
        [f'localshield_vulnerabilities{{severity="{sev}"}} {int(counts.get(sev, 0))}' for sev in _SEVERITIES],
    )
    add(
        "localshield_vulnerabilities_total",
        "Total stored vulnerabilities.",
        [f"localshield_vulnerabilities_total {total}"],
    )
    add(
        "localshield_vulnerabilities_fixable",
        "Vulnerabilities with a fix available.",
        [f"localshield_vulnerabilities_fixable {fixable}"],
    )
    add(
        "localshield_vulnerabilities_fixable_ratio",
        "Fraction of vulnerabilities that have a fix available (0-1).",
        [f"localshield_vulnerabilities_fixable_ratio {ratio:.4f}"],
    )

    return "\n".join(lines) + "\n"


class _MetricsHandler(BaseHTTPRequestHandler):
    """Serves GET /metrics as Prometheus text; 404 for anything else."""

    def do_GET(self) -> None:  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        if self.path.split("?", 1)[0] != "/metrics":
            self.send_error(404, "Not Found")
            return
        try:
            body = render_metrics().encode("utf-8")
        except Exception as e:  # a render failure must not kill the server
            logger.error("metrics render failed: %s", e, exc_info=True)
            self.send_error(500, "metrics render error")
            return
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        # Route the default stderr access log into our logger at debug level.
        logger.debug("metrics %s - %s", self.address_string(), fmt % args)


def make_server(host: Optional[str] = None, port: Optional[int] = None) -> HTTPServer:
    """Build (but do not start) the metrics HTTP server. Port 0 picks a free port."""
    host = str(host or getattr(config, "METRICS_HOST", "127.0.0.1"))
    port = int(port if port is not None else getattr(config, "METRICS_PORT", 9109))
    return HTTPServer((host, port), _MetricsHandler)


def serve(host: Optional[str] = None, port: Optional[int] = None) -> None:
    """Serve /metrics until interrupted."""
    server = make_server(host, port)
    bound_host, bound_port = server.server_address[0], server.server_address[1]
    logger.info("LocalShield metrics exporter on http://%s:%s/metrics", bound_host, bound_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    db_manager.init_db()
    serve()
