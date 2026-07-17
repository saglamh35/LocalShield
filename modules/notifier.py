"""
Notifier Module - offline-first alerting for high-risk events.

Design principle: the tool must remain fully functional with NO internet.
- alert-log file  : always on, cross-platform, fully offline (primary channel)
- desktop toast   : opt-in, best-effort on Windows, fully offline
- webhook         : strictly opt-in, the ONLY networked backend, non-blocking
                    and offline-safe (short timeout, failures swallowed)

Nothing here may raise into the caller: a notification failure must never
disrupt event processing.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

import config

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _rank(severity: Optional[str]) -> int:
    return _SEVERITY_RANK.get(str(severity or "").strip().lower(), 0)


class Notifier:
    """Dispatches high-risk events to the enabled, offline-first backends."""

    def __init__(
        self,
        min_severity: Optional[str] = None,
        alert_log_file: Optional[str] = None,
        desktop: Optional[bool] = None,
        webhook_url: Optional[str] = None,
    ):
        self.min_rank = _rank(min_severity or getattr(config, "NOTIFY_MIN_SEVERITY", "High"))
        self.alert_log_file: str = str(alert_log_file or getattr(config, "ALERT_LOG_FILE", "alerts.log"))
        self.desktop = getattr(config, "NOTIFY_DESKTOP", False) if desktop is None else desktop
        self.webhook_url = (webhook_url if webhook_url is not None else getattr(config, "NOTIFY_WEBHOOK_URL", "")) or ""
        # Scheme policy: https anywhere, plain http only to the local machine
        # (a local ntfy/Gotify fits the offline-first design). Anything else
        # (file://, ftp://, http to an external host) would hand alert
        # contents straight to urlopen — disable the webhook instead.
        if self.webhook_url and not self._is_allowed_webhook_url(self.webhook_url):
            logger.warning(
                f"Webhook disabled: only https:// (or http:// to localhost) URLs are allowed "
                f"(got: {self.webhook_url[:40]!r})"
            )
            self.webhook_url = ""

    @staticmethod
    def _is_allowed_webhook_url(url: str) -> bool:
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        if parsed.scheme == "https":
            return True
        if parsed.scheme == "http":
            return parsed.hostname in ("localhost", "127.0.0.1", "::1")
        return False

    def should_notify(self, severity: str) -> bool:
        return _rank(severity) >= self.min_rank

    def notify(
        self,
        severity: str,
        title: str,
        detail: str = "",
        event_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> None:
        """
        Send a notification for an event, if it meets the severity threshold.
        Never raises — each backend failure is isolated and logged.
        """
        if not self.should_notify(severity):
            return

        payload: Dict[str, Any] = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "severity": severity,
            "title": title,
            "detail": detail,
            "event_id": event_id,
            "source_ip": source_ip,
        }

        # 1) alert-log (offline, always on)
        try:
            self._write_alert_log(payload)
        except Exception as e:  # pragma: no cover - filesystem edge cases
            logger.debug(f"alert-log notification failed: {e}")

        # 2) desktop toast (offline, opt-in)
        if self.desktop:
            try:
                self._desktop_toast(title, detail or severity)
            except Exception as e:
                logger.debug(f"desktop notification failed: {e}")

        # 3) webhook (opt-in, only networked backend, offline-safe)
        if self.webhook_url:
            self._post_webhook(payload)

    def _write_alert_log(self, payload: Dict[str, Any]) -> None:
        line = (
            f"[{payload['time']}] {payload['severity'].upper()} "
            f"{payload['title']}"
            + (f" (Event {payload['event_id']})" if payload.get("event_id") else "")
            + (f" src={payload['source_ip']}" if payload.get("source_ip") else "")
            + (f" — {payload['detail']}" if payload.get("detail") else "")
        )
        with open(self.alert_log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _desktop_toast(self, title: str, message: str) -> None:  # pragma: no cover - Windows-only
        # Best-effort, guarded import; a no-op where the library is unavailable.
        try:
            from win10toast import ToastNotifier
        except Exception:
            return
        ToastNotifier().show_toast(f"LocalShield: {title}", message, duration=5, threaded=True)

    def _post_webhook(self, payload: Dict[str, Any]) -> None:
        """
        POST the payload as JSON. Offline-safe: short timeout, single attempt,
        all failures swallowed so a missing network never blocks processing.
        """
        import urllib.request

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3)  # noqa: S310  # nosec B310
        except Exception as e:
            logger.debug(f"webhook notification failed (ignored, offline-safe): {e}")


# Module-level default instance for convenience
_default_notifier: Optional[Notifier] = None


def get_notifier() -> Notifier:
    global _default_notifier
    if _default_notifier is None:
        _default_notifier = Notifier()
    return _default_notifier
