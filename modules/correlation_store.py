"""
Correlation-state persistence.

Correlation rules (e.g. "successful logon after >= 5 failures from the same
source") accumulate prior events over a window of minutes. Keeping that state
only in memory means a watcher restart forgets an attack already in progress —
the first failures of an ongoing brute force would be lost. This store mirrors
each rule's prior events into the `correlation_state` table so the engine can
re-seed itself on startup.

Scope: only correlation-rule priors are persisted. Threshold-rule history is
deliberately memory-only — its windows are short (~60s, less than one restart)
and its entries carry heavy per-event context that would bloat the table.

Every method is best-effort: persistence trouble is logged and swallowed,
because state mirroring must never break live event processing. Only the
watcher process writes this table, so it adds no dashboard write contention.
"""

import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

import config

logger = logging.getLogger(__name__)

# ISO format used for the ts column (matches datetime.fromisoformat round-trip)
_TS_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


class CorrelationStore:
    """Persists correlation-rule prior events in SQLite."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path: str = db_path or config.DB_PATH

    def _connect(self) -> sqlite3.Connection:
        # Short-lived connections with the same settings as db_manager: WAL is
        # already set on the file by init_db; the timeout rides out the single
        # writer's bursts.
        return sqlite3.connect(self.db_path, timeout=10.0)

    def record_prior(self, rule_id: str, event_key: str, ts: datetime) -> None:
        """Mirrors one prior event (e.g. one failed logon) to disk."""
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO correlation_state (rule_id, event_key, ts) VALUES (?, ?, ?)",
                    (rule_id, event_key, ts.strftime(_TS_FORMAT)),
                )
        except Exception as e:
            logger.debug(f"correlation_store.record_prior failed (ignored): {e}")

    def clear_key(self, rule_id: str, event_key: str) -> None:
        """Consume-on-fire: drops a source's priors once the rule has fired."""
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM correlation_state WHERE rule_id = ? AND event_key = ?",
                    (rule_id, event_key),
                )
        except Exception as e:
            logger.debug(f"correlation_store.clear_key failed (ignored): {e}")

    def load_priors(self, rule_id: str, cutoff: datetime) -> Dict[str, List[datetime]]:
        """
        Returns a rule's surviving priors, keyed by event key (source IP),
        newer than `cutoff`. Used to re-seed the in-memory history on startup.
        """
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT event_key, ts FROM correlation_state WHERE rule_id = ? AND ts > ? ORDER BY ts",
                    (rule_id, cutoff.strftime(_TS_FORMAT)),
                ).fetchall()
        except Exception as e:
            logger.debug(f"correlation_store.load_priors failed (ignored): {e}")
            return {}

        priors: Dict[str, List[datetime]] = {}
        for event_key, ts_text in rows:
            try:
                ts = datetime.strptime(ts_text, _TS_FORMAT)
            except (ValueError, TypeError):
                continue
            priors.setdefault(str(event_key), []).append(ts)
        return priors

    def prune(self, cutoff: datetime) -> int:
        """Deletes priors older than `cutoff` (all rules). Returns rows removed."""
        try:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM correlation_state WHERE ts <= ?",
                    (cutoff.strftime(_TS_FORMAT),),
                )
                return int(cur.rowcount)
        except Exception as e:
            logger.debug(f"correlation_store.prune failed (ignored): {e}")
            return 0
