"""
Database Manager - SQLite database management
Production-Ready: Updated with type hints and logging
"""

import logging
import sqlite3
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

import config

# Logging configuration
logger = logging.getLogger(__name__)


def init_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates SQLite database and prepares security_logs table.

    Args:
        db_path: Database file path (default: config.DB_PATH)

    Returns:
        sqlite3.Connection: Database connection
    """
    db_path = db_path or config.DB_PATH

    try:
        # Thread-safe connection: with timeout and WAL mode
        conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
        # Enable WAL (Write-Ahead Logging) mode (better performance and thread-safety)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()

        # Create security_logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                event_id TEXT,
                message TEXT,
                ai_analysis TEXT,
                risk_score TEXT,
                mitre_technique TEXT
            )
        """)

        # Add mitre_technique column to existing tables (if not exists)
        try:
            cursor.execute("ALTER TABLE security_logs ADD COLUMN mitre_technique TEXT")
            conn.commit()
            logger.debug("'mitre_technique' column added")
        except sqlite3.OperationalError:
            # Don't error if column already exists
            pass

        # Indexes speed up the dashboard's time-ordered and risk-filtered queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_risk ON security_logs(risk_score)")

        # Audit trail of automated actions (e.g. firewall blocks)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT,
                details TEXT
            )
        """)

        # Current set of IP addresses blocked by the response engine (persisted
        # so a restart knows what is already blocked). expires_at is NULL for
        # permanent blocks; timed blocks are lifted once it passes.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                rule_name TEXT,
                blocked_at DATETIME NOT NULL,
                reason TEXT,
                expires_at DATETIME
            )
        """)

        # Add expires_at to databases created before timed blocks existed
        try:
            cursor.execute("ALTER TABLE blocked_ips ADD COLUMN expires_at DATETIME")
            conn.commit()
            logger.debug("'expires_at' column added to blocked_ips")
        except sqlite3.OperationalError:
            # Don't error if column already exists
            pass

        # Incidents: related high-risk detections grouped by a key (source IP or
        # rule) within a rolling window, so the analyst sees incidents, not noise.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                title TEXT,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 1,
                max_severity TEXT,
                status TEXT NOT NULL DEFAULT 'open'
            )
        """)

        # Vulnerabilities: CVE findings from the Trivy-based vuln scanner
        # (modules/vuln_scanner.py). One row per (cve, package, target); repeated
        # scans upsert the same row so findings don't multiply over time.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                package TEXT NOT NULL,
                installed_version TEXT,
                fixed_version TEXT,
                severity TEXT,
                target TEXT NOT NULL,
                target_type TEXT,
                cvss REAL,
                title TEXT,
                scan_time DATETIME NOT NULL,
                UNIQUE(cve_id, package, target)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulnerabilities(target)")

        conn.commit()
        logger.info(f"Database '{db_path}' successfully created/connected")
        logger.debug("'security_logs' table ready")

        return conn
    except Exception as e:
        logger.error(f"Database initialization error: {e}", exc_info=True)
        raise


def insert_log(
    timestamp: datetime,
    event_id: Optional[str] = None,
    message: Optional[str] = None,
    ai_analysis: Optional[str] = None,
    risk_score: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    db_path: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> int:
    """
    Adds a new log entry to security_logs table.

    Args:
        timestamp: Record time (datetime object)
        event_id: Event ID (optional)
        message: Log message (optional)
        ai_analysis: AI analysis result (optional)
        risk_score: Risk score (optional)
        mitre_technique: MITRE ATT&CK technique (optional)
        db_path: Database file path (default: config.DB_PATH)
        conn: Existing database connection (optional, opens new connection if not provided)

    Returns:
        int: ID of the inserted record
    """
    should_close = False
    if conn is None:
        db_path = db_path or config.DB_PATH
        # Thread-safe connection: with timeout and WAL mode
        conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
        # Enable WAL (Write-Ahead Logging) mode (better performance and thread-safety)
        conn.execute("PRAGMA journal_mode=WAL")
        should_close = True

    try:
        cursor = conn.cursor()

        # Convert timestamp to string format
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute(
            """
            INSERT INTO security_logs (timestamp, event_id, message, ai_analysis, risk_score, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (timestamp_str, event_id, message, ai_analysis, risk_score, mitre_technique),
        )

        conn.commit()
        log_id: int = cursor.lastrowid or -1

        logger.debug(f"Log entry added. ID: {log_id}, Event ID: {event_id}, Risk: {risk_score}")
        return log_id

    except Exception as e:
        logger.error(f"Error adding log: {e}", exc_info=True)
        raise
    finally:
        if should_close:
            conn.close()


def get_all_logs(
    db_path: Optional[str] = None, limit: Optional[int] = None, order_by: str = "DESC"
) -> List[Tuple[int, str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]]:
    """
    Gets all log entries from security_logs table.

    Args:
        db_path: Database file path (default: config.DB_PATH)
        limit: Maximum number of records (optional)
        order_by: Sort direction ('DESC' or 'ASC', default: 'DESC')

    Returns:
        list: List of log entries (tuple list: id, timestamp, event_id, message, ai_analysis, risk_score, mitre_technique)
    """
    db_path = db_path or config.DB_PATH

    # Validate untrusted-ish inputs before interpolating them into SQL.
    # ORDER BY direction must be an exact keyword; LIMIT must be a positive int.
    direction = "DESC" if str(order_by).strip().upper() != "ASC" else "ASC"

    conn = sqlite3.connect(db_path, timeout=10.0)

    try:
        cursor = conn.cursor()

        query = f"""
            SELECT id, timestamp, event_id, message, ai_analysis, risk_score, mitre_technique
            FROM security_logs
            ORDER BY timestamp {direction}
        """

        params: Tuple = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (int(limit),)

        cursor.execute(query, params)
        results: List[Tuple[int, str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]] = (
            cursor.fetchall()
        )

        logger.debug(f"{len(results)} log entries retrieved (limit: {limit})")
        return results

    except Exception as e:
        logger.error(f"Log reading error: {e}", exc_info=True)
        return []
    finally:
        conn.close()


def get_high_risk_count(db_path: Optional[str] = None) -> int:
    """
    Returns the count of high-risk events.

    Args:
        db_path: Database file path (default: config.DB_PATH)

    Returns:
        int: Count of high-risk events
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)

    try:
        cursor = conn.cursor()

        # 'Critical' counts as high risk too; 'Yüksek' covers databases
        # written before the Turkish->English migration.
        cursor.execute("""
            SELECT COUNT(*) FROM security_logs
            WHERE risk_score IN ('Critical', 'High', 'Yüksek')
        """)
        count: int = cursor.fetchone()[0]
        return count

    except Exception as e:
        logger.error(f"Error calculating high-risk event count: {e}", exc_info=True)
        return 0
    finally:
        conn.close()


def get_total_log_count(db_path: Optional[str] = None) -> int:
    """
    Returns the total log count.

    Args:
        db_path: Database file path (default: config.DB_PATH)

    Returns:
        int: Total log count
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_logs")
        count: int = cursor.fetchone()[0]
        return count

    except Exception as e:
        logger.error(f"Error calculating total log count: {e}", exc_info=True)
        return 0
    finally:
        conn.close()


def get_latest_detection(db_path: Optional[str] = None) -> Optional[str]:
    """
    Returns the time of the latest detected event.

    Args:
        db_path: Database file path (default: config.DB_PATH)

    Returns:
        str: Latest detection time (if exists), otherwise None
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp FROM security_logs
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        result = cursor.fetchone()
        return result[0] if result else None

    except Exception as e:
        logger.error(f"Error getting latest detection time: {e}", exc_info=True)
        return None
    finally:
        conn.close()


def clear_all_logs(db_path: Optional[str] = None) -> bool:
    """
    Deletes all log entries in the database (table structure is preserved).

    Args:
        db_path: Database file path (default: config.DB_PATH)

    Returns:
        bool: True if successful, False if error occurred
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)

    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_logs")
        conn.commit()

        deleted_count = cursor.rowcount
        logger.info(f"All log entries deleted. Deleted count: {deleted_count}")
        return True

    except Exception as e:
        logger.error(f"Error deleting log entries: {e}", exc_info=True)
        conn.rollback()
        return False
    finally:
        conn.close()


def purge_old_logs(
    retention_days: Optional[int] = None,
    now: Optional[datetime] = None,
    db_path: Optional[str] = None,
) -> int:
    """
    Delete security_logs and actions rows older than the retention window so
    the database cannot grow unbounded on a long-running install.

    retention_days defaults to config.LOG_RETENTION_DAYS; a value of 0 (the
    default configuration) disables the purge and deletes nothing. Incidents
    and blocked_ips are intentionally kept — they are small, and they carry
    state (open incidents, active blocks) that must survive.

    Returns:
        int: Number of rows deleted (across both tables)
    """
    days = config.LOG_RETENTION_DAYS if retention_days is None else retention_days
    if days <= 0:
        return 0

    db_path = db_path or config.DB_PATH
    cutoff = ((now or datetime.now()) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM security_logs WHERE timestamp < ?", (cutoff,))
        deleted = cursor.rowcount
        cursor.execute("DELETE FROM actions WHERE timestamp < ?", (cutoff,))
        deleted += cursor.rowcount
        conn.commit()
        if deleted:
            logger.info(f"Retention purge: deleted {deleted} row(s) older than {days} day(s)")
        return deleted
    except Exception as e:
        logger.error(f"Error purging old logs: {e}", exc_info=True)
        return 0
    finally:
        conn.close()


def record_action(
    action_type: str,
    target: Optional[str] = None,
    details: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    db_path: Optional[str] = None,
) -> int:
    """
    Record an automated action in the audit trail (e.g. a firewall block).

    Args:
        action_type: Short action identifier (e.g. 'block_ip')
        target: Subject of the action (e.g. the IP address)
        details: Optional free-text context
        timestamp: Action time (defaults to now)
        db_path: Database file path (default: config.DB_PATH)

    Returns:
        int: ID of the inserted audit row
    """
    db_path = db_path or config.DB_PATH
    ts = (timestamp or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO actions (timestamp, action_type, target, details) VALUES (?, ?, ?, ?)",
            (ts, action_type, target, details),
        )
        conn.commit()
        return cursor.lastrowid or -1
    except Exception as e:
        logger.error(f"Error recording action: {e}", exc_info=True)
        return -1
    finally:
        conn.close()


def record_blocked_ip(
    ip: str,
    rule_name: Optional[str] = None,
    reason: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    db_path: Optional[str] = None,
) -> None:
    """
    Persist a blocked IP so a restart knows it is already blocked.
    Uses INSERT OR REPLACE so re-blocking the same IP is idempotent.
    expires_at=None means the block is permanent; otherwise the watcher lifts
    the block once the expiry time passes.
    """
    db_path = db_path or config.DB_PATH
    ts = (timestamp or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    exp = expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, rule_name, blocked_at, reason, expires_at) VALUES (?, ?, ?, ?, ?)",
            (ip, rule_name, ts, reason, exp),
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Error recording blocked IP: {e}", exc_info=True)
    finally:
        conn.close()


def get_expired_blocked_ips(now: Optional[datetime] = None, db_path: Optional[str] = None) -> List[str]:
    """
    Return IPs whose timed block has expired (expires_at is set and in the
    past). Permanent blocks (expires_at NULL) are never returned.
    """
    db_path = db_path or config.DB_PATH
    ts = (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ip FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (ts,),
        )
        return [row[0] for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error reading expired blocks: {e}", exc_info=True)
        return []
    finally:
        conn.close()


def remove_blocked_ip(ip: str, db_path: Optional[str] = None) -> None:
    """Remove an IP from the persisted block list (after a successful unblock)."""
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        conn.commit()
    except Exception as e:
        logger.error(f"Error removing blocked IP: {e}", exc_info=True)
    finally:
        conn.close()


def get_blocked_ips(db_path: Optional[str] = None) -> List[Tuple[str, Optional[str], str, Optional[str]]]:
    """Return all persisted blocked IPs as (ip, rule_name, blocked_at, reason)."""
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT ip, rule_name, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC")
        return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error reading blocked IPs: {e}", exc_info=True)
        return []
    finally:
        conn.close()


def get_recent_actions(
    limit: int = 50,
    db_path: Optional[str] = None,
) -> List[Tuple[int, str, str, Optional[str], Optional[str]]]:
    """Return recent audit actions as (id, timestamp, action_type, target, details)."""
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, action_type, target, details FROM actions ORDER BY timestamp DESC LIMIT ?",
            (int(limit),),
        )
        return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error reading actions: {e}", exc_info=True)
        return []
    finally:
        conn.close()


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def upsert_incident(
    key: str,
    title: str,
    severity: str,
    timestamp: Optional[datetime] = None,
    window_seconds: int = 1800,
    db_path: Optional[str] = None,
) -> int:
    """
    Attach a detection to an OPEN incident for `key` seen within `window_seconds`,
    or open a new incident. Groups related high-risk events instead of emitting a
    flat stream. Returns the incident id.
    """
    db_path = db_path or config.DB_PATH
    ts = timestamp or datetime.now()
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
        # Most recent open incident for this key
        cursor.execute(
            "SELECT id, last_seen, event_count, max_severity FROM incidents "
            "WHERE key = ? AND status = 'open' ORDER BY last_seen DESC LIMIT 1",
            (key,),
        )
        row = cursor.fetchone()

        fresh = False
        if row:
            inc_id, last_seen, count, max_sev = row
            try:
                last_dt = datetime.strptime(str(last_seen), "%Y-%m-%d %H:%M:%S")
                fresh = (ts - last_dt).total_seconds() <= window_seconds
            except Exception:
                fresh = False

        if row and fresh:
            new_sev = max_sev
            if _SEVERITY_RANK.get(str(severity).lower(), 0) > _SEVERITY_RANK.get(str(max_sev).lower(), 0):
                new_sev = severity
            cursor.execute(
                "UPDATE incidents SET last_seen = ?, event_count = event_count + 1, max_severity = ? WHERE id = ?",
                (ts_str, new_sev, inc_id),
            )
            conn.commit()
            return inc_id

        cursor.execute(
            "INSERT INTO incidents (key, title, first_seen, last_seen, event_count, "
            "max_severity, status) VALUES (?, ?, ?, ?, 1, ?, 'open')",
            (key, title, ts_str, ts_str, severity),
        )
        conn.commit()
        return cursor.lastrowid or -1
    except Exception as e:
        logger.error(f"Error upserting incident: {e}", exc_info=True)
        return -1
    finally:
        conn.close()


def get_incidents(
    status: Optional[str] = None,
    limit: int = 100,
    db_path: Optional[str] = None,
) -> List[Tuple[int, str, Optional[str], str, str, int, Optional[str], str]]:
    """
    Return incidents as (id, key, title, first_seen, last_seen, event_count,
    max_severity, status), newest activity first. Optionally filter by status.
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cursor = conn.cursor()
        query = "SELECT id, key, title, first_seen, last_seen, event_count, max_severity, status FROM incidents"
        params: Tuple = ()
        if status:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params = params + (int(limit),)
        cursor.execute(query, params)
        return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error reading incidents: {e}", exc_info=True)
        return []
    finally:
        conn.close()


def get_open_incident_count(db_path: Optional[str] = None) -> int:
    """Return the number of currently-open incidents."""
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        return cursor.fetchone()[0]
    except Exception as e:
        logger.error(f"Error counting incidents: {e}", exc_info=True)
        return 0
    finally:
        conn.close()


def record_vulnerability(
    cve_id: str,
    package: str,
    target: str,
    installed_version: Optional[str] = None,
    fixed_version: Optional[str] = None,
    severity: Optional[str] = None,
    target_type: Optional[str] = None,
    cvss: Optional[float] = None,
    title: Optional[str] = None,
    scan_time: Optional[datetime] = None,
    db_path: Optional[str] = None,
) -> None:
    """
    Persist (or refresh) a single CVE finding. Upserts on
    (cve_id, package, target) so re-scanning updates the existing row — the new
    installed/fixed version, severity and scan_time — instead of adding a duplicate.
    """
    db_path = db_path or config.DB_PATH
    ts = (scan_time or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vulnerabilities
                (cve_id, package, installed_version, fixed_version, severity,
                 target, target_type, cvss, title, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id, package, target) DO UPDATE SET
                installed_version = excluded.installed_version,
                fixed_version = excluded.fixed_version,
                severity = excluded.severity,
                target_type = excluded.target_type,
                cvss = excluded.cvss,
                title = excluded.title,
                scan_time = excluded.scan_time
            """,
            (cve_id, package, installed_version, fixed_version, severity, target, target_type, cvss, title, ts),
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Error recording vulnerability: {e}", exc_info=True)
    finally:
        conn.close()


_VULN_UPSERT_SQL = """
    INSERT INTO vulnerabilities
        (cve_id, package, installed_version, fixed_version, severity,
         target, target_type, cvss, title, scan_time)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(cve_id, package, target) DO UPDATE SET
        installed_version = excluded.installed_version,
        fixed_version = excluded.fixed_version,
        severity = excluded.severity,
        target_type = excluded.target_type,
        cvss = excluded.cvss,
        title = excluded.title,
        scan_time = excluded.scan_time
"""


def record_vulnerabilities(
    findings: List[dict],
    scan_time: Optional[datetime] = None,
    db_path: Optional[str] = None,
) -> int:
    """
    Batch-upsert many findings in a SINGLE connection (one commit), instead of
    one connect/commit/close per CVE. A real image scan returns hundreds of
    CVEs, so this matters. Each finding is a dict with keys cve_id, package,
    target (required) plus optional installed_version, fixed_version, severity,
    target_type, cvss, title. Returns the number of rows written.
    """
    if not findings:
        return 0
    db_path = db_path or config.DB_PATH
    ts = (scan_time or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    rows = [
        (
            f["cve_id"],
            f["package"],
            f.get("installed_version"),
            f.get("fixed_version"),
            f.get("severity"),
            f["target"],
            f.get("target_type"),
            f.get("cvss"),
            f.get("title"),
            ts,
        )
        for f in findings
    ]
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    try:
        conn.executemany(_VULN_UPSERT_SQL, rows)
        conn.commit()
        return len(rows)
    except Exception as e:
        logger.error(f"Error recording vulnerabilities (batch): {e}", exc_info=True)
        return 0
    finally:
        conn.close()


def get_vulnerabilities(
    severity: Optional[str] = None,
    target: Optional[str] = None,
    fixable_only: bool = False,
    limit: int = 1000,
    db_path: Optional[str] = None,
) -> List[
    Tuple[
        int,
        str,
        str,
        Optional[str],
        Optional[str],
        Optional[str],
        str,
        Optional[str],
        Optional[float],
        Optional[str],
        str,
    ]
]:
    """
    Return vulnerability findings, most severe first. Optionally filter by
    severity, target, and whether a fix is available. Rows are:
    (id, cve_id, package, installed_version, fixed_version, severity, target,
     target_type, cvss, title, scan_time).
    """
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cursor = conn.cursor()
        query = (
            "SELECT id, cve_id, package, installed_version, fixed_version, severity, "
            "target, target_type, cvss, title, scan_time FROM vulnerabilities"
        )
        clauses: List[str] = []
        params: List = []
        if severity:
            clauses.append("LOWER(severity) = ?")
            params.append(str(severity).lower())
        if target:
            clauses.append("target = ?")
            params.append(target)
        if fixable_only:
            clauses.append("fixed_version IS NOT NULL AND fixed_version != ''")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        # Order by severity rank (critical first), then CVSS
        query += (
            " ORDER BY CASE LOWER(severity) "
            "WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, "
            "cvss DESC LIMIT ?"
        )
        params.append(int(limit))
        cursor.execute(query, params)
        return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error reading vulnerabilities: {e}", exc_info=True)
        return []
    finally:
        conn.close()


def get_vulnerability_counts(db_path: Optional[str] = None) -> dict:
    """
    Return summary counts for the dashboard KPI row:
    {'critical', 'high', 'medium', 'low', 'unknown', 'total', 'fixable'}.
    """
    db_path = db_path or config.DB_PATH
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0, "fixable": 0}
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT LOWER(severity), COUNT(*) FROM vulnerabilities GROUP BY LOWER(severity)")
        for sev, n in cursor.fetchall():
            key = sev if sev in counts else "unknown"
            counts[key] += n
            counts["total"] += n
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE fixed_version IS NOT NULL AND fixed_version != ''")
        counts["fixable"] = cursor.fetchone()[0]
        return counts
    except Exception as e:
        logger.error(f"Error counting vulnerabilities: {e}", exc_info=True)
        return counts
    finally:
        conn.close()


def clear_vulnerabilities(db_path: Optional[str] = None) -> bool:
    """Delete all vulnerability findings (table structure is preserved)."""
    db_path = db_path or config.DB_PATH
    conn = sqlite3.connect(db_path, timeout=10.0)
    try:
        conn.execute("DELETE FROM vulnerabilities")
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error clearing vulnerabilities: {e}", exc_info=True)
        return False
    finally:
        conn.close()


# Example usage for testing
if __name__ == "__main__":
    # Logging configuration
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Initialize database
    conn = init_db(config.DB_PATH)

    # Add example log entry
    now = datetime.now()
    insert_log(
        timestamp=now,
        event_id="4625",
        message="Failed login attempt to administrator account",
        ai_analysis="Potential brute-force attack detected.",
        risk_score="High",
        conn=conn,
    )

    # Close connection
    conn.close()
    logger.info("Test completed!")
