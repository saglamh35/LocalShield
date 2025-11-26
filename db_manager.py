"""
Database Manager - SQLite database management
Production-Ready: Updated with type hints and logging
"""
import sqlite3
import logging
from datetime import datetime
from typing import Optional, List, Tuple
from pathlib import Path

import config

# Logging yapılandırması
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
        conn.execute('PRAGMA journal_mode=WAL')
        cursor = conn.cursor()
        
        # Create security_logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                event_id TEXT,
                message TEXT,
                ai_analysis TEXT,
                risk_score TEXT,
                mitre_technique TEXT
            )
        ''')
        
        # Add mitre_technique column to existing tables (if not exists)
        try:
            cursor.execute('ALTER TABLE security_logs ADD COLUMN mitre_technique TEXT')
            conn.commit()
            logger.debug("'mitre_technique' column added")
        except sqlite3.OperationalError:
            # Don't error if column already exists
            pass
        
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
    conn: Optional[sqlite3.Connection] = None
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
        conn.execute('PRAGMA journal_mode=WAL')
        should_close = True
    
    try:
        cursor = conn.cursor()
        
        # Convert timestamp to string format
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO security_logs (timestamp, event_id, message, ai_analysis, risk_score, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp_str, event_id, message, ai_analysis, risk_score, mitre_technique))
        
        conn.commit()
        log_id: int = cursor.lastrowid
        
        logger.debug(f"Log entry added. ID: {log_id}, Event ID: {event_id}, Risk: {risk_score}")
        return log_id
        
    except Exception as e:
        logger.error(f"Error adding log: {e}", exc_info=True)
        raise
    finally:
        if should_close:
            conn.close()


def get_all_logs(
    db_path: Optional[str] = None,
    limit: Optional[int] = None,
    order_by: str = 'DESC'
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
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        
        query = f'''
            SELECT id, timestamp, event_id, message, ai_analysis, risk_score, mitre_technique
            FROM security_logs
            ORDER BY timestamp {order_by}
        '''
        
        if limit:
            query += f' LIMIT {limit}'
        
        cursor.execute(query)
        results: List[Tuple[int, str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]] = cursor.fetchall()
        
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
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM security_logs
            WHERE risk_score = 'Yüksek' OR risk_score = 'High'
        ''')
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
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM security_logs')
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
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp FROM security_logs
            ORDER BY timestamp DESC
            LIMIT 1
        ''')
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
    conn = sqlite3.connect(db_path)
    
    try:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM security_logs')
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


# Example usage for testing
if __name__ == "__main__":
    # Logging configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
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
        conn=conn
    )
    
    # Close connection
    conn.close()
    logger.info("Test completed!")
