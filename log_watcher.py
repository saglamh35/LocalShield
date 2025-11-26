"""
Log Watcher - Windows Security Event Log'larını sürekli dinleyen servis
Production-Ready: Asenkron yapı ve logging ile güncellendi
"""
import asyncio
import sys
import logging
from datetime import datetime
from typing import Optional, List, Any
from concurrent.futures import ThreadPoolExecutor

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
except ImportError:
    print("ERROR: pywin32 library is not installed. Install it with 'pip install pywin32' command.")
    sys.exit(1)

import config
from db_manager import init_db, insert_log
from modules.ai_engine import Brain
from modules.detection_engine import DetectionEngine

# Logging yapılandırması
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class LogWatcher:
    """
    Class that asynchronously monitors Windows Security Event Logs and analyzes them with AI
    Production-Ready: Non-blocking structure using AsyncIO
    """
    
    def __init__(self) -> None:
        """Initializes LogWatcher"""
        self.brain = Brain()
        self.detection_engine = DetectionEngine()  # Kural Motoru
        self.db_conn = init_db(config.DB_PATH)
        self.log_handle: Optional[Any] = None
        self.last_check_time = datetime.now()
        self.check_interval: int = config.CHECK_INTERVAL
        self.executor = ThreadPoolExecutor(max_workers=3)  # Thread pool for blocking operations
        self.running: bool = False
    
    def open_event_log(self) -> None:
        """Opens Windows Event Log (synchronous operation)"""
        try:
            self.log_handle = win32evtlog.OpenEventLog(
                None,  # Local machine
                config.EVENT_LOG_NAME
            )
            logger.info(f"Successfully opened '{config.EVENT_LOG_NAME}' log")
            
        except Exception as e:
            logger.error(f"Could not open Event Log: {e}")
            logger.warning("💡 Make sure you're running with administrator privileges.")
            raise
    
    def close_event_log(self) -> None:
        """Closes Windows Event Log"""
        if self.log_handle:
            try:
                win32evtlog.CloseEventLog(self.log_handle)
                self.log_handle = None
            except Exception as e:
                logger.warning(f"Error closing log: {e}")
    
    def get_event_message(self, event: Any) -> str:
        """
        Gets readable message text from event
        
        Args:
            event: win32evtlog event object
        
        Returns:
            str: Event message
        """
        try:
            message = win32evtlogutil.SafeFormatMessage(event, config.EVENT_LOG_NAME)
            if not message or message.strip() == "":
                if event.StringInserts:
                    message = " | ".join(str(insert) for insert in event.StringInserts)
                else:
                    message = "Message could not be retrieved"
            return message
        except Exception as e:
            if event.StringInserts:
                return " | ".join(str(insert) for insert in event.StringInserts)
            return f"Event ID {event.EventID} (Message could not be parsed: {e})"
    
    async def process_event_async(self, event: Any) -> None:
        """
        Processes a single event asynchronously: sends to AI, saves to database
        
        Args:
            event: win32evtlog event object
        """
        try:
            # Event bilgilerini al
            event_id = str(event.EventID)
            event_time = event.TimeGenerated
            message = self.get_event_message(event)
            
            # Get additional info from StringInserts
            additional_info = ""
            if event.StringInserts:
                inserts_str = " | ".join([str(insert) for insert in event.StringInserts if insert])
                if inserts_str:
                    additional_info = f"\nAdditional Details (StringInserts): {inserts_str}"
            
            # Combine event in rich format
            log_text = f"""Event ID: {event_id}
Time: {event_time}
Message: {message}{additional_info}

Note: Pay special attention to fields like 'Account Name', 'Workstation Name', 'Source Network Address', 'Logon Type' in the message."""
            
            # FIRST: Detection Engine check (Fast and Precise)
            logger.info(f"Checking Event ID {event_id} in detection engine...")
            loop = asyncio.get_event_loop()
            detection_result = await loop.run_in_executor(
                self.executor,
                self.detection_engine.check_event,
                event_id,
                event_time,
                message
            )
            
            # Kural Motoru sonucu
            rule_risk_level: Optional[str] = None
            mitre_technique: Optional[str] = None
            rule_match_message: Optional[str] = None
            
            if detection_result:
                rule_risk_level = detection_result.get('risk_level')
                mitre_technique = detection_result.get('mitre_technique')
                rule_match_message = detection_result.get('match_message')
                logger.warning(f"🔴 RULE MATCH: {detection_result.get('rule_name')} - Risk: {rule_risk_level}, MITRE: {mitre_technique}")
            
            # THEN: Run AI analysis in thread pool (blocking operation)
            logger.info(f"Analyzing Event ID {event_id} with AI...")
            analysis, ai_risk_level = await loop.run_in_executor(
                self.executor,
                self.brain.analyze,
                log_text
            )
            
            # Detection Engine override logic: If Detection Engine says "High Risk", override AI's risk score
            final_risk_level = ai_risk_level
            final_analysis = analysis
            
            if rule_risk_level:
                # Add Detection Engine result to AI analysis
                if rule_match_message:
                    final_analysis = f"{rule_match_message}\n\n---\n\n{analysis}"
                
                # If Detection Engine says "High Risk", override AI's risk score
                if rule_risk_level == "Yüksek" or rule_risk_level == "High":
                    final_risk_level = "High"
                    logger.warning(f"⚠️ Detection Engine overrode risk score: {ai_risk_level} -> {final_risk_level}")
                else:
                    # If Detection Engine is not "High", use AI's score but also show rule result
                    final_risk_level = ai_risk_level
            
            # Save to database (run in thread pool)
            # FIX: Set conn=None so each thread opens its own connection
            # SQLite is not thread-safe, so each thread should use its own connection
            await loop.run_in_executor(
                self.executor,
                lambda: insert_log(
                    timestamp=event_time,
                    event_id=event_id,
                    message=message[:500],
                    ai_analysis=final_analysis,
                    risk_score=final_risk_level,
                    mitre_technique=mitre_technique,
                    conn=None  # Her thread kendi connection'ını açacak
                )
            )
            
            logger.info(f"Log processed: Event ID {event_id} - Risk: {final_risk_level} - MITRE: {mitre_technique or 'N/A'}")
            
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
    
    async def check_new_events_async(self) -> None:
        """Checks and processes new events asynchronously"""
        try:
            # Run event log reading in thread pool (blocking operation)
            loop = asyncio.get_event_loop()
            events = await loop.run_in_executor(
                self.executor,
                self._read_events_sync
            )
            
            if events:
                # Process new events asynchronously
                tasks = []
                for event in events:
                    task = self.process_event_async(event)
                    tasks.append(task)
                
                # Process all events in parallel
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
            
            # Update last check time
            self.last_check_time = datetime.now()
                    
        except Exception as e:
            error_code = getattr(e, 'winerror', None)
            error_msg = str(e).lower()
            
            # Skip normal errors without logging
            if error_code == 122 or error_code == 1223:
                pass
            elif "no more data" in error_msg or "no more events" in error_msg or "no records" in error_msg:
                pass
            else:
                logger.warning(f"Log reading error: {e}")
                # Try to reinitialize log
                try:
                    self.close_event_log()
                    await asyncio.sleep(1)
                except Exception:
                    pass
    
    def _read_events_sync(self) -> List[Any]:
        """
        Reads events synchronously (to be run in thread pool)
        
        Returns:
            list: List of new events
        """
        try:
            # Close and reopen log each time (to see new logs)
            self.close_event_log()
            self.open_event_log()
            
            if not self.log_handle:
                return []
            
            # Read events after last check time
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(
                self.log_handle,
                flags,
                0,
                100  # Read maximum 100 events
            )
            
            if events:
                new_events = []
                current_time = datetime.now()
                
                # Filter events by timestamp
                for event in events:
                    event_time = event.TimeGenerated
                    if event_time > self.last_check_time:
                        new_events.append(event)
                
                # Sort new events by time
                new_events.sort(key=lambda e: e.TimeGenerated)
                return new_events
            
            return []
            
        except Exception as e:
            error_code = getattr(e, 'winerror', None)
            error_msg = str(e).lower()
            
            # Silently skip normal errors
            if error_code == 122 or error_code == 1223:
                return []
            elif "no more data" in error_msg or "no more events" in error_msg:
                return []
            
            logger.warning(f"Event reading error: {e}")
            return []
    
    async def run_async(self) -> None:
        """Monitors logs asynchronously"""
        logger.info("🛡️  LocalShield Log Watcher starting...")
        logger.info("=" * 60)
        
        try:
            # Open Event Log (synchronous operation, run in thread pool)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self.executor, self.open_event_log)
            
            logger.info(f"⏰ Checking for new logs every {self.check_interval} seconds...")
            logger.info("💡 Press Ctrl+C to exit.")
            logger.info("=" * 60)
            
            self.running = True
            
            # Async loop
            while self.running:
                try:
                    await self.check_new_events_async()
                    await asyncio.sleep(self.check_interval)
                except KeyboardInterrupt:
                    logger.info("\n\n⚠️  Stopped by user.")
                    self.running = False
                    break
                except Exception as e:
                    logger.error(f"Unexpected error: {e}", exc_info=True)
                    await asyncio.sleep(1)  # Short wait on error
                    
        except Exception as e:
            logger.error(f"Critical error: {e}", exc_info=True)
        finally:
            # Cleanup
            self.close_event_log()
            if self.db_conn:
                self.db_conn.close()
            self.executor.shutdown(wait=True)
            logger.info("\n🛡️  LocalShield Log Watcher stopped.")
    
    def run(self) -> None:
        """
        Synchronous wrapper - runs async run_async
        For backward compatibility
        """
        try:
            asyncio.run(self.run_async())
        except KeyboardInterrupt:
            logger.info("Log Watcher stopped.")


if __name__ == "__main__":
    watcher = LogWatcher()
    watcher.run()
