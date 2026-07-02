"""
Log Watcher - Service that continuously monitors Windows Security Event Logs.
Production-Ready: asynchronous structure with logging.
"""
import asyncio
import sys
import logging
from datetime import datetime, timedelta
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
import re
from db_manager import init_db, insert_log
from modules.ai_engine import Brain
from modules.detection_engine import DetectionEngine
from modules.response_engine import FirewallManager
from modules.threat_intel import ThreatIntel

# Logging configuration
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
        self.detection_engine = DetectionEngine()  # Rule engine
        self.firewall_manager = FirewallManager()  # Active response engine
        self.threat_intel = ThreatIntel()  # Threat intelligence engine
        self.db_conn = init_db(config.DB_PATH)
        # Dictionary to hold multiple log handles: {log_name: handle}
        self.log_handles: dict[str, Optional[Any]] = {}
        self.last_check_time = datetime.now()
        self.check_interval: int = config.CHECK_INTERVAL
        self.executor = ThreadPoolExecutor(max_workers=3)  # Thread pool for blocking operations
        self.running: bool = False
    
    def open_event_log(self) -> None:
        """Opens Windows Event Logs for both Security and Sysmon (synchronous operation)"""
        # Always try to open Security log
        try:
            security_handle = win32evtlog.OpenEventLog(
                None,  # Local machine
                config.EVENT_LOG_NAME
            )
            self.log_handles[config.EVENT_LOG_NAME] = security_handle
            logger.info(f"✅ Successfully opened '{config.EVENT_LOG_NAME}' log")
        except Exception as e:
            logger.error(f"❌ Could not open Security Event Log: {e}")
            logger.warning("💡 Make sure you're running with administrator privileges.")
            raise
        
        # Try to open Sysmon log (optional - may not be installed)
        try:
            sysmon_handle = win32evtlog.OpenEventLog(
                None,  # Local machine
                config.SYSMON_LOG_NAME
            )
            self.log_handles[config.SYSMON_LOG_NAME] = sysmon_handle
            logger.info(f"✅ Successfully opened '{config.SYSMON_LOG_NAME}' log")
        except Exception as e:
            logger.warning(f"⚠️  Sysmon log not found: {config.SYSMON_LOG_NAME}")
            logger.warning("   Sysmon is not installed or not available. Only Security logs will be monitored.")
            # Don't raise - continue with Security log only
    
    def close_event_log(self) -> None:
        """Closes all Windows Event Log handles"""
        for log_name, handle in self.log_handles.items():
            if handle:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception as e:
                    logger.warning(f"Error closing {log_name} log: {e}")
        self.log_handles.clear()
    
    def get_event_message(self, event: Any, log_name: str = None) -> str:
        """
        Gets readable message text from event
        
        Args:
            event: win32evtlog event object
            log_name: Name of the log channel (for proper message formatting)
        
        Returns:
            str: Event message
        """
        # Use provided log_name or default to Security
        log_channel = log_name or config.EVENT_LOG_NAME
        
        try:
            message = win32evtlogutil.SafeFormatMessage(event, log_channel)
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
    
    def parse_sysmon_event_1(self, event: Any) -> dict:
        """
        Parses Sysmon Event ID 1 (Process Creation) and extracts critical fields
        
        Args:
            event: win32evtlog event object
        
        Returns:
            dict: Parsed fields (Image, CommandLine, User, ParentImage)
        """
        parsed_data = {
            'Image': 'N/A',
            'CommandLine': 'N/A',
            'User': 'N/A',
            'ParentImage': 'N/A'
        }
        
        try:
            # Sysmon Event ID 1 uses XML data in StringInserts
            # Format: EventData contains Image, CommandLine, User, ParentImage, etc.
            if event.StringInserts:
                # StringInserts typically contains: [Image, CommandLine, User, LogonGuid, ProcessGuid, ParentImage, ...]
                inserts = [str(insert) for insert in event.StringInserts if insert]
                
                # Typical order for Event ID 1:
                # [0] RuleName, [1] UtcTime, [2] ProcessGuid, [3] ProcessId, [4] Image, 
                # [5] FileVersion, [6] Description, [7] Product, [8] Company, [9] OriginalFileName,
                # [10] CommandLine, [11] CurrentDirectory, [12] User, [13] LogonGuid, 
                # [14] LogonId, [15] TerminalSessionId, [16] IntegrityLevel, [17] Hashes,
                # [18] ParentProcessGuid, [19] ParentImage, [20] ParentCommandLine, ...
                
                # Try to find fields by position (may vary by Sysmon version)
                if len(inserts) > 4:
                    parsed_data['Image'] = inserts[4] if len(inserts) > 4 else 'N/A'
                if len(inserts) > 10:
                    parsed_data['CommandLine'] = inserts[10] if len(inserts) > 10 else 'N/A'
                if len(inserts) > 12:
                    parsed_data['User'] = inserts[12] if len(inserts) > 12 else 'N/A'
                if len(inserts) > 19:
                    parsed_data['ParentImage'] = inserts[19] if len(inserts) > 19 else 'N/A'
                
                # Alternative: Try to parse from XML if available
                # Some Sysmon versions provide XML data
                if hasattr(event, 'XML') and event.XML:
                    import xml.etree.ElementTree as ET
                    try:
                        root = ET.fromstring(event.XML)
                        event_data = root.find('.//EventData')
                        if event_data is not None:
                            for data in event_data.findall('Data'):
                                name = data.get('Name', '')
                                value = data.text or ''
                                if name == 'Image':
                                    parsed_data['Image'] = value
                                elif name == 'CommandLine':
                                    parsed_data['CommandLine'] = value
                                elif name == 'User':
                                    parsed_data['User'] = value
                                elif name == 'ParentImage':
                                    parsed_data['ParentImage'] = value
                    except Exception:
                        pass  # Fall back to StringInserts method
        except Exception as e:
            logger.warning(f"Error parsing Sysmon Event ID 1: {e}")
        
        return parsed_data
    
    def parse_sysmon_event_5(self, event: Any) -> dict:
        """
        Parses Sysmon Event ID 5 (Process Terminated) and extracts critical fields
        
        Args:
            event: win32evtlog event object
        
        Returns:
            dict: Parsed fields (Image, ProcessId)
        """
        parsed_data = {
            'Image': 'N/A',
            'ProcessId': 'N/A'
        }
        
        try:
            # Sysmon Event ID 5 uses StringInserts
            # Format: EventData contains Image, ProcessId, etc.
            if event.StringInserts:
                # StringInserts typically contains: [RuleName, UtcTime, ProcessGuid, ProcessId, Image, ...]
                inserts = [str(insert) for insert in event.StringInserts if insert]
                
                # Typical order for Event ID 5:
                # [0] RuleName, [1] UtcTime, [2] ProcessGuid, [3] ProcessId, [4] Image
                
                # Try to find fields by position (may vary by Sysmon version)
                if len(inserts) > 3:
                    parsed_data['ProcessId'] = inserts[3] if len(inserts) > 3 else 'N/A'
                if len(inserts) > 4:
                    parsed_data['Image'] = inserts[4] if len(inserts) > 4 else 'N/A'
                
                # Alternative: Try to parse from XML if available
                if hasattr(event, 'XML') and event.XML:
                    import xml.etree.ElementTree as ET
                    try:
                        root = ET.fromstring(event.XML)
                        event_data = root.find('.//EventData')
                        if event_data is not None:
                            for data in event_data.findall('Data'):
                                name = data.get('Name', '')
                                value = data.text or ''
                                if name == 'Image':
                                    parsed_data['Image'] = value
                                elif name == 'ProcessId':
                                    parsed_data['ProcessId'] = value
                    except Exception:
                        pass  # Fall back to StringInserts method
        except Exception as e:
            logger.warning(f"Error parsing Sysmon Event ID 5: {e}")
        
        return parsed_data
    
    async def process_event_async(self, event: Any, log_source: str = "Security") -> None:
        """
        Processes a single event asynchronously: sends to AI, saves to database
        
        Args:
            event: win32evtlog event object
            log_source: Source log channel name (Security or Sysmon)
        """
        try:
            # Get event details
            event_id = str(event.EventID)
            event_time = event.TimeGenerated

            # Get log channel name for message formatting
            log_channel = config.SYSMON_LOG_NAME if log_source == "Sysmon" else config.EVENT_LOG_NAME
            message = self.get_event_message(event, log_channel)

            # Special parsing for Sysmon Event ID 1 (Process Creation) and Event ID 5 (Process Terminated)
            sysmon_details = ""
            sysmon_data = None  # For detection engine
            if log_source == "Sysmon" and event_id == "1":
                parsed = self.parse_sysmon_event_1(event)
                sysmon_data = {
                    'Image': parsed['Image'],
                    'CommandLine': parsed['CommandLine'],
                    'User': parsed['User'],
                    'ParentImage': parsed['ParentImage']
                }
                sysmon_details = f"""
Sysmon Process Creation Details:
  Image: {parsed['Image']}
  CommandLine: {parsed['CommandLine']}
  User: {parsed['User']}
  ParentImage: {parsed['ParentImage']}
"""
            elif log_source == "Sysmon" and event_id == "5":
                parsed = self.parse_sysmon_event_5(event)
                sysmon_data = {
                    'Image': parsed['Image'],
                    'ProcessId': parsed['ProcessId']
                }
                sysmon_details = f"""
Sysmon Process Terminated Details:
  Image: {parsed['Image']}
  ProcessId: {parsed['ProcessId']}
"""
            
            # Get additional info from StringInserts
            additional_info = ""
            if event.StringInserts:
                inserts_str = " | ".join([str(insert) for insert in event.StringInserts if insert])
                if inserts_str:
                    additional_info = f"\nAdditional Details (StringInserts): {inserts_str}"
            
            # Combine event in rich format
                log_text = f"""Log Source: {log_source}
Event ID: {event_id}
Time: {event_time}
Message: {message}{sysmon_details}{additional_info}

Note: Pay special attention to fields like 'Account Name', 'Workstation Name', 'Source Network Address', 'Logon Type' in the message."""
            
            # THREAT INTELLIGENCE CHECK: extract IPs from the log text and check them against the malicious list.
            # These IPs are reused later for the active-response step (extracted only once).
            threat_intel_match = None
            combined_text = f"{message}{sysmon_details}{additional_info}"
            found_ips = self.firewall_manager.extract_ips_from_text(combined_text)

            for ip in found_ips:
                # Private IP check - only inspect public IPs
                if not self.firewall_manager.is_private_ip(ip):
                    threat_result = self.threat_intel.check_ip(ip)
                    if threat_result:
                        threat_intel_match = threat_result
                        # Stop at the first malicious IP found
                        break

            # If there is a Threat Intelligence match, force the risk level to "High"
            threat_intel_header = ""
            if threat_intel_match:
                threat_intel_header = f"🚨 [THREAT INTEL MATCH] IP {threat_intel_match['ip']} found on the malicious list! Category: {threat_intel_match['category']}, Confidence: {threat_intel_match['confidence']}%\n\n"
                logger.warning(f"🚨 THREAT INTEL: {threat_intel_match['ip']} on malicious list - risk level automatically set to 'High'")
            
            # FIRST: Detection Engine check (Fast and Precise)
            logger.info(f"Checking Event ID {event_id} in detection engine...")
            loop = asyncio.get_event_loop()
            detection_result = await loop.run_in_executor(
                self.executor,
                self.detection_engine.check_event,
                event_id,
                event_time,
                message,
                log_source,  # Add log_source parameter
                sysmon_data  # Add sysmon_data parameter
            )
            
            # Rule engine result
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
            
            # Risk level decision logic (priority order):
            # 1. Threat Intelligence (highest priority - malicious IP forces High)
            # 2. Detection Engine (rule match)
            # 3. AI Analysis (default)

            final_risk_level = ai_risk_level
            final_analysis = analysis

            # THREAT INTELLIGENCE OVERRIDE: if a malicious IP is present, force risk level to "High"
            if threat_intel_match:
                final_risk_level = "High"
                # Prepend the threat intel note to the analysis text
                final_analysis = threat_intel_header + analysis
                logger.warning(f"🚨 Threat Intelligence overrode risk level: {ai_risk_level} -> High")

            # Detection Engine override logic: if the engine says "High", override the AI's risk score
            elif rule_risk_level:
                # Add Detection Engine result to AI analysis
                if rule_match_message:
                    final_analysis = f"{rule_match_message}\n\n---\n\n{analysis}"

                # If Detection Engine says "High", override AI's risk score
                if rule_risk_level == "High":
                    final_risk_level = "High"
                    logger.warning(f"⚠️ Detection Engine overrode risk score: {ai_risk_level} -> {final_risk_level}")
                else:
                    # If Detection Engine is not "High", keep the AI's score but still show the rule result
                    final_risk_level = ai_risk_level

            # ACTIVE RESPONSE: block IPs on high-risk events.
            # Reuse the IPs already extracted above instead of scanning the text again.
            action_taken = ""
            if final_risk_level == "High":
                blocked_ips = []
                for ip in found_ips:
                    # Private IP check (also enforced inside FirewallManager, kept here as a guard)
                    if not self.firewall_manager.is_private_ip(ip):
                        # Block the IP (run in the thread pool - blocking operation)
                        success = await loop.run_in_executor(
                            self.executor,
                            self.firewall_manager.block_ip,
                            ip
                        )
                        if success:
                            blocked_ips.append(ip)

                # If any IP was blocked, prepend a note to the analysis text
                if blocked_ips:
                    blocked_ips_str = ", ".join(blocked_ips)
                    action_taken = f"🛡️ [ACTION TAKEN]: Blocked IP address(es): {blocked_ips_str}\n\n"
                    logger.warning(f"🛡️ ACTIVE RESPONSE: blocked {len(blocked_ips)} IP address(es): {blocked_ips_str}")

            # Prepend the "action taken" message to the analysis text
            if action_taken:
                final_analysis = action_taken + final_analysis
            
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
                    conn=None  # Each thread opens its own connection
                )
            )
            
            logger.info(f"Log processed: Event ID {event_id} - Risk: {final_risk_level} - MITRE: {mitre_technique or 'N/A'}")
            
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
    
    async def check_new_events_async(self) -> None:
        """Checks and processes new events asynchronously from all log channels"""
        try:
            # Run event log reading in thread pool (blocking operation)
            loop = asyncio.get_event_loop()
            all_events = await loop.run_in_executor(
                self.executor,
                self._read_events_sync
            )
            
            if all_events:
                # Process new events asynchronously
                # all_events is a list of tuples: (event, log_source)
                tasks = []
                for event, log_source in all_events:
                    task = self.process_event_async(event, log_source)
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
    
    def _read_events_sync(self) -> List[tuple]:
        """
        Reads events synchronously from all log channels (to be run in thread pool)
        
        Returns:
            list: List of tuples (event, log_source) for new events
        """
        all_new_events = []
        
        try:
            # Close and reopen all logs each time (to see new logs)
            self.close_event_log()
            self.open_event_log()
            
            # Read from each log channel
            for log_name, log_handle in self.log_handles.items():
                if not log_handle:
                    continue
                
                try:
                    # Determine log source name for processing
                    if log_name == config.SYSMON_LOG_NAME:
                        log_source = "Sysmon"
                    else:
                        log_source = "Security"
                    
                    # Read events after last check time
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    
                    events = win32evtlog.ReadEventLog(
                        log_handle,
                        flags,
                        0,
                        1000  # Read maximum 1000 events per channel
                    )
                    
                    if events:
                        # Filter events by timestamp with 5 second buffer to catch events that might have been missed
                        # due to millisecond-level timing differences
                        time_threshold = self.last_check_time - timedelta(seconds=5)
                        for event in events:
                            event_time = event.TimeGenerated
                            if event_time > time_threshold:
                                all_new_events.append((event, log_source))
                
                except Exception as e:
                    error_code = getattr(e, 'winerror', None)
                    error_msg = str(e).lower()
                    
                    # Silently skip normal errors for this channel
                    if error_code == 122 or error_code == 1223:
                        continue
                    elif "no more data" in error_msg or "no more events" in error_msg:
                        continue
                    else:
                        logger.warning(f"Error reading from {log_name}: {e}")
            
            # Sort all new events by time (across all channels)
            all_new_events.sort(key=lambda e: e[0].TimeGenerated)
            return all_new_events
            
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
