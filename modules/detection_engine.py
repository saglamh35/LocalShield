"""
Detection Engine Module - Rule Engine
Production-Ready: YAML-based rule system and MITRE ATT&CK integration
"""
import yaml
import logging
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

# Logging yapılandırması
logger = logging.getLogger(__name__)


class DetectionRule:
    """Class representing a single detection rule"""
    
    def __init__(self, rule_data: Dict[str, Any], rule_file: str):
        """
        Creates DetectionRule.
        
        Args:
            rule_data: Rule data parsed from YAML file
            rule_file: Rule file name
        """
        # Required fields
        self.id: str = rule_data.get('id', f'rule_{rule_file}')
        self.name: str = rule_data.get('name', 'Unknown Rule')
        self.description: str = rule_data.get('description', '')
        self.enabled: bool = rule_data.get('enabled', True)
        
        # MITRE ATT&CK - can be single string or list
        mitre_data = rule_data.get('mitre', [])
        if isinstance(mitre_data, str):
            self.mitre: List[str] = [mitre_data]
        elif isinstance(mitre_data, list):
            self.mitre: List[str] = mitre_data
        else:
            self.mitre: List[str] = []
        
        # Severity: low, medium, high, critical
        self.severity: str = rule_data.get('severity', 'medium').lower()
        
        # Tags
        tags_data = rule_data.get('tags', [])
        self.tags: List[str] = tags_data if isinstance(tags_data, list) else []
        
        # Conditions
        self.conditions: Dict[str, Any] = rule_data.get('conditions', {})
        self.rule_file: str = rule_file
        
        # Extract condition values
        self.event_id: Optional[str] = self.conditions.get('event_id')
        self.provider: Optional[str] = self.conditions.get('provider')  # Security, Sysmon, etc.
        self.message_regex: Optional[str] = self.conditions.get('message_regex')
        self.command_line_regex: Optional[str] = self.conditions.get('command_line_regex')
        self.image_regex: Optional[str] = self.conditions.get('image_regex')
        self.parent_image_regex: Optional[str] = self.conditions.get('parent_image_regex')
        
        # Threshold and time window (for counting-based rules)
        self.time_window: int = self.conditions.get('time_window', 60)  # seconds
        self.threshold: int = self.conditions.get('threshold', 0)  # 0 means no threshold check
        
        # Backward compatibility: if old format has risk_level, map to severity
        if 'risk_level' in rule_data and not rule_data.get('severity'):
            old_risk = rule_data.get('risk_level', '').lower()
            if 'yüksek' in old_risk or old_risk == 'high':
                self.severity = 'high'
            elif 'orta' in old_risk or old_risk == 'medium':
                self.severity = 'medium'
            elif 'düşük' in old_risk or old_risk == 'low':
                self.severity = 'low'
        
        # Match message (for backward compatibility)
        self.match_message: str = rule_data.get('match_message', f'🔴 Detection Rule Match: {self.name}')
        
        # Filters (for backward compatibility)
        self.filters: Dict[str, Any] = rule_data.get('filters', {})
        
        # Track event history for threshold-based rules
        # Format: key -> [(timestamp, context_dict), ...]
        self.event_history: Dict[str, List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)
    
    def matches(
        self, 
        event_id: str, 
        timestamp: datetime, 
        message: str = "",
        log_source: str = "Security",
        sysmon_data: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Checks if event matches this rule.
        
        Args:
            event_id: Event ID
            timestamp: Event time
            message: Event message (optional, for filtering)
            log_source: Log source name (Security, Sysmon, etc.)
            sysmon_data: Optional dict with Sysmon fields (Image, CommandLine, ParentImage, etc.)
        
        Returns:
            bool: True if rule matches
        """
        if not self.enabled:
            return False
        
        # Provider check (if specified)
        if self.provider:
            if self.provider.lower() != log_source.lower():
                return False
        
        # Event ID check
        if self.event_id:
            if str(event_id) != str(self.event_id):
                return False
        
        # Message regex check
        if self.message_regex:
            try:
                if not re.search(self.message_regex, message, re.IGNORECASE | re.MULTILINE):
                    return False
            except re.error as e:
                logger.warning(f"Invalid regex pattern in rule {self.id}: {self.message_regex} - {e}")
                return False
        
        # Sysmon-specific checks (if sysmon_data is provided)
        if sysmon_data:
            # Image regex check
            if self.image_regex and 'Image' in sysmon_data:
                try:
                    if not re.search(self.image_regex, sysmon_data['Image'], re.IGNORECASE):
                        return False
                except re.error as e:
                    logger.warning(f"Invalid image_regex in rule {self.id}: {e}")
                    return False
            
            # Command line regex check
            if self.command_line_regex and 'CommandLine' in sysmon_data:
                try:
                    if not re.search(self.command_line_regex, sysmon_data['CommandLine'], re.IGNORECASE):
                        return False
                except re.error as e:
                    logger.warning(f"Invalid command_line_regex in rule {self.id}: {e}")
                    return False
            
            # Parent image regex check (for parent-child detection)
            if self.parent_image_regex and 'ParentImage' in sysmon_data:
                try:
                    if not re.search(self.parent_image_regex, sysmon_data['ParentImage'], re.IGNORECASE):
                        return False
                except re.error as e:
                    logger.warning(f"Invalid parent_image_regex in rule {self.id}: {e}")
                    return False
        
        # User filtering (backward compatibility)
        if self.filters:
            exclude_users = self.filters.get('exclude_users', [])
            include_users = self.filters.get('include_users', [])
            
            if exclude_users or include_users:
                user_in_message = self._extract_user_from_message(message)
                
                if exclude_users and user_in_message:
                    if user_in_message.upper() in [u.upper() for u in exclude_users]:
                        return False
                
                if include_users and user_in_message:
                    if user_in_message.upper() not in [u.upper() for u in include_users]:
                        return False
        
        # Threshold-based counting (if threshold > 0)
        if self.threshold > 0:
            # Create a unique key for this event pattern
            # For threshold counting, we need to group similar events
            event_key = self._get_event_key(event_id, message, sysmon_data)
            
            # Clear old records (older than time_window)
            cutoff_time = timestamp - timedelta(seconds=self.time_window)
            self.event_history[event_key] = [
                (ts, ctx) for ts, ctx in self.event_history[event_key]
                if ts > cutoff_time
            ]
            
            # Add new event with context
            context = {
                'message': message,
                'sysmon_data': sysmon_data or {}
            }
            self.event_history[event_key].append((timestamp, context))
            
            # Threshold check
            if len(self.event_history[event_key]) >= self.threshold:
                return True
            
            # If threshold not met, return False
            return False
        
        # If no threshold, this is a single-event match rule
        return True
    
    def _get_event_key(self, event_id: str, message: str, sysmon_data: Optional[Dict[str, str]]) -> str:
        """
        Creates a unique key for grouping similar events for threshold counting.
        
        Args:
            event_id: Event ID
            message: Event message
            sysmon_data: Optional Sysmon data
        
        Returns:
            str: Unique key for event grouping
        """
        # For brute force: group by event_id (all failed logons count together)
        # For parent-child: group by parent+child combination
        if self.parent_image_regex and sysmon_data:
            parent = sysmon_data.get('ParentImage', 'UNKNOWN')
            image = sysmon_data.get('Image', 'UNKNOWN')
            return f"{event_id}:{parent}->{image}"
        elif self.image_regex and sysmon_data:
            image = sysmon_data.get('Image', 'UNKNOWN')
            return f"{event_id}:{image}"
        else:
            # Default: group by event_id
            return str(event_id)
    
    def _extract_user_from_message(self, message: str) -> Optional[str]:
        """
        Tries to extract username from message.
        
        Args:
            message: Event message
        
        Returns:
            str: Username (if exists), otherwise None
        """
        if not message:
            return None
        
        patterns = [
            r'Account Name:\s*([^\s\n]+)',
            r'User Name:\s*([^\s\n]+)',
            r'Account Name\s+([^\s\n]+)',
            r'User\s+([^\s\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def get_result(self) -> Dict[str, Any]:
        """
        Gets result information to return when rule matches.
        
        Returns:
            dict: Rule result with all metadata
        """
        # Map severity to risk_level for backward compatibility
        severity_to_risk = {
            'critical': 'High',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low'
        }
        risk_level = severity_to_risk.get(self.severity, 'Medium')
        
        # Get first MITRE technique for backward compatibility (or join all)
        mitre_technique = self.mitre[0] if self.mitre else None
        
        return {
            'rule_id': self.id,
            'rule_name': self.name,
            'risk_level': risk_level,
            'severity': self.severity,
            'mitre_technique': mitre_technique,
            'mitre_techniques': self.mitre,  # Full list
            'tags': self.tags,
            'match_message': self.match_message,
            'description': self.description
        }


class DetectionEngine:
    """
    Engine that loads YAML-based detection rules and checks logs.
    """
    
    def __init__(self, rules_dir: str = "rules"):
        """
        Initializes DetectionEngine.
        
        Args:
            rules_dir: Directory where rule files are located
        """
        self.rules_dir = Path(rules_dir)
        self.rules: List[DetectionRule] = []
        self.load_rules()
    
    def load_rules(self) -> None:
        """Loads all YAML files in rules/ directory"""
        try:
            if not self.rules_dir.exists():
                logger.warning(f"Rule directory not found: {self.rules_dir}")
                return
            
            # Find all YAML files
            yaml_files = list(self.rules_dir.glob("*.yaml")) + list(self.rules_dir.glob("*.yml"))
            
            if not yaml_files:
                logger.warning(f"No YAML files found in rule directory: {self.rules_dir}")
                return
            
            # Load each YAML file
            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, 'r', encoding='utf-8') as f:
                        rule_data = yaml.safe_load(f)
                    
                    if rule_data:
                        # Support both single rule and list of rules
                        if isinstance(rule_data, list):
                            for rule_item in rule_data:
                                rule = DetectionRule(rule_item, yaml_file.name)
                                self.rules.append(rule)
                                logger.info(f"Rule loaded: {rule.name} (ID: {rule.id}) from {yaml_file.name}")
                        else:
                            rule = DetectionRule(rule_data, yaml_file.name)
                            self.rules.append(rule)
                            logger.info(f"Rule loaded: {rule.name} (ID: {rule.id}) from {yaml_file.name}")
                
                except Exception as e:
                    logger.error(f"Error loading rule ({yaml_file}): {e}", exc_info=True)
            
            enabled_count = sum(1 for r in self.rules if r.enabled)
            logger.info(f"Total {len(self.rules)} rules loaded ({enabled_count} enabled)")
        
        except Exception as e:
            logger.error(f"Error loading rules: {e}", exc_info=True)
    
    def check_event(
        self,
        event_id: str,
        timestamp: datetime,
        message: str = "",
        log_source: str = "Security",
        sysmon_data: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Checks an event against all rules.
        
        Args:
            event_id: Event ID
            timestamp: Event time
            message: Event message
            log_source: Log source name (Security, Sysmon, etc.)
            sysmon_data: Optional dict with Sysmon fields (Image, CommandLine, ParentImage, etc.)
        
        Returns:
            dict: If rule matches, rule result with all metadata
                 None if no match
        """
        # Check all enabled rules
        # Sort by severity: critical -> high -> medium -> low
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_rules = sorted(
            [r for r in self.rules if r.enabled],
            key=lambda r: severity_order.get(r.severity, 99)
        )
        
        for rule in sorted_rules:
            if rule.matches(event_id, timestamp, message, log_source, sysmon_data):
                logger.warning(
                    f"🔴 RULE MATCH: {rule.name} (ID: {rule.id}) - Event ID: {event_id}, "
                    f"Severity: {rule.severity}, MITRE: {', '.join(rule.mitre) if rule.mitre else 'N/A'}"
                )
                return rule.get_result()
        
        return None
    
    def check_event_all_rules(
        self,
        event_id: str,
        timestamp: datetime,
        message: str = "",
        log_source: str = "Security",
        sysmon_data: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Checks an event against all rules and returns ALL matching rules (not just first).
        Useful for getting a complete list of triggered rules.
        
        Args:
            event_id: Event ID
            timestamp: Event time
            message: Event message
            log_source: Log source name (Security, Sysmon, etc.)
            sysmon_data: Optional dict with Sysmon fields (Image, CommandLine, ParentImage, etc.)
        
        Returns:
            list: List of all matching rule results
        """
        matching_rules = []
        
        for rule in self.rules:
            if rule.enabled and rule.matches(event_id, timestamp, message, log_source, sysmon_data):
                matching_rules.append(rule.get_result())
                logger.info(
                    f"🔴 RULE MATCH: {rule.name} (ID: {rule.id}) - Event ID: {event_id}, "
                    f"Severity: {rule.severity}"
                )
        
        return matching_rules
    
    def reload_rules(self) -> None:
        """Reloads rules (hot reload)"""
        self.rules.clear()
        self.load_rules()
        logger.info("Rules reloaded")
