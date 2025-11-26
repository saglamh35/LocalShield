"""
Detection Engine Module - Rule Engine
Production-Ready: YAML-based rule system and MITRE ATT&CK integration
"""
import yaml
import logging
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
        self.name: str = rule_data.get('name', 'Unknown Rule')
        self.description: str = rule_data.get('description', '')
        self.enabled: bool = rule_data.get('enabled', True)
        self.priority: str = rule_data.get('priority', 'medium')
        self.conditions: Dict[str, Any] = rule_data.get('conditions', {})
        self.risk_level: str = rule_data.get('risk_level', 'Medium')
        self.mitre_technique: Optional[str] = rule_data.get('mitre_technique')
        self.match_message: str = rule_data.get('match_message', f'Detection Rule Match: {self.name}')
        self.filters: Dict[str, Any] = rule_data.get('filters', {})
        self.rule_file: str = rule_file
        
        # Time window and threshold values
        self.time_window: int = self.conditions.get('time_window', 60)  # seconds
        self.threshold: int = self.conditions.get('threshold', 5)
        self.event_id: Optional[str] = self.conditions.get('event_id')
        
        # Track repeat count (event_id -> [(timestamp, user), ...])
        self.event_history: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
    
    def matches(self, event_id: str, timestamp: datetime, message: str = "") -> bool:
        """
        Checks if event matches this rule.
        
        Args:
            event_id: Event ID
            timestamp: Event time
            message: Event message (optional, for filtering)
        
        Returns:
            bool: True if rule matches
        """
        if not self.enabled:
            return False
        
        # Event ID check
        if self.event_id and event_id != self.event_id:
            return False
        
        # User filtering
        if self.filters:
            exclude_users = self.filters.get('exclude_users', [])
            include_users = self.filters.get('include_users', [])
            
            # Try to extract username from message (simple regex)
            user_in_message = self._extract_user_from_message(message)
            
            if exclude_users and user_in_message:
                if user_in_message.upper() in [u.upper() for u in exclude_users]:
                    return False
            
            if include_users and user_in_message:
                if user_in_message.upper() not in [u.upper() for u in include_users]:
                    return False
        
        # Time window check (if threshold exists)
        if self.threshold > 0:
            # Clear old records (older than time_window)
            cutoff_time = timestamp - timedelta(seconds=self.time_window)
            self.event_history[event_id] = [
                (ts, user) for ts, user in self.event_history[event_id]
                if ts > cutoff_time
            ]
            
            # Add new event
            user_in_message = self._extract_user_from_message(message)
            self.event_history[event_id].append((timestamp, user_in_message or 'UNKNOWN'))
            
            # Threshold check
            if len(self.event_history[event_id]) >= self.threshold:
                return True
        
        return False
    
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
        
        # Basit pattern matching (Account Name, User Name gibi alanları ara)
        import re
        
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
            dict: Rule result (risk_level, mitre_technique, match_message)
        """
        return {
            'risk_level': self.risk_level,
            'mitre_technique': self.mitre_technique,
            'match_message': self.match_message,
            'rule_name': self.name
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
                        rule = DetectionRule(rule_data, yaml_file.name)
                        self.rules.append(rule)
                        logger.info(f"Rule loaded: {rule.name} ({yaml_file.name})")
                
                except Exception as e:
                    logger.error(f"Error loading rule ({yaml_file}): {e}", exc_info=True)
            
            logger.info(f"Total {len(self.rules)} rules loaded")
        
        except Exception as e:
            logger.error(f"Error loading rules: {e}", exc_info=True)
    
    def check_event(
        self,
        event_id: str,
        timestamp: datetime,
        message: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Checks an event against all rules.
        
        Args:
            event_id: Event ID
            timestamp: Event time
            message: Event message
        
        Returns:
            dict: If rule matches, rule result (risk_level, mitre_technique, match_message)
                 None if no match
        """
        # Check all rules (sort by priority: high -> medium -> low)
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_rules = sorted(
            self.rules,
            key=lambda r: priority_order.get(r.priority.lower(), 99)
        )
        
        for rule in sorted_rules:
            if rule.matches(event_id, timestamp, message):
                logger.warning(
                    f"🔴 RULE MATCH: {rule.name} - Event ID: {event_id}, "
                    f"Risk: {rule.risk_level}, MITRE: {rule.mitre_technique}"
                )
                return rule.get_result()
        
        return None
    
    def reload_rules(self) -> None:
        """Reloads rules (hot reload)"""
        self.rules.clear()
        self.load_rules()
        logger.info("Rules reloaded")

