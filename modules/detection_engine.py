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

from modules.rule_schema import validate_rule

# Logging configuration
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
        # event_id may be a single value OR a list (OR-match across event IDs).
        raw_event_id = self.conditions.get('event_id')
        if isinstance(raw_event_id, list):
            self.event_ids: List[str] = [str(e) for e in raw_event_id]
            self.event_id: Optional[str] = self.event_ids[0] if self.event_ids else None
        elif raw_event_id is not None:
            self.event_id = str(raw_event_id)
            self.event_ids = [self.event_id]
        else:
            self.event_id = None
            self.event_ids = []

        self.provider: Optional[str] = self.conditions.get('provider')  # Security, Sysmon, etc.
        self.message_regex: Optional[str] = self.conditions.get('message_regex')
        self.command_line_regex: Optional[str] = self.conditions.get('command_line_regex')
        self.image_regex: Optional[str] = self.conditions.get('image_regex')
        self.parent_image_regex: Optional[str] = self.conditions.get('parent_image_regex')
        # Negative conditions: the rule does NOT match if these patterns match.
        self.not_message_regex: Optional[str] = self.conditions.get('not_message_regex')
        self.not_command_line_regex: Optional[str] = self.conditions.get('not_command_line_regex')

        # Threshold and time window (for counting-based rules)
        self.time_window: int = self.conditions.get('time_window', 60)  # seconds
        self.threshold: int = self.conditions.get('threshold', 0)  # 0 means no threshold check
        # Optional threshold grouping: 'source_ip' counts per attacker address
        # (extracted from the message) instead of one global counter per event_id.
        self.group_by: Optional[str] = self.conditions.get('group_by')

        # Cross-event correlation: fire the trigger (event_id) only when a prior
        # event pattern has occurred >= count times for the same source within a
        # window. E.g. a successful logon (4624) after 5 failures (4625) = a
        # successful brute force.
        corr = self.conditions.get('correlation')
        self.correlation: Optional[Dict[str, Any]] = corr if isinstance(corr, dict) else None
        if self.correlation:
            self.corr_prior_event_id: str = str(self.correlation.get('prior_event_id', ''))
            self.corr_count: int = int(self.correlation.get('count', 5))
            self.corr_within: int = int(self.correlation.get('within', 300))
        
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

        # Correlation rules observe two event types (prior + trigger); handle
        # them separately, after the provider gate.
        if self.correlation:
            return self._matches_correlation(event_id, timestamp, message, sysmon_data)

        # Event ID check (single value or OR across a list)
        if self.event_ids:
            if str(event_id) not in self.event_ids:
                return False

        # Message regex check
        if self.message_regex:
            try:
                if not re.search(self.message_regex, message, re.IGNORECASE | re.MULTILINE):
                    return False
            except re.error as e:
                logger.warning(f"Invalid regex pattern in rule {self.id}: {self.message_regex} - {e}")
                return False

        # Negative message regex: rule must NOT match this pattern
        if self.not_message_regex:
            try:
                if re.search(self.not_message_regex, message, re.IGNORECASE | re.MULTILINE):
                    return False
            except re.error as e:
                logger.warning(f"Invalid not_message_regex in rule {self.id}: {e}")
        
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

            # Negative command line regex: rule must NOT match this pattern
            if self.not_command_line_regex and 'CommandLine' in sysmon_data:
                try:
                    if re.search(self.not_command_line_regex, sysmon_data['CommandLine'], re.IGNORECASE):
                        return False
                except re.error as e:
                    logger.warning(f"Invalid not_command_line_regex in rule {self.id}: {e}")
            
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

            cutoff_time = timestamp - timedelta(seconds=self.time_window)

            # Prune expired entries across ALL keys and drop keys that become
            # empty. Pruning only the current key would let stale keys (e.g. a
            # parent->child combo that never reappears) accumulate forever,
            # leaking memory over a long-running session.
            for key in list(self.event_history.keys()):
                self.event_history[key] = [
                    (ts, ctx) for ts, ctx in self.event_history[key]
                    if ts > cutoff_time
                ]
                if not self.event_history[key]:
                    del self.event_history[key]

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
    
    def _matches_correlation(
        self,
        event_id: str,
        timestamp: datetime,
        message: str,
        sysmon_data: Optional[Dict[str, str]],
    ) -> bool:
        """
        Handles a cross-event correlation rule.

        Records occurrences of the prior event (keyed by source IP), and fires
        only when the trigger event arrives for a source that has accumulated
        >= corr_count prior events within corr_within seconds.
        """
        source = self._extract_source_ip_from_message(message)
        if not source:
            return False

        # Prune expired prior events across all sources (keeps memory bounded)
        cutoff = timestamp - timedelta(seconds=self.corr_within)
        for key in list(self.event_history.keys()):
            self.event_history[key] = [
                (ts, ctx) for ts, ctx in self.event_history[key] if ts > cutoff
            ]
            if not self.event_history[key]:
                del self.event_history[key]

        # A prior event (e.g. a failed logon): record it, don't fire yet.
        if str(event_id) == self.corr_prior_event_id:
            self.event_history[source].append((timestamp, {}))
            return False

        # The trigger event (e.g. a successful logon): fire if enough priors.
        if self.event_ids and str(event_id) in self.event_ids:
            return len(self.event_history.get(source, [])) >= self.corr_count

        return False

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
        # For parent-child: group by parent+child combination
        if self.parent_image_regex and sysmon_data:
            parent = sysmon_data.get('ParentImage', 'UNKNOWN')
            image = sysmon_data.get('Image', 'UNKNOWN')
            return f"{event_id}:{parent}->{image}"
        elif self.image_regex and sysmon_data:
            image = sysmon_data.get('Image', 'UNKNOWN')
            return f"{event_id}:{image}"

        # Per-source grouping: count separately per attacker address so five
        # unrelated single failures (five different hosts) do not add up to one
        # false brute-force alert. Falls back to event_id if no IP is found.
        if self.group_by == 'source_ip':
            source_ip = self._extract_source_ip_from_message(message)
            if source_ip:
                return f"{event_id}:{source_ip}"

        # Default: group by event_id (one global counter)
        return str(event_id)

    @staticmethod
    def _extract_source_ip_from_message(message: str) -> Optional[str]:
        """
        Extracts the source/attacker IP from known log field shapes:
        Windows 'Source Network Address:', PAM 'rhost=', SSH 'from <ip>'.
        """
        if not message:
            return None
        for pattern in (
            r'Source Network Address:\s*(\d{1,3}(?:\.\d{1,3}){3})',
            r'rhost=(\d{1,3}(?:\.\d{1,3}){3})',
            r'\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})',
        ):
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
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
                        rule_items = rule_data if isinstance(rule_data, list) else [rule_data]
                        for rule_item in rule_items:
                            # Validate against the schema; skip (don't crash) on a
                            # malformed rule so one bad file can't disable the engine.
                            try:
                                validate_rule(rule_item)
                            except Exception as ve:
                                logger.error(
                                    f"Skipping invalid rule in {yaml_file.name}: {ve}"
                                )
                                continue
                            rule = DetectionRule(rule_item, yaml_file.name)
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

    def reload_rules(self) -> None:
        """Reloads rules (hot reload)"""
        self.rules.clear()
        self.load_rules()
        logger.info("Rules reloaded")
