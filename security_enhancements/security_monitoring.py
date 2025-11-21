"""
OWASP Security Monitoring and Logging
Comprehensive security event monitoring and threat detection
"""

import json
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress

# Configure logging
security_logger = logging.getLogger('django.security')
monitor_logger = logging.getLogger('security_monitoring')

User = get_user_model()

class RiskLevel(Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EventType(Enum):
    """Security event types"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    INJECTION_ATTEMPT = "injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_FAILURE = "csrf_failure"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    FILE_UPLOAD = "file_upload"
    DATA_ACCESS = "data_access"
    MFA_SETUP = "mfa_setup"
    MFA_VERIFY = "mfa_verify"
    SESSION_ANOMALY = "session_anomaly"
    API_ABUSE = "api_abuse"

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: EventType
    user_id: Optional[int]
    username: Optional[str]
    ip_address: str
    user_agent: str
    timestamp: datetime
    risk_level: RiskLevel
    details: Dict[str, Any]
    session_id: Optional[str] = None
    request_path: Optional[str] = None

class SecurityEventProcessor:
    """Process and analyze security events"""
    
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.blocked_ips = set()
        self.suspicious_ips = set()
    
    def process_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Process a security event and determine response"""
        
        # Log the event
        self._log_event(event)
        
        # Analyze threat level
        analysis = self._analyze_event(event)
        
        # Take automated actions if needed
        actions = self._determine_actions(event, analysis)
        
        # Execute actions
        self._execute_actions(actions)
        
        # Store event for correlation
        self._store_event_for_correlation(event)
        
        return {
            'event_id': self._generate_event_id(event),
            'risk_score': analysis['risk_score'],
            'actions_taken': actions,
            'analysis': analysis
        }
    
    def _log_event(self, event: SecurityEvent):
        """Log security event with appropriate level"""
        
        log_data = {
            'event_type': event.event_type.value,
            'user_id': event.user_id,
            'username': event.username,
            'ip_address': event.ip_address,
            'risk_level': event.risk_level.value,
            'timestamp': event.timestamp.isoformat(),
            'details': event.details,
            'session_id': event.session_id,
            'path': event.request_path
        }
        
        if event.risk_level == RiskLevel.CRITICAL:
            security_logger.critical(f"CRITICAL: {event.event_type.value}", extra=log_data)
        elif event.risk_level == RiskLevel.HIGH:
            security_logger.error(f"HIGH RISK: {event.event_type.value}", extra=log_data)
        elif event.risk_level == RiskLevel.MEDIUM:
            security_logger.warning(f"MEDIUM RISK: {event.event_type.value}", extra=log_data)
        else:
            security_logger.info(f"LOW RISK: {event.event_type.value}", extra=log_data)
    
    def _analyze_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Analyze event for threat indicators"""
        
        analysis = {
            'risk_score': 0,
            'indicators': [],
            'patterns_matched': [],
            'correlation_score': 0,
            'anomaly_score': 0
        }
        
        # Check IP reputation
        ip_reputation = self._check_ip_reputation(event.ip_address)
        analysis['risk_score'] += ip_reputation['risk_score']
        analysis['indicators'].extend(ip_reputation['indicators'])
        
        # Check user patterns
        user_analysis = self._analyze_user_behavior(event)
        analysis['risk_score'] += user_analysis['risk_score']
        analysis['indicators'].extend(user_analysis['indicators'])
        
        # Check request patterns
        request_analysis = self._analyze_request_patterns(event)
        analysis['risk_score'] += request_analysis['risk_score']
        analysis['patterns_matched'].extend(request_analysis['patterns'])
        
        # Check for event correlation
        correlation_score = self._correlate_events(event)
        analysis['correlation_score'] = correlation_score
        analysis['risk_score'] += correlation_score
        
        # Normalize risk score (0-100)\n        analysis['risk_score'] = min(100, max(0, analysis['risk_score']))\n        \n        return analysis\n    \n    def _check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:\n        \"\"\"Check IP address reputation\"\"\"\n        \n        result = {\n            'risk_score': 0,\n            'indicators': []\n        }\n        \n        try:\n            ip = ipaddress.ip_address(ip_address)\n            \n            # Check if IP is in blocked list\n            if ip_address in self.blocked_ips:\n                result['risk_score'] += 50\n                result['indicators'].append('blocked_ip')\n            \n            # Check if IP is suspicious\n            if ip_address in self.suspicious_ips:\n                result['risk_score'] += 25\n                result['indicators'].append('suspicious_ip')\n            \n            # Check for private/internal IPs in suspicious contexts\n            if ip.is_private and not self._is_expected_internal_ip(ip_address):\n                result['risk_score'] += 10\n                result['indicators'].append('unexpected_internal_ip')\n            \n            # Check recent failed attempts from this IP\n            failed_attempts = self._get_recent_failed_attempts(ip_address)\n            if failed_attempts > 5:\n                result['risk_score'] += min(30, failed_attempts * 3)\n                result['indicators'].append('multiple_failed_attempts')\n            \n        except ValueError:\n            result['risk_score'] += 20\n            result['indicators'].append('invalid_ip_format')\n        \n        return result\n    \n    def _analyze_user_behavior(self, event: SecurityEvent) -> Dict[str, Any]:\n        \"\"\"Analyze user behavior patterns\"\"\"\n        \n        result = {\n            'risk_score': 0,\n            'indicators': []\n        }\n        \n        if not event.user_id:\n            return result\n        \n        # Check login patterns\n        if event.event_type == EventType.LOGIN_SUCCESS:\n            # Check for unusual login times\n            if self._is_unusual_login_time(event):\n                result['risk_score'] += 15\n                result['indicators'].append('unusual_login_time')\n            \n            # Check for geolocation anomalies (simplified)\n            if self._is_unusual_location(event):\n                result['risk_score'] += 20\n                result['indicators'].append('unusual_location')\n        \n        # Check for rapid successive actions\n        if self._has_rapid_actions(event):\n            result['risk_score'] += 25\n            result['indicators'].append('rapid_actions')\n        \n        # Check session duration anomalies\n        if self._has_unusual_session_duration(event):\n            result['risk_score'] += 10\n            result['indicators'].append('unusual_session_duration')\n        \n        return result\n    \n    def _analyze_request_patterns(self, event: SecurityEvent) -> Dict[str, Any]:\n        \"\"\"Analyze request patterns for attacks\"\"\"\n        \n        result = {\n            'risk_score': 0,\n            'patterns': []\n        }\n        \n        # Check User-Agent patterns\n        user_agent = event.user_agent.lower()\n        \n        # Bot/automation detection\n        bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'automation']\n        if any(indicator in user_agent for indicator in bot_indicators):\n            result['risk_score'] += 15\n            result['patterns'].append('automation_tool')\n        \n        # Check for suspicious User-Agent patterns\n        if len(user_agent) < 10 or 'mozilla' not in user_agent:\n            result['risk_score'] += 10\n            result['patterns'].append('suspicious_user_agent')\n        \n        # Check request details for attack patterns\n        details = event.details\n        \n        if 'request_data' in details:\n            request_data = str(details['request_data'])\n            \n            # SQL injection patterns\n            sql_patterns = self.threat_patterns.get('sql_injection', [])\n            for pattern in sql_patterns:\n                if re.search(pattern, request_data, re.IGNORECASE):\n                    result['risk_score'] += 30\n                    result['patterns'].append('sql_injection_attempt')\n                    break\n            \n            # XSS patterns\n            xss_patterns = self.threat_patterns.get('xss', [])\n            for pattern in xss_patterns:\n                if re.search(pattern, request_data, re.IGNORECASE):\n                    result['risk_score'] += 25\n                    result['patterns'].append('xss_attempt')\n                    break\n            \n            # Path traversal patterns\n            path_patterns = self.threat_patterns.get('path_traversal', [])\n            for pattern in path_patterns:\n                if re.search(pattern, request_data, re.IGNORECASE):\n                    result['risk_score'] += 20\n                    result['patterns'].append('path_traversal_attempt')\n                    break\n        \n        return result\n    \n    def _correlate_events(self, event: SecurityEvent) -> int:\n        \"\"\"Correlate events to detect attack patterns\"\"\"\n        \n        correlation_score = 0\n        \n        # Get recent events from same IP\n        recent_events = self._get_recent_events_by_ip(event.ip_address, minutes=30)\n        \n        if len(recent_events) > 10:\n            correlation_score += 20\n        \n        # Check for distributed attacks (same user, multiple IPs)\n        if event.user_id:\n            user_ips = self._get_recent_ips_for_user(event.user_id, hours=1)\n            if len(user_ips) > 3:\n                correlation_score += 25\n        \n        # Check for coordinated attacks (multiple users, similar patterns)\n        similar_events = self._find_similar_events(event, hours=1)\n        if len(similar_events) > 5:\n            correlation_score += 15\n        \n        return correlation_score\n    \n    def _determine_actions(self, event: SecurityEvent, analysis: Dict[str, Any]) -> List[str]:\n        \"\"\"Determine automated response actions\"\"\"\n        \n        actions = []\n        risk_score = analysis['risk_score']\n        \n        # Critical risk actions\n        if risk_score >= 80:\n            actions.append('block_ip_immediately')\n            actions.append('alert_security_team')\n            actions.append('terminate_user_sessions')\n        \n        # High risk actions\n        elif risk_score >= 60:\n            actions.append('temporary_ip_block')\n            actions.append('require_mfa_verification')\n            actions.append('alert_administrators')\n        \n        # Medium risk actions\n        elif risk_score >= 40:\n            actions.append('increase_monitoring')\n            actions.append('add_to_watchlist')\n            actions.append('log_detailed_audit')\n        \n        # Specific event type actions\n        if event.event_type == EventType.LOGIN_FAILURE:\n            failed_count = self._get_recent_failed_attempts(event.ip_address)\n            if failed_count >= 5:\n                actions.append('temporary_account_lock')\n        \n        elif event.event_type == EventType.INJECTION_ATTEMPT:\n            actions.append('block_request')\n            actions.append('sanitize_input')\n        \n        return list(set(actions))  # Remove duplicates\n    \n    def _execute_actions(self, actions: List[str]):\n        \"\"\"Execute automated response actions\"\"\"\n        \n        for action in actions:\n            try:\n                if action == 'block_ip_immediately':\n                    self._block_ip_permanently()\n                \n                elif action == 'temporary_ip_block':\n                    self._block_ip_temporarily()\n                \n                elif action == 'alert_security_team':\n                    self._send_security_alert()\n                \n                elif action == 'increase_monitoring':\n                    self._increase_monitoring_level()\n                \n                # Log action execution\n                monitor_logger.info(f\"Executed security action: {action}\")\n                \n            except Exception as e:\n                monitor_logger.error(f\"Failed to execute action {action}: {str(e)}\")\n    \n    def _load_threat_patterns(self) -> Dict[str, List[str]]:\n        \"\"\"Load threat detection patterns\"\"\"\n        \n        return {\n            'sql_injection': [\n                r\"('|(\\\\'))+.*(\\\\').*(('|(\\\\'))|($))\",\n                r\"union\\s+select\",\n                r\"select.*from\",\n                r\"insert\\s+into\",\n                r\"delete\\s+from\",\n                r\"drop\\s+table\",\n                r\"--\\s*$\",\n                r\"/\\*.*\\*/\"\n            ],\n            'xss': [\n                r\"<script[^>]*>.*?</script>\",\n                r\"javascript\\s*:\",\n                r\"vbscript\\s*:\",\n                r\"on\\w+\\s*=\",\n                r\"<iframe[^>]*>\",\n                r\"<object[^>]*>\"\n            ],\n            'path_traversal': [\n                r\"\\.\\./\",\n                r\"\\.\\.\\\\\\\\",\n                r\"%2e%2e%2f\",\n                r\"%2e%2e\\\\\\\\\"\n            ],\n            'command_injection': [\n                r\"[;&|`$]\",\n                r\"\\$\\(\",\n                r\"`.*`\",\n                r\"\\|\\s*\\w+\"\n            ]\n        }\n    \n    def _generate_event_id(self, event: SecurityEvent) -> str:\n        \"\"\"Generate unique event ID\"\"\"\n        event_data = f\"{event.timestamp.isoformat()}:{event.ip_address}:{event.event_type.value}\"\n        return hashlib.sha256(event_data.encode()).hexdigest()[:16]\n    \n    def _store_event_for_correlation(self, event: SecurityEvent):\n        \"\"\"Store event data for correlation analysis\"\"\"\n        \n        cache_key = f\"security_event:{event.ip_address}:{int(event.timestamp.timestamp())}\"\n        event_data = {\n            'event_type': event.event_type.value,\n            'user_id': event.user_id,\n            'timestamp': event.timestamp.isoformat(),\n            'risk_level': event.risk_level.value\n        }\n        \n        cache.set(cache_key, event_data, 3600)  # Store for 1 hour\n    \n    # Helper methods (simplified implementations)\n    def _is_expected_internal_ip(self, ip_address: str) -> bool:\n        \"\"\"Check if internal IP is expected\"\"\"\n        expected_ranges = ['192.168.', '10.', '172.']\n        return any(ip_address.startswith(range_) for range_ in expected_ranges)\n    \n    def _get_recent_failed_attempts(self, ip_address: str) -> int:\n        \"\"\"Get count of recent failed attempts from IP\"\"\"\n        cache_key = f\"failed_attempts:{ip_address}\"\n        return cache.get(cache_key, 0)\n    \n    def _is_unusual_login_time(self, event: SecurityEvent) -> bool:\n        \"\"\"Check if login time is unusual for user\"\"\"\n        # Simplified: check if login is outside business hours\n        hour = event.timestamp.hour\n        return hour < 6 or hour > 22\n    \n    def _is_unusual_location(self, event: SecurityEvent) -> bool:\n        \"\"\"Check for unusual geolocation (simplified)\"\"\"\n        # This would integrate with GeoIP service\n        return False\n    \n    def _has_rapid_actions(self, event: SecurityEvent) -> bool:\n        \"\"\"Check for rapid successive actions\"\"\"\n        if not event.user_id:\n            return False\n        \n        cache_key = f\"user_actions:{event.user_id}\"\n        recent_actions = cache.get(cache_key, [])\n        \n        # Check if more than 10 actions in last minute\n        current_time = time.time()\n        recent_actions = [t for t in recent_actions if current_time - t < 60]\n        \n        return len(recent_actions) > 10\n    \n    def _has_unusual_session_duration(self, event: SecurityEvent) -> bool:\n        \"\"\"Check for unusual session duration\"\"\"\n        # This would check session duration patterns\n        return False\n    \n    def _get_recent_events_by_ip(self, ip_address: str, minutes: int = 30) -> List[Dict]:\n        \"\"\"Get recent events from IP address\"\"\"\n        # This would query the event store\n        return []\n    \n    def _get_recent_ips_for_user(self, user_id: int, hours: int = 1) -> List[str]:\n        \"\"\"Get recent IP addresses for user\"\"\"\n        # This would query the event store\n        return []\n    \n    def _find_similar_events(self, event: SecurityEvent, hours: int = 1) -> List[Dict]:\n        \"\"\"Find similar events in time window\"\"\"\n        # This would query for similar event patterns\n        return []\n    \n    def _block_ip_permanently(self):\n        \"\"\"Block IP address permanently\"\"\"\n        pass\n    \n    def _block_ip_temporarily(self):\n        \"\"\"Block IP address temporarily\"\"\"\n        pass\n    \n    def _send_security_alert(self):\n        \"\"\"Send alert to security team\"\"\"\n        pass\n    \n    def _increase_monitoring_level(self):\n        \"\"\"Increase monitoring for entity\"\"\"\n        pass\n\n\nclass SecurityMetrics:\n    \"\"\"Calculate and track security metrics\"\"\"\n    \n    @staticmethod\n    def get_security_dashboard_data() -> Dict[str, Any]:\n        \"\"\"Get data for security dashboard\"\"\"\n        \n        now = timezone.now()\n        last_24h = now - timedelta(hours=24)\n        last_7d = now - timedelta(days=7)\n        \n        return {\n            'events_last_24h': SecurityMetrics._count_events_since(last_24h),\n            'high_risk_events_24h': SecurityMetrics._count_high_risk_events_since(last_24h),\n            'blocked_ips_count': len(SecurityMetrics._get_blocked_ips()),\n            'failed_logins_24h': SecurityMetrics._count_failed_logins_since(last_24h),\n            'top_threat_types': SecurityMetrics._get_top_threat_types(last_7d),\n            'risk_trend': SecurityMetrics._calculate_risk_trend()\n        }\n    \n    @staticmethod\n    def _count_events_since(since: datetime) -> int:\n        \"\"\"Count security events since timestamp\"\"\"\n        # This would query the SecurityLog model\n        return 0\n    \n    @staticmethod\n    def _count_high_risk_events_since(since: datetime) -> int:\n        \"\"\"Count high/critical risk events\"\"\"\n        return 0\n    \n    @staticmethod\n    def _get_blocked_ips() -> Set[str]:\n        \"\"\"Get currently blocked IP addresses\"\"\"\n        return set()\n    \n    @staticmethod\n    def _count_failed_logins_since(since: datetime) -> int:\n        \"\"\"Count failed login attempts\"\"\"\n        return 0\n    \n    @staticmethod\n    def _get_top_threat_types(since: datetime) -> List[Dict[str, Any]]:\n        \"\"\"Get most common threat types\"\"\"\n        return []\n    \n    @staticmethod\n    def _calculate_risk_trend() -> Dict[str, float]:\n        \"\"\"Calculate risk trend over time\"\"\"\n        return {'trend': 0.0, 'direction': 'stable'}\n\n\n# Global security event processor instance\nsecurity_processor = SecurityEventProcessor()