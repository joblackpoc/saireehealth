"""
Phase 7: Advanced Security Monitoring Middleware
Real-time security monitoring, threat intelligence integration, automated response

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
Component: Security Monitoring Middleware Stack
"""

import json
import time
from typing import Dict, List, Optional, Any
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.contrib.auth.models import User
import logging

from .security_intelligence import (
    SecurityIntelligenceEngine,
    AdvancedThreatHunting,
    MLBasedAnomalyDetection,
    SecurityOrchestrationSOAR,
    SecurityEvent,
    ThreatLevel
)

# Enhanced Security Logging
security_logger = logging.getLogger('security_core')

class SecurityIntelligenceMiddleware(MiddlewareMixin):
    """
    Main security intelligence middleware
    Integrates with Security Intelligence Engine for real-time monitoring
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.intelligence_engine = SecurityIntelligenceEngine()
        self.ml_detector = MLBasedAnomalyDetection()
        self.soar = SecurityOrchestrationSOAR()
        
        # Configuration
        self.enabled = getattr(settings, 'SECURITY_INTELLIGENCE_ENABLED', True)
        self.real_time_analysis = getattr(settings, 'REAL_TIME_ANALYSIS_ENABLED', True)
        self.auto_response = getattr(settings, 'AUTO_INCIDENT_RESPONSE_ENABLED', True)
        
        # Threat detection thresholds
        self.threat_score_threshold = getattr(settings, 'THREAT_SCORE_THRESHOLD', 80)
        self.anomaly_threshold = getattr(settings, 'ANOMALY_DETECTION_THRESHOLD', 0.8)
        
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        start_time = time.time()
        
        # Pre-processing: Security event ingestion
        security_event = self._create_security_event(request)
        if security_event:
            self._process_security_event(request, security_event)
        
        response = self.get_response(request)
        
        # Post-processing: Response analysis and correlation
        processing_time = time.time() - start_time
        self._analyze_response_security(request, response, processing_time, security_event)
        
        return response
    
    def _create_security_event(self, request: HttpRequest) -> Optional[SecurityEvent]:
        """Create security event from HTTP request"""
        try:
            # Determine event type based on request characteristics
            event_type = self._classify_request_event_type(request)
            
            if not event_type:
                return None  # Not a security-relevant event
            
            # Extract threat indicators
            threat_indicators = self._extract_threat_indicators(request)
            
            # Determine severity
            severity = self._calculate_request_severity(request, event_type, threat_indicators)
            
            # Create event data
            event_data = {
                'event_type': event_type,
                'source_ip': self._get_client_ip(request),
                'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
                'severity': severity.value,
                'description': f"{event_type} from {self._get_client_ip(request)}",
                'metadata': {
                    'method': request.method,
                    'path': request.path,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'content_type': request.content_type,
                    'content_length': len(getattr(request, 'body', b'')),
                    'referer': request.META.get('HTTP_REFERER', ''),
                    'x_forwarded_for': request.META.get('HTTP_X_FORWARDED_FOR', ''),
                },
                'threat_indicators': threat_indicators,
                'raw_data': json.dumps({
                    'headers': dict(request.META),
                    'path': request.path,
                    'method': request.method
                })
            }
            
            # Ingest event into intelligence engine
            security_event = self.intelligence_engine.ingest_security_event(event_data)
            
            return security_event
            
        except Exception as e:
            security_logger.error(f"Security event creation failed: {str(e)}")
            return None
    
    def _process_security_event(self, request: HttpRequest, event: SecurityEvent):
        """Process security event for real-time analysis"""
        try:
            # Real-time threat scoring
            threat_score = event.metadata.get('threat_score', 0)
            
            # ML-based anomaly detection for user behavior
            if event.user_id and self.real_time_analysis:
                user_behavior = self._extract_user_behavior_data(request, event.user_id)
                anomaly_result = self.ml_detector.detect_user_behavior_anomalies(
                    event.user_id, 
                    user_behavior
                )
                
                if anomaly_result.get('anomaly_detected'):
                    threat_score += anomaly_result.get('confidence', 0) * 30
                    event.metadata['behavioral_anomaly'] = anomaly_result
            
            # Check for immediate response triggers
            if threat_score >= self.threat_score_threshold:
                self._trigger_immediate_response(request, event, threat_score)
            
            # Store processed event metadata in request
            request.security_event = event
            request.security_threat_score = threat_score
            
        except Exception as e:
            security_logger.error(f"Security event processing failed: {str(e)}")
    
    def _classify_request_event_type(self, request: HttpRequest) -> Optional[str]:
        """Classify HTTP request into security event type"""
        try:
            path = request.path.lower()
            method = request.method
            user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
            
            # Authentication events
            if '/login' in path or '/auth' in path:
                return 'authentication_attempt'
            
            if '/logout' in path:
                return 'logout_event'
            
            # Admin access events
            if '/admin' in path:
                return 'admin_access_attempt'
            
            # API access events
            if '/api' in path:
                return 'api_access'
            
            # File upload events
            if method == 'POST' and request.FILES:
                return 'file_upload'
            
            # Suspicious user agent patterns
            if any(bot in user_agent for bot in ['bot', 'crawler', 'spider', 'scan']):
                return 'automated_access'
            
            # SQL injection indicators in URL
            sql_patterns = ['union', 'select', 'drop', 'insert', 'delete', 'update', 'exec']
            if any(pattern in path for pattern in sql_patterns):
                return 'potential_sql_injection'
            
            # XSS indicators
            if any(xss in path for xss in ['<script', 'javascript:', 'onerror=']):
                return 'potential_xss_attempt'
            
            # High-frequency requests (potential DoS)
            client_ip = self._get_client_ip(request)
            request_count_key = f"request_count_{client_ip}"
            current_count = cache.get(request_count_key, 0)
            
            if current_count > 100:  # More than 100 requests in tracking window
                return 'high_frequency_requests'
            
            # Sensitive data access
            sensitive_paths = ['/health/', '/medical/', '/patient/', '/billing/']
            if any(sensitive in path for sensitive in sensitive_paths):
                return 'sensitive_data_access'
            
            return None  # No specific security event type identified
            
        except Exception as e:
            security_logger.error(f"Request event classification failed: {str(e)}")
            return None
    
    def _extract_threat_indicators(self, request: HttpRequest) -> List[str]:
        """Extract threat indicators from HTTP request"""
        indicators = []
        
        try:
            # IP-based indicators
            client_ip = self._get_client_ip(request)
            
            # Check IP reputation
            ip_reputation_key = f"ip_reputation_{client_ip}"
            ip_reputation = cache.get(ip_reputation_key)
            
            if ip_reputation and ip_reputation.get('malicious'):
                indicators.append(f"malicious_ip:{client_ip}")
            
            # Geographic indicators
            geolocation_key = f"ip_geolocation_{client_ip}"
            geolocation = cache.get(geolocation_key)
            
            if geolocation:
                country = geolocation.get('country_code')
                high_risk_countries = getattr(settings, 'HIGH_RISK_COUNTRIES', [])
                
                if country in high_risk_countries:
                    indicators.append(f"high_risk_country:{country}")
            
            # User agent indicators
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            if not user_agent:
                indicators.append("missing_user_agent")
            elif len(user_agent) < 10:
                indicators.append("suspicious_user_agent")
            
            # Known malicious user agent patterns
            malicious_ua_patterns = [
                'sqlmap', 'nmap', 'nikto', 'burp', 'zap', 'metasploit'
            ]
            
            if any(pattern in user_agent.lower() for pattern in malicious_ua_patterns):
                indicators.append("malicious_tool_user_agent")
            
            # Request pattern indicators
            if request.method in ['PUT', 'DELETE', 'PATCH'] and not hasattr(request, 'user'):
                indicators.append("unauthenticated_modification_attempt")
            
            # Header analysis
            suspicious_headers = []
            
            if 'X-Forwarded-For' in request.META:
                xff_value = request.META['X-Forwarded-For']
                if ',' in xff_value:  # Multiple IPs in chain
                    indicators.append("proxy_chain_detected")
            
            if request.META.get('HTTP_ACCEPT') == '*/*':
                indicators.append("generic_accept_header")
            
            return indicators
            
        except Exception as e:
            security_logger.error(f"Threat indicator extraction failed: {str(e)}")
            return []
    
    def _calculate_request_severity(self, request: HttpRequest, 
                                  event_type: str, 
                                  threat_indicators: List[str]) -> ThreatLevel:
        """Calculate severity level for security event"""
        try:
            base_severity = ThreatLevel.LOW
            
            # Event type based severity
            high_severity_events = [
                'potential_sql_injection',
                'potential_xss_attempt',
                'admin_access_attempt',
                'malicious_tool_user_agent'
            ]
            
            medium_severity_events = [
                'authentication_attempt',
                'file_upload',
                'high_frequency_requests',
                'sensitive_data_access'
            ]
            
            if event_type in high_severity_events:
                base_severity = ThreatLevel.HIGH
            elif event_type in medium_severity_events:
                base_severity = ThreatLevel.MEDIUM
            
            # Threat indicators impact
            indicator_count = len(threat_indicators)
            
            if indicator_count >= 3:
                base_severity = ThreatLevel.CRITICAL
            elif indicator_count >= 2:
                base_severity = max(base_severity, ThreatLevel.HIGH)
            elif indicator_count >= 1:
                base_severity = max(base_severity, ThreatLevel.MEDIUM)
            
            # Special escalation conditions
            malicious_indicators = [
                indicator for indicator in threat_indicators
                if 'malicious' in indicator or 'suspicious' in indicator
            ]
            
            if malicious_indicators:
                base_severity = ThreatLevel.CRITICAL
            
            return base_severity
            
        except Exception as e:
            security_logger.error(f"Severity calculation failed: {str(e)}")
            return ThreatLevel.LOW
    
    def _trigger_immediate_response(self, request: HttpRequest, 
                                  event: SecurityEvent, 
                                  threat_score: int):
        """Trigger immediate security response for high-threat events"""
        try:
            if not self.auto_response:
                return
            
            client_ip = self._get_client_ip(request)
            
            # Create mock incident for SOAR processing
            from .security_intelligence import SecurityIncident, IncidentStatus
            
            incident = SecurityIncident(
                incident_id=f"auto_{event.event_id}",
                title=f"High-threat activity detected: {event.event_type}",
                description=f"Automated incident created for threat score {threat_score}",
                severity=event.severity,
                status=IncidentStatus.NEW,
                created_at=timezone.now(),
                updated_at=timezone.now(),
                assigned_to='auto_response_system',
                events=[event]
            )
            
            # Execute automated response
            if threat_score >= 95:  # Critical threat
                # Block IP immediately
                self._emergency_ip_block(client_ip, "critical_threat_detected")
                
                # Execute critical incident playbook
                if self.auto_response:
                    response_result = self.soar.execute_incident_response(
                        incident, 
                        'critical_threat_response'
                    )
                    event.metadata['auto_response'] = response_result
            
            elif threat_score >= 85:  # High threat
                # Temporary IP restriction
                self._temporary_ip_restriction(client_ip, 3600)  # 1 hour
                
                # Execute high-threat playbook
                if self.auto_response:
                    response_result = self.soar.execute_incident_response(
                        incident, 
                        'high_threat_response'
                    )
                    event.metadata['auto_response'] = response_result
            
            security_logger.warning(f"Immediate response triggered for threat score {threat_score}: {event.event_id}")
            
        except Exception as e:
            security_logger.error(f"Immediate response trigger failed: {str(e)}")
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract real client IP address"""
        # Check for IP in X-Forwarded-For header (proxy/load balancer)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
            return ip
        
        # Check for IP in X-Real-IP header
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            return x_real_ip
        
        # Fall back to REMOTE_ADDR
        return request.META.get('REMOTE_ADDR', '0.0.0.0')
    
    def _extract_user_behavior_data(self, request: HttpRequest, user_id: int) -> Dict[str, Any]:
        """Extract user behavior data for ML analysis"""
        try:
            behavior_key = f"user_behavior_{user_id}"
            behavior_data = cache.get(behavior_key, {
                'login_count': 0,
                'failed_login_count': 0,
                'pages_visited': 0,
                'session_duration': 0,
                'unique_ips_count': 0,
                'unique_countries': 0,
                'new_device': False
            })
            
            # Update with current request
            behavior_data['pages_visited'] += 1
            
            # Track unique IPs
            current_ip = self._get_client_ip(request)
            user_ips_key = f"user_ips_{user_id}"
            user_ips = cache.get(user_ips_key, set())
            
            if current_ip not in user_ips:
                user_ips.add(current_ip)
                behavior_data['unique_ips_count'] = len(user_ips)
                cache.set(user_ips_key, user_ips, 86400)  # 24 hours
            
            # Update behavior cache
            cache.set(behavior_key, behavior_data, 86400)  # 24 hours
            
            return behavior_data
            
        except Exception as e:
            security_logger.error(f"User behavior data extraction failed: {str(e)}")
            return {}
    
    def _emergency_ip_block(self, ip_address: str, reason: str):
        """Emergency IP blocking"""
        try:
            block_key = f"emergency_blocked_ip_{ip_address}"
            block_data = {
                'ip_address': ip_address,
                'blocked_at': timezone.now().isoformat(),
                'reason': reason,
                'type': 'emergency_block',
                'duration': 86400  # 24 hours
            }
            
            cache.set(block_key, block_data, 86400)
            security_logger.critical(f"EMERGENCY IP BLOCK: {ip_address} - {reason}")
            
        except Exception as e:
            security_logger.error(f"Emergency IP block failed: {str(e)}")
    
    def _temporary_ip_restriction(self, ip_address: str, duration: int):
        """Temporary IP access restriction"""
        try:
            restriction_key = f"restricted_ip_{ip_address}"
            restriction_data = {
                'ip_address': ip_address,
                'restricted_at': timezone.now().isoformat(),
                'duration': duration,
                'type': 'temporary_restriction'
            }
            
            cache.set(restriction_key, restriction_data, duration)
            security_logger.warning(f"TEMPORARY IP RESTRICTION: {ip_address} for {duration} seconds")
            
        except Exception as e:
            security_logger.error(f"Temporary IP restriction failed: {str(e)}")
    
    def _analyze_response_security(self, request: HttpRequest, response: HttpResponse,
                                 processing_time: float, event: Optional[SecurityEvent]):
        """Analyze response for additional security insights"""
        try:
            if not event:
                return
            
            # Response analysis
            response_data = {
                'status_code': response.status_code,
                'content_length': len(response.content) if hasattr(response, 'content') else 0,
                'processing_time': processing_time
            }
            
            # Add response metadata to event
            event.metadata['response'] = response_data
            
            # Detect potential information disclosure
            if response.status_code == 500 and getattr(settings, 'DEBUG', False):
                event.metadata['security_concern'] = 'debug_info_disclosure'
            
            # Detect potential brute force patterns
            if hasattr(request, 'user') and not request.user.is_authenticated:
                if response.status_code == 401 or response.status_code == 403:
                    self._track_failed_authentication(request, event)
            
        except Exception as e:
            security_logger.error(f"Response security analysis failed: {str(e)}")
    
    def _track_failed_authentication(self, request: HttpRequest, event: SecurityEvent):
        """Track failed authentication attempts for brute force detection"""
        try:
            client_ip = self._get_client_ip(request)
            failed_auth_key = f"failed_auth_{client_ip}"
            
            failed_attempts = cache.get(failed_auth_key, [])
            failed_attempts.append({
                'timestamp': timezone.now().isoformat(),
                'event_id': event.event_id,
                'path': request.path,
                'user_agent': request.META.get('HTTP_USER_AGENT', '')
            })
            
            # Keep only recent attempts (last hour)
            cutoff_time = timezone.now() - timezone.timedelta(hours=1)
            recent_attempts = [
                attempt for attempt in failed_attempts
                if timezone.datetime.fromisoformat(attempt['timestamp']) > cutoff_time
            ]
            
            cache.set(failed_auth_key, recent_attempts, 3600)  # 1 hour
            
            # Check for brute force pattern
            if len(recent_attempts) >= 5:  # 5+ failed attempts in 1 hour
                # Create brute force event
                brute_force_data = {
                    'event_type': 'brute_force_attack',
                    'source_ip': client_ip,
                    'severity': ThreatLevel.HIGH.value,
                    'description': f'Brute force attack detected from {client_ip}',
                    'metadata': {
                        'failed_attempts': len(recent_attempts),
                        'time_window': '1_hour',
                        'target_paths': list(set(attempt['path'] for attempt in recent_attempts))
                    },
                    'threat_indicators': ['brute_force_pattern', 'repeated_failures']
                }
                
                # Ingest brute force event
                self.intelligence_engine.ingest_security_event(brute_force_data)
                
        except Exception as e:
            security_logger.error(f"Failed authentication tracking failed: {str(e)}")


class ThreatHuntingMiddleware(MiddlewareMixin):
    """
    Proactive threat hunting middleware
    Continuously hunts for advanced threats and suspicious patterns
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.threat_hunter = AdvancedThreatHunting()
        self.enabled = getattr(settings, 'THREAT_HUNTING_ENABLED', True)
        self.hunting_frequency = getattr(settings, 'THREAT_HUNTING_FREQUENCY', 3600)  # 1 hour
        
        # Start background hunting
        if self.enabled:
            self._start_hunting_scheduler()
    
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        # Check for hunting triggers in request
        self._check_hunting_triggers(request)
        
        response = self.get_response(request)
        
        return response
    
    def _check_hunting_triggers(self, request: HttpRequest):
        """Check if request should trigger specific threat hunts"""
        try:
            # Trigger hunts based on request characteristics
            if '/admin' in request.path:
                # Hunt for privilege escalation
                self.threat_hunter.execute_hunt('privilege_escalation_hunt')
            
            if request.FILES:
                # Hunt for malicious file uploads
                self.threat_hunter.execute_hunt('malicious_file_hunt')
            
        except Exception as e:
            security_logger.error(f"Hunting trigger check failed: {str(e)}")
    
    def _start_hunting_scheduler(self):
        """Start background threat hunting scheduler"""
        import threading
        
        def hunting_scheduler():
            while True:
                try:
                    # Execute scheduled hunts
                    hunt_names = [
                        'suspicious_login_patterns',
                        'lateral_movement_hunt',
                        'data_exfiltration_hunt'
                    ]
                    
                    for hunt_name in hunt_names:
                        try:
                            result = self.threat_hunter.execute_hunt(hunt_name)
                            
                            if result.get('high_risk_findings', 0) > 0:
                                security_logger.warning(
                                    f"Threat hunt '{hunt_name}' found {result['high_risk_findings']} high-risk findings"
                                )
                        except Exception as hunt_error:
                            security_logger.error(f"Hunt execution failed for '{hunt_name}': {str(hunt_error)}")
                    
                    time.sleep(self.hunting_frequency)
                    
                except Exception as e:
                    security_logger.error(f"Hunting scheduler error: {str(e)}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        hunting_thread = threading.Thread(target=hunting_scheduler, daemon=True)
        hunting_thread.start()
        security_logger.info("Threat hunting scheduler started")


class SecurityAnalyticsMiddleware(MiddlewareMixin):
    """
    Security analytics and reporting middleware
    Real-time security metrics and dashboard data
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.enabled = getattr(settings, 'SECURITY_ANALYTICS_ENABLED', True)
        
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        start_time = time.time()
        
        response = self.get_response(request)
        
        # Collect analytics
        processing_time = time.time() - start_time
        self._collect_security_analytics(request, response, processing_time)
        
        return response
    
    def _collect_security_analytics(self, request: HttpRequest, response: HttpResponse, 
                                  processing_time: float):
        """Collect security analytics data"""
        try:
            # Security metrics
            metrics = {
                'timestamp': timezone.now().isoformat(),
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'processing_time': processing_time,
                'client_ip': self._get_client_ip(request),
                'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
                'threat_score': getattr(request, 'security_threat_score', 0),
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:100]  # Truncate
            }
            
            # Store in real-time metrics
            realtime_key = "security_realtime_metrics"
            realtime_metrics = cache.get(realtime_key, {
                'total_requests': 0,
                'high_threat_requests': 0,
                'blocked_requests': 0,
                'avg_threat_score': 0.0,
                'unique_ips': set(),
                'top_paths': {},
                'last_updated': timezone.now().isoformat()
            })
            
            # Update metrics
            realtime_metrics['total_requests'] += 1
            
            if metrics['threat_score'] >= 70:
                realtime_metrics['high_threat_requests'] += 1
            
            if response.status_code == 403:
                realtime_metrics['blocked_requests'] += 1
            
            # Update average threat score
            current_avg = realtime_metrics.get('avg_threat_score', 0.0)
            total_requests = realtime_metrics['total_requests']
            new_score = metrics['threat_score']
            
            realtime_metrics['avg_threat_score'] = (
                (current_avg * (total_requests - 1) + new_score) / total_requests
            )
            
            # Track unique IPs
            realtime_metrics['unique_ips'].add(metrics['client_ip'])
            
            # Track top paths
            path = metrics['path']
            realtime_metrics['top_paths'][path] = realtime_metrics['top_paths'].get(path, 0) + 1
            
            realtime_metrics['last_updated'] = timezone.now().isoformat()
            
            # Store updated metrics
            cache.set(realtime_key, realtime_metrics, 3600)  # 1 hour
            
            # Store individual metric for detailed analysis
            metric_key = f"security_metric_{int(time.time())}_{hash(request.path) % 1000}"
            cache.set(metric_key, metrics, 86400)  # 24 hours
            
        except Exception as e:
            security_logger.error(f"Security analytics collection failed: {str(e)}")
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
            return ip
        
        return request.META.get('REMOTE_ADDR', '0.0.0.0')