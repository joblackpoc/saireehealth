"""
Phase 8: Security Monitoring Middleware & API Integration
Real-time event processing middleware and management APIs

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Middleware Integration & Management APIs
"""

import json
import time
import uuid
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from functools import wraps
import logging

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
# BaseMiddleware not needed for new-style middleware

from .advanced_monitoring import SecurityEvent, EventPriority, get_security_monitor
from .event_streaming import get_event_streamer, StreamStatus
from .security_intelligence import get_security_intelligence

# Monitoring Logger
monitor_logger = logging.getLogger('security_monitoring')

class SecurityMonitoringMiddleware:
    """
    Django middleware for real-time security event processing
    
    Integrates with all request/response cycles to provide
    comprehensive security monitoring and threat detection.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.security_monitor = get_security_monitor()
        self.event_streamer = get_event_streamer()
        self.security_intelligence = get_security_intelligence()
        
        # Middleware configuration
        self.config = getattr(settings, 'SECURITY_MONITORING_CONFIG', {
            'ENABLE_REQUEST_MONITORING': True,
            'ENABLE_RESPONSE_MONITORING': True,
            'ENABLE_EXCEPTION_MONITORING': True,
            'TRACK_SUSPICIOUS_PATTERNS': True,
            'RATE_LIMITING_ENABLED': True,
            'ANOMALY_DETECTION_ENABLED': True,
            'LOG_SENSITIVE_DATA': False,
            'WHITELIST_PATHS': ['/health/', '/status/', '/metrics/'],
            'SUSPICIOUS_USER_AGENTS': [
                'sqlmap', 'nikto', 'nmap', 'masscan', 'dirb', 'gobuster'
            ],
            'MAX_REQUESTS_PER_MINUTE': 60,
            'BLOCK_SUSPICIOUS_IPS': True,
        })
        
        # Request tracking
        self.request_tracker = RequestTracker()
        self.threat_detector = ThreatDetector()
        
        monitor_logger.info("Security Monitoring Middleware initialized")
    
    def __call__(self, request):
        """Process request and response"""
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        # Pre-process request
        if self.config.get('ENABLE_REQUEST_MONITORING', True):
            security_context = self._analyze_request_security(request, request_id)
            
            # Block suspicious requests
            if security_context.get('block_request', False):
                return self._create_blocked_response(security_context)
        
        # Process request
        try:
            response = self.get_response(request)
            
            # Post-process response
            if self.config.get('ENABLE_RESPONSE_MONITORING', True):
                self._analyze_response_security(request, response, request_id, start_time)
            
            return response
            
        except Exception as e:
            # Handle exceptions
            if self.config.get('ENABLE_EXCEPTION_MONITORING', True):
                self._handle_request_exception(request, e, request_id, start_time)
            raise
    
    def _analyze_request_security(self, request, request_id: str) -> Dict[str, Any]:
        """Analyze request for security threats"""
        security_context = {
            'request_id': request_id,
            'threats_detected': [],
            'risk_score': 0,
            'block_request': False
        }
        
        try:
            # Get client information
            client_ip = self._get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            # Skip whitelisted paths
            if any(request.path.startswith(path) for path in self.config.get('WHITELIST_PATHS', [])):
                return security_context
            
            # Rate limiting check
            if self.config.get('RATE_LIMITING_ENABLED', True):
                rate_limit_result = self.request_tracker.check_rate_limit(
                    client_ip, 
                    self.config.get('MAX_REQUESTS_PER_MINUTE', 60)
                )
                
                if rate_limit_result['exceeded']:
                    security_context['threats_detected'].append('RATE_LIMIT_EXCEEDED')
                    security_context['risk_score'] += 30
                    
                    if self.config.get('BLOCK_SUSPICIOUS_IPS', True):
                        security_context['block_request'] = True
            
            # Suspicious user agent detection
            if any(suspicious in user_agent.lower() 
                   for suspicious in self.config.get('SUSPICIOUS_USER_AGENTS', [])):
                security_context['threats_detected'].append('SUSPICIOUS_USER_AGENT')
                security_context['risk_score'] += 40
                
                if self.config.get('BLOCK_SUSPICIOUS_IPS', True):
                    security_context['block_request'] = True
            
            # SQL injection detection
            sql_patterns = self.threat_detector.detect_sql_injection(request)
            if sql_patterns:
                security_context['threats_detected'].append('SQL_INJECTION_ATTEMPT')
                security_context['risk_score'] += 50
                security_context['block_request'] = True
            
            # XSS detection
            xss_patterns = self.threat_detector.detect_xss(request)
            if xss_patterns:
                security_context['threats_detected'].append('XSS_ATTEMPT')
                security_context['risk_score'] += 45
                security_context['block_request'] = True
            
            # Path traversal detection
            if self.threat_detector.detect_path_traversal(request):
                security_context['threats_detected'].append('PATH_TRAVERSAL_ATTEMPT')
                security_context['risk_score'] += 40
                security_context['block_request'] = True
            
            # Command injection detection
            if self.threat_detector.detect_command_injection(request):
                security_context['threats_detected'].append('COMMAND_INJECTION_ATTEMPT')
                security_context['risk_score'] += 55
                security_context['block_request'] = True
            
            # Log security events
            if security_context['threats_detected']:
                self._log_security_event(request, security_context, 'REQUEST_ANALYSIS')
            
        except Exception as e:
            monitor_logger.error(f"Request security analysis failed: {str(e)}")
        
        return security_context
    
    def _analyze_response_security(self, request, response, request_id: str, start_time: float):
        """Analyze response for security issues"""
        try:
            processing_time = (time.time() - start_time) * 1000  # ms
            
            # Detect slow responses (potential DoS)
            if processing_time > 5000:  # 5 seconds
                self._log_security_event(
                    request, 
                    {'processing_time_ms': processing_time},
                    'SLOW_RESPONSE_DETECTED'
                )
            
            # Detect error responses
            if response.status_code >= 400:
                error_context = {
                    'status_code': response.status_code,
                    'processing_time_ms': processing_time
                }
                
                # Track 404 patterns (potential reconnaissance)
                if response.status_code == 404:
                    client_ip = self._get_client_ip(request)
                    self.request_tracker.track_404_pattern(client_ip, request.path)
                
                self._log_security_event(request, error_context, 'ERROR_RESPONSE')
            
            # Check for information disclosure
            if hasattr(response, 'content'):
                self._check_information_disclosure(request, response)
        
        except Exception as e:
            monitor_logger.error(f"Response security analysis failed: {str(e)}")
    
    def _handle_request_exception(self, request, exception: Exception, request_id: str, start_time: float):
        """Handle request exceptions"""
        try:
            exception_context = {
                'exception_type': type(exception).__name__,
                'exception_message': str(exception),
                'processing_time_ms': (time.time() - start_time) * 1000
            }
            
            # Track exceptions that might indicate attacks
            if any(pattern in str(exception).lower() for pattern in ['sql', 'injection', 'script', 'eval']):
                exception_context['potential_attack'] = True
            
            self._log_security_event(request, exception_context, 'REQUEST_EXCEPTION')
        
        except Exception as e:
            monitor_logger.error(f"Exception handling failed: {str(e)}")
    
    def _log_security_event(self, request, context: Dict[str, Any], event_type: str):
        """Log security event"""
        try:
            # Create security event
            event = SecurityEvent(
                event_type=f"MIDDLEWARE_{event_type}",
                severity=self._calculate_severity(context),
                source=self._get_client_ip(request),
                destination=request.get_host(),
                description=f"Security event detected: {event_type}",
                metadata={
                    'path': request.path,
                    'method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                    'context': context
                },
                priority=self._calculate_priority(context)
            )
            
            # Process through monitoring system
            asyncio.create_task(self.security_monitor.process_event(event))
            
            # Stream event if configured
            if self.event_streamer.status == StreamStatus.ACTIVE:
                asyncio.create_task(self.event_streamer.stream_event(event))
        
        except Exception as e:
            monitor_logger.error(f"Security event logging failed: {str(e)}")
    
    def _calculate_severity(self, context: Dict[str, Any]) -> int:
        """Calculate event severity based on context"""
        risk_score = context.get('risk_score', 0)
        
        if risk_score >= 50:
            return 5  # Critical
        elif risk_score >= 30:
            return 4  # High
        elif risk_score >= 15:
            return 3  # Medium
        elif risk_score > 0:
            return 2  # Low
        else:
            return 1  # Info
    
    def _calculate_priority(self, context: Dict[str, Any]) -> EventPriority:
        """Calculate event priority"""
        if context.get('block_request', False):
            return EventPriority.CRITICAL
        elif context.get('risk_score', 0) >= 30:
            return EventPriority.HIGH
        else:
            return EventPriority.NORMAL
    
    def _get_client_ip(self, request) -> str:
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _create_blocked_response(self, security_context: Dict[str, Any]) -> HttpResponse:
        """Create response for blocked requests"""
        return JsonResponse({
            'error': 'Request blocked by security system',
            'request_id': security_context.get('request_id'),
            'threats': security_context.get('threats_detected', [])
        }, status=403)
    
    def _check_information_disclosure(self, request, response):
        """Check for potential information disclosure"""
        try:
            content = response.content.decode('utf-8', errors='ignore')
            
            # Check for common information disclosure patterns
            disclosure_patterns = [
                'traceback', 'exception', 'error', 'debug',
                'database', 'sql error', 'mysql', 'postgresql',
                'stack trace', 'internal server error'
            ]
            
            found_patterns = [pattern for pattern in disclosure_patterns 
                            if pattern.lower() in content.lower()]
            
            if found_patterns:
                context = {
                    'disclosure_patterns': found_patterns,
                    'content_length': len(content)
                }
                self._log_security_event(request, context, 'INFORMATION_DISCLOSURE')
        
        except Exception as e:
            monitor_logger.error(f"Information disclosure check failed: {str(e)}")


class RequestTracker:
    """Track request patterns for security analysis"""
    
    def __init__(self):
        self.rate_limit_cache = {}
        self.pattern_cache = {}
    
    def check_rate_limit(self, client_ip: str, max_requests: int) -> Dict[str, Any]:
        """Check if client exceeds rate limit"""
        current_time = time.time()
        minute_window = int(current_time // 60)
        
        cache_key = f"rate_limit_{client_ip}_{minute_window}"
        
        # Get current count from cache
        current_count = cache.get(cache_key, 0)
        
        # Increment count
        cache.set(cache_key, current_count + 1, 60)
        
        return {
            'exceeded': current_count >= max_requests,
            'current_count': current_count + 1,
            'limit': max_requests,
            'window_end': (minute_window + 1) * 60
        }
    
    def track_404_pattern(self, client_ip: str, path: str):
        """Track 404 patterns for reconnaissance detection"""
        cache_key = f"404_pattern_{client_ip}"
        
        # Get existing patterns
        patterns = cache.get(cache_key, [])
        patterns.append({
            'path': path,
            'timestamp': time.time()
        })
        
        # Keep only last hour
        cutoff_time = time.time() - 3600
        patterns = [p for p in patterns if p['timestamp'] > cutoff_time]
        
        # Store updated patterns
        cache.set(cache_key, patterns, 3600)
        
        # Check for reconnaissance pattern
        if len(patterns) > 20:  # More than 20 404s in an hour
            monitor_logger.warning(f"Potential reconnaissance detected from IP {client_ip}")


class ThreatDetector:
    """Detect various security threats in requests"""
    
    def __init__(self):
        # SQL injection patterns
        self.sql_patterns = [
            r"(?i)(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
            r"(?i)(\b(or|and)\s+\d+\s*=\s*\d+)",
            r"(?i)(\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
            r"(?i)(['\"];\s*(drop|delete|insert|update))",
            r"(?i)(--|\#|/\*|\*/)",
            r"(?i)(\bunion\s+all\s+select\b)",
            r"(?i)(\bconcat\s*\()",
            r"(?i)(\bchar\s*\(\d+\))",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(?i)(<script[^>]*>.*?</script>)",
            r"(?i)(<img[^>]*\s+src\s*=\s*['\"]?\s*javascript:)",
            r"(?i)(<[^>]*\s+on\w+\s*=)",
            r"(?i)(javascript\s*:)",
            r"(?i)(<iframe[^>]*>)",
            r"(?i)(<object[^>]*>)",
            r"(?i)(<embed[^>]*>)",
            r"(?i)(eval\s*\()",
            r"(?i)(expression\s*\()",
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"(\.\.\/|\.\.\\)",
            r"(%2e%2e%2f|%2e%2e%5c)",
            r"(%c0%af|%c1%9c)",
            r"(\/etc\/passwd|\/etc\/shadow)",
            r"(\/windows\/system32)",
        ]
        
        # Command injection patterns
        self.command_patterns = [
            r"(?i)(\b(cmd|command|exec|system|shell|bash|sh|powershell)\b)",
            r"(\||&|;|`|\$\(|\${)",
            r"(nc\s+-|netcat\s+-)",
            r"(wget\s+|curl\s+)",
            r"(chmod\s+|chown\s+)",
            r"(\brm\s+-rf|\bdel\s+)",
        ]
    
    def detect_sql_injection(self, request) -> List[str]:
        """Detect SQL injection attempts"""
        import re
        
        detected_patterns = []
        
        # Check query parameters
        for param, value in request.GET.items():
            for pattern in self.sql_patterns:
                if re.search(pattern, str(value)):
                    detected_patterns.append(f"SQL_INJECTION_GET_{param}")
        
        # Check POST data
        if hasattr(request, 'POST'):
            for param, value in request.POST.items():
                for pattern in self.sql_patterns:
                    if re.search(pattern, str(value)):
                        detected_patterns.append(f"SQL_INJECTION_POST_{param}")
        
        # Check headers
        for header, value in request.META.items():
            if header.startswith('HTTP_'):
                for pattern in self.sql_patterns:
                    if re.search(pattern, str(value)):
                        detected_patterns.append(f"SQL_INJECTION_HEADER_{header}")
        
        return detected_patterns
    
    def detect_xss(self, request) -> List[str]:
        """Detect XSS attempts"""
        import re
        
        detected_patterns = []
        
        # Check query parameters
        for param, value in request.GET.items():
            for pattern in self.xss_patterns:
                if re.search(pattern, str(value)):
                    detected_patterns.append(f"XSS_GET_{param}")
        
        # Check POST data
        if hasattr(request, 'POST'):
            for param, value in request.POST.items():
                for pattern in self.xss_patterns:
                    if re.search(pattern, str(value)):
                        detected_patterns.append(f"XSS_POST_{param}")
        
        return detected_patterns
    
    def detect_path_traversal(self, request) -> bool:
        """Detect path traversal attempts"""
        import re
        
        # Check URL path
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, request.path):
                return True
        
        # Check query parameters
        for param, value in request.GET.items():
            for pattern in self.path_traversal_patterns:
                if re.search(pattern, str(value)):
                    return True
        
        return False
    
    def detect_command_injection(self, request) -> bool:
        """Detect command injection attempts"""
        import re
        
        # Check query parameters
        for param, value in request.GET.items():
            for pattern in self.command_patterns:
                if re.search(pattern, str(value)):
                    return True
        
        # Check POST data
        if hasattr(request, 'POST'):
            for param, value in request.POST.items():
                for pattern in self.command_patterns:
                    if re.search(pattern, str(value)):
                        return True
        
        return False


# Management API Views

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(staff_member_required, name='dispatch')
class SecurityMonitoringAPIView(View):
    """API for security monitoring management"""
    
    def get(self, request):
        """Get monitoring status"""
        try:
            security_monitor = get_security_monitor()
            event_streamer = get_event_streamer()
            
            status = {
                'monitoring': security_monitor.get_system_status(),
                'streaming': event_streamer.get_streaming_status(),
                'timestamp': timezone.now().isoformat()
            }
            
            return JsonResponse(status)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    def post(self, request):
        """Control monitoring system"""
        try:
            data = json.loads(request.body)
            action = data.get('action')
            
            security_monitor = get_security_monitor()
            
            if action == 'start':
                security_monitor.start_monitoring()
                return JsonResponse({'message': 'Monitoring started'})
            elif action == 'stop':
                security_monitor.stop_monitoring()
                return JsonResponse({'message': 'Monitoring stopped'})
            elif action == 'restart':
                security_monitor.stop_monitoring()
                security_monitor.start_monitoring()
                return JsonResponse({'message': 'Monitoring restarted'})
            else:
                return JsonResponse({'error': 'Invalid action'}, status=400)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@csrf_exempt
@staff_member_required
def event_stream_status(request):
    """Get event streaming status"""
    if request.method == 'GET':
        try:
            streamer = get_event_streamer()
            status = streamer.get_streaming_status()
            return JsonResponse(status)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
@staff_member_required  
def security_events_api(request):
    """API for retrieving security events"""
    if request.method == 'GET':
        try:
            # Parse query parameters
            start_time = request.GET.get('start_time')
            end_time = request.GET.get('end_time') 
            event_types = request.GET.getlist('event_type')
            severity_min = request.GET.get('severity_min', type=int)
            limit = min(int(request.GET.get('limit', 100)), 1000)
            
            security_monitor = get_security_monitor()
            
            # Get events based on filters
            events = security_monitor.get_events_by_criteria(
                start_time=start_time,
                end_time=end_time,
                event_types=event_types,
                severity_min=severity_min,
                limit=limit
            )
            
            # Convert to JSON-serializable format
            events_data = [event.to_dict() for event in events]
            
            return JsonResponse({
                'events': events_data,
                'total_count': len(events_data),
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
@staff_member_required
def threat_intelligence_api(request):
    """API for threat intelligence data"""
    if request.method == 'GET':
        try:
            intelligence = get_security_intelligence()
            
            # Get latest threat intelligence
            threat_data = intelligence.get_threat_intelligence_summary()
            
            return JsonResponse({
                'threat_intelligence': threat_data,
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
@staff_member_required
def security_metrics_api(request):
    """API for security metrics"""
    if request.method == 'GET':
        try:
            security_monitor = get_security_monitor()
            
            # Get comprehensive metrics
            metrics = security_monitor.get_security_metrics()
            
            return JsonResponse({
                'metrics': metrics,
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


def security_dashboard_view(request):
    """Security dashboard view"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    try:
        # Get dashboard data
        security_monitor = get_security_monitor()
        event_streamer = get_event_streamer()
        
        dashboard_data = {
            'monitoring_status': security_monitor.get_system_status(),
            'streaming_status': event_streamer.get_streaming_status(),
            'recent_events': [event.to_dict() for event in security_monitor.get_recent_events(50)],
            'security_metrics': security_monitor.get_security_metrics(),
        }
        
        return JsonResponse(dashboard_data)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Utility functions for monitoring management

def enable_security_monitoring():
    """Enable security monitoring"""
    try:
        security_monitor = get_security_monitor()
        security_monitor.start_monitoring()
        monitor_logger.info("Security monitoring enabled")
        return True
    except Exception as e:
        monitor_logger.error(f"Failed to enable security monitoring: {str(e)}")
        return False


def disable_security_monitoring():
    """Disable security monitoring"""
    try:
        security_monitor = get_security_monitor()
        security_monitor.stop_monitoring()
        monitor_logger.info("Security monitoring disabled")
        return True
    except Exception as e:
        monitor_logger.error(f"Failed to disable security monitoring: {str(e)}")
        return False


def restart_security_monitoring():
    """Restart security monitoring"""
    try:
        security_monitor = get_security_monitor()
        security_monitor.stop_monitoring()
        security_monitor.start_monitoring()
        monitor_logger.info("Security monitoring restarted")
        return True
    except Exception as e:
        monitor_logger.error(f"Failed to restart security monitoring: {str(e)}")
        return False