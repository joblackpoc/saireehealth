"""
Optimized Security Middleware for Health Progress
Reduced false positives while maintaining protection
"""
import re
import json
from typing import Optional
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from .models import SecurityEvent
from .health_security_config import (
    HEALTH_REPORT_WHITELIST_PATTERNS,
    REDUCED_SENSITIVITY_PATHS, 
    HEALTH_APP_SQL_OVERRIDES
)


class OptimizedSecurityMiddleware(MiddlewareMixin):
    """
    Security middleware optimized for health app functionality
    Reduces false positives while maintaining security
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.whitelist_patterns = [re.compile(pattern, re.IGNORECASE) 
                                 for pattern in HEALTH_REPORT_WHITELIST_PATTERNS]
        self.reduced_sensitivity_paths = [re.compile(pattern) 
                                        for pattern in REDUCED_SENSITIVITY_PATHS]
        
        # Only the most critical SQL injection patterns
        self.critical_sql_patterns = [
            re.compile(r'\'\s*;\s*DROP\s+TABLE', re.IGNORECASE),
            re.compile(r'\'\s*;\s*DELETE\s+FROM', re.IGNORECASE),
            re.compile(r'UNION\s+SELECT.*--', re.IGNORECASE),
            re.compile(r'\'\s*OR\s*\'1\'\s*=\s*\'1\'\s*--', re.IGNORECASE),
            re.compile(r'xp_cmdshell', re.IGNORECASE),
            re.compile(r'sp_executesql', re.IGNORECASE),
        ]
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process request with optimized security checks"""
        
        # Skip static files and common paths
        skip_paths = ['/static/', '/media/', '/favicon.ico', '/robots.txt', '/admin/jsi18n/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Check if this is a reduced sensitivity path
        is_reduced_sensitivity = any(pattern.search(request.path) 
                                   for pattern in self.reduced_sensitivity_paths)
        
        # Get request data
        request_data = self._get_request_data(request)
        
        # Only check for critical threats on admin paths
        if is_reduced_sensitivity:
            threat_detected = self._check_critical_threats_only(request_data, request)
        else:
            threat_detected = self._check_all_threats(request_data, request)
        
        if threat_detected:
            return self._handle_threat(request, threat_detected)
        
        return None
    
    def _get_request_data(self, request: HttpRequest) -> str:
        """Extract request data for analysis"""
        data_parts = []
        
        # GET parameters
        if request.GET:
            data_parts.append(request.GET.urlencode())
        
        # POST data
        if request.method == 'POST' and hasattr(request, 'POST'):
            data_parts.append(request.POST.urlencode())
        
        # Headers (only suspicious ones)
        suspicious_headers = ['user-agent', 'referer', 'x-forwarded-for']
        for header in suspicious_headers:
            header_value = request.META.get(f'HTTP_{header.upper().replace("-", "_")}', '')
            if header_value:
                data_parts.append(header_value)
        
        return ' '.join(data_parts).lower()
    
    def _check_critical_threats_only(self, data: str, request: HttpRequest) -> Optional[dict]:
        """Check only for critical SQL injection attempts"""
        
        # Skip if data contains whitelisted patterns
        if any(pattern.search(data) for pattern in self.whitelist_patterns):
            return None
        
        # Check critical SQL patterns
        for pattern in self.critical_sql_patterns:
            if pattern.search(data):
                return {
                    'type': 'CRITICAL_SQL_INJECTION',
                    'pattern': pattern.pattern,
                    'severity': 'CRITICAL'
                }
        
        return None
    
    def _check_all_threats(self, data: str, request: HttpRequest) -> Optional[dict]:
        """Check for all threats on non-admin paths"""
        
        # Check for obvious XSS
        xss_patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
        ]
        
        for pattern in xss_patterns:
            if pattern.search(data):
                return {
                    'type': 'XSS_ATTACK',
                    'pattern': pattern.pattern,
                    'severity': 'HIGH'
                }
        
        # Check critical SQL patterns
        return self._check_critical_threats_only(data, request)
    
    def _handle_threat(self, request: HttpRequest, threat_info: dict) -> HttpResponse:
        """Handle detected threat"""
        
        try:
            # Log the security event
            SecurityEvent.objects.create(
                event_type=threat_info['type'],
                severity=threat_info['severity'],
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                user=request.user if request.user.is_authenticated else None,
                path=request.path,
                method=request.method,
                payload=str(request.POST) if request.method == 'POST' else str(request.GET),
            )
        except Exception as e:
            # If logging fails, don't block the request
            print(f"Failed to log security event: {e}")
        
        # Return appropriate response
        if request.content_type == 'application/json':
            return JsonResponse({
                'error': 'Security violation detected',
                'message': 'Your request has been logged and blocked',
                'incident_id': f'{threat_info["type"]}_{int(time.time())}'
            }, status=403)
        else:
            return HttpResponse(
                'Security violation detected. Your request has been logged.',
                status=403,
                content_type='text/plain'
            )
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get the real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip


# Import required for the middleware
import time