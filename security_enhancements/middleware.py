"""
Advanced Threat Monitoring Middleware for HealthProgress
Implements real-time threat detection and response
"""
from django.core.cache import cache
from django.http import HttpResponseForbidden, JsonResponse
from django.utils import timezone
from django.conf import settings
import logging
import re
import hashlib
from datetime import timedelta
from accounts.models import UserActivity

logger = logging.getLogger('security')


class ThreatMonitoringMiddleware:
    """
    Advanced threat detection and monitoring middleware
    
    Detects and blocks:
    - SQL injection attempts
    - XSS attacks
    - Path traversal attacks
    - Command injection
    - Suspicious user agents
    - Automated attack tools
    - Rate limit violations
    - Brute force attempts
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Malicious pattern detection
        self.sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
            r"UNION.*SELECT",
            r"INSERT.*INTO",
            r"DELETE.*FROM",
            r"DROP.*TABLE",
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<iframe",
            r"<embed",
            r"<object",
        ]
        
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.",
            r"%2e%2e",
            r"\.\.\\",
        ]
        
        self.command_injection_patterns = [
            r";\s*(ls|cat|wget|curl|nc|bash|sh)",
            r"\|\s*(ls|cat|wget|curl|nc|bash|sh)",
            r"`.*`",
            r"\$\(.*\)",
        ]
        
        # Suspicious user agents (attack tools)
        self.suspicious_agents = [
            'nikto', 'sqlmap', 'nmap', 'masscan', 'nessus',
            'burp', 'zap', 'metasploit', 'hydra', 'dirbuster',
            'acunetix', 'appscan', 'w3af', 'havij', 'pangolin'
        ]
    
    def __call__(self, request):
        # Skip static files
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return self.get_response(request)
        
        # Get client IP
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(f'Blocked IP attempted access: {ip_address}', extra={
                'ip': ip_address,
                'path': request.path,
                'severity': 'HIGH'
            })
            return HttpResponseForbidden('Access denied - IP blocked')
        
        # Check for malicious patterns
        threat_detected, threat_type = self.detect_threats(request)
        
        if threat_detected:
            self.handle_threat(request, ip_address, threat_type)
            
            logger.error(f'Threat detected: {threat_type}', extra={
                'ip': ip_address,
                'path': request.path,
                'method': request.method,
                'threat_type': threat_type,
                'severity': 'CRITICAL',
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200]
            })
            
            return JsonResponse({
                'error': 'Security violation detected',
                'message': 'Your request has been logged and blocked',
                'incident_id': self.generate_incident_id(request, threat_type)
            }, status=403)
        
        # Check for suspicious user agent
        if self.is_suspicious_user_agent(request):
            logger.warning(f'Suspicious user agent detected', extra={
                'ip': ip_address,
                'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
                'severity': 'MEDIUM'
            })
            
            # Track but don't block (could be false positive)
            self.increment_suspicion_score(ip_address, 5)
        
        # Rate limiting check
        if self.is_rate_limited(request, ip_address):
            logger.warning(f'Rate limit exceeded', extra={
                'ip': ip_address,
                'path': request.path,
                'severity': 'MEDIUM'
            })
            return JsonResponse({
                'error': 'Too many requests',
                'message': 'Please slow down'
            }, status=429)
        
        # Process request
        response = self.get_response(request)
        
        # Log successful requests (for analytics)
        if request.user.is_authenticated:
            self.log_request(request, response, ip_address)
        
        return response
    
    def get_client_ip(self, request):
        """Get real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
    
    def is_ip_blocked(self, ip_address):
        """Check if IP is in blocklist"""
        try:
            from security_enhancements.models import IPBlocklist
            return IPBlocklist.objects.filter(
                ip_address=ip_address,
                is_active=True
            ).exists()
        except:
            return False
    
    def detect_threats(self, request):
        """Detect malicious patterns in request"""
        # Get request data
        query_string = request.META.get('QUERY_STRING', '')
        path = request.path
        
        # Check POST data
        post_data = ''
        if request.method == 'POST':
            try:
                post_data = str(request.POST)
            except:
                pass
        
        # Combine all data for pattern matching
        data_to_check = f"{query_string} {path} {post_data}".lower()
        
        # Check SQL injection patterns
        for pattern in self.sql_patterns:
            if re.search(pattern, data_to_check, re.IGNORECASE):
                return True, 'SQL_INJECTION'
        
        # Check XSS patterns
        for pattern in self.xss_patterns:
            if re.search(pattern, data_to_check, re.IGNORECASE):
                return True, 'XSS_ATTACK'
        
        # Check path traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, data_to_check, re.IGNORECASE):
                return True, 'PATH_TRAVERSAL'
        
        # Check command injection
        for pattern in self.command_injection_patterns:
            if re.search(pattern, data_to_check, re.IGNORECASE):
                return True, 'COMMAND_INJECTION'
        
        return False, None
    
    def is_suspicious_user_agent(self, request):
        """Check for known attack tool user agents"""
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        
        for tool in self.suspicious_agents:
            if tool in user_agent:
                return True
        
        return False
    
    def is_rate_limited(self, request, ip_address):
        """
        Rate limiting per IP address
        - 100 requests per minute
        - 1000 requests per hour
        """
        # Per-minute limit
        minute_key = f"rate_limit_minute_{ip_address}"
        minute_count = cache.get(minute_key, 0)
        
        if minute_count >= 100:
            return True
        
        cache.set(minute_key, minute_count + 1, 60)  # 1 minute TTL
        
        # Per-hour limit
        hour_key = f"rate_limit_hour_{ip_address}"
        hour_count = cache.get(hour_key, 0)
        
        if hour_count >= 1000:
            return True
        
        cache.set(hour_key, hour_count + 1, 3600)  # 1 hour TTL
        
        return False
    
    def handle_threat(self, request, ip_address, threat_type):
        """Handle detected threat"""
        # Increment threat score
        threat_score = self.increment_suspicion_score(ip_address, 50)
        
        # Auto-block if score exceeds threshold
        if threat_score >= 100:
            self.auto_block_ip(ip_address, threat_type, request)
        
        # Log to database
        try:
            from security_enhancements.models import ThreatEvent
            ThreatEvent.objects.create(
                ip_address=ip_address,
                threat_type=threat_type,
                severity='CRITICAL',
                path=request.path,
                method=request.method,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                query_string=request.META.get('QUERY_STRING', '')[:500],
                blocked=True,
                timestamp=timezone.now()
            )
        except Exception as e:
            logger.error(f'Failed to log threat event: {e}')
    
    def increment_suspicion_score(self, ip_address, points):
        """Track suspicion score for IP"""
        score_key = f"suspicion_score_{ip_address}"
        current_score = cache.get(score_key, 0)
        new_score = current_score + points
        
        # Store for 24 hours
        cache.set(score_key, new_score, 86400)
        
        return new_score
    
    def auto_block_ip(self, ip_address, reason, request):
        """Automatically block malicious IP"""
        try:
            from security_enhancements.models import IPBlocklist
            
            # Check if already blocked
            if not IPBlocklist.objects.filter(ip_address=ip_address, is_active=True).exists():
                IPBlocklist.objects.create(
                    ip_address=ip_address,
                    reason=f'Auto-blocked: {reason}',
                    blocked_by=None,  # System auto-block
                    is_active=True,
                    notes=f'Auto-blocked due to threat score. Path: {request.path}'
                )
                
                logger.critical(f'Auto-blocked IP: {ip_address}', extra={
                    'ip': ip_address,
                    'reason': reason,
                    'severity': 'CRITICAL'
                })
        except Exception as e:
            logger.error(f'Failed to auto-block IP: {e}')
    
    def generate_incident_id(self, request, threat_type):
        """Generate unique incident ID"""
        import time
        import secrets
        
        timestamp = int(time.time())
        random_part = secrets.token_hex(4)
        
        return f"{threat_type}_{timestamp}_{random_part}"
    
    def log_request(self, request, response, ip_address):
        """Log successful authenticated requests for analytics"""
        # Only log to cache for performance monitoring
        # Detailed logs go to file via Django logging
        
        # Track requests per user
        if request.user.is_authenticated:
            user_key = f"user_requests_{request.user.id}"
            user_count = cache.get(user_key, 0)
            cache.set(user_key, user_count + 1, 3600)  # 1 hour


class SecurityHeadersMiddleware:
    """
    Add comprehensive security headers to all responses
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Content Security Policy
        if not getattr(settings, 'DEBUG', True):  # Only in production
            csp = (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
                "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https://cdn.jsdelivr.net; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
            response['Content-Security-Policy'] = csp
        
        return response


class RequestLoggingMiddleware:
    """
    Comprehensive request logging for security analytics
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger('security.requests')
    
    def __call__(self, request):
        # Record start time
        import time
        start_time = time.time()
        
        # Process request
        response = self.get_response(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log request details
        if request.user.is_authenticated:
            self.logger.info(
                f'{request.method} {request.path}',
                extra={
                    'user_id': request.user.id,
                    'username': request.user.username,
                    'ip': self.get_client_ip(request),
                    'status_code': response.status_code,
                    'duration': f'{duration:.3f}s',
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200]
                }
            )
        
        return response
    
    def get_client_ip(self, request):
        """Get real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
