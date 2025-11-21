"""
OWASP Django Security Hardening Implementation
Comprehensive security implementation following OWASP Top 10 and Django Security Guidelines
"""

from django.conf import settings
from django.core.exceptions import ValidationError, SuspiciousOperation
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver
from django.urls import resolve
from django.utils import timezone
from django.contrib.auth import get_user_model
import logging
import re
import json
import hashlib
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
import ipaddress
from typing import Dict, List, Optional, Set
import bleach
from html import escape
import secrets
import base64

# Configure logging
logger = logging.getLogger('security_enhancements')
security_logger = logging.getLogger('django.security')

User = get_user_model()

class OWASPSecurityMiddleware(MiddlewareMixin):
    """
    Comprehensive OWASP security middleware implementing:
    - A01: Broken Access Control
    - A02: Cryptographic Failures  
    - A03: Injection
    - A04: Insecure Design
    - A05: Security Misconfiguration
    - A06: Vulnerable and Outdated Components
    - A07: Identification and Authentication Failures
    - A08: Software and Data Integrity Failures
    - A09: Security Logging and Monitoring Failures
    - A10: Server-Side Request Forgery (SSRF)
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.blocked_ips = set()
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.rate_limits = {}
        super().__init__(get_response)
    
    def _load_suspicious_patterns(self) -> List[re.Pattern]:
        """Load patterns for detecting suspicious requests"""
        patterns = [
            # SQL Injection patterns
            re.compile(r"(\'|(\\'))+.*(\\').*(\'|(\\'))", re.IGNORECASE),
            re.compile(r"w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
            re.compile(r"union\s+.*select", re.IGNORECASE),
            re.compile(r"select.*from", re.IGNORECASE),
            re.compile(r"insert\s+into", re.IGNORECASE),
            re.compile(r"delete\s+from", re.IGNORECASE),
            re.compile(r"update.*set", re.IGNORECASE),
            re.compile(r"drop\s+table", re.IGNORECASE),
            
            # XSS patterns
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
            re.compile(r"<iframe[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<object[^>]*>.*?</object>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<embed[^>]*>", re.IGNORECASE),
            re.compile(r"vbscript:", re.IGNORECASE),
            
            # Path traversal
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"\.\.\\", re.IGNORECASE),
            re.compile(r"%2e%2e%2f", re.IGNORECASE),
            re.compile(r"%2e%2e\\", re.IGNORECASE),
            
            # Command injection
            re.compile(r"[;&|`]", re.IGNORECASE),
            re.compile(r"\$\(", re.IGNORECASE),
            re.compile(r"`.*`", re.IGNORECASE),
            
            # LDAP injection
            re.compile(r"[*()\\&|!>=<~]", re.IGNORECASE),
            
            # XXE patterns
            re.compile(r"<!entity", re.IGNORECASE),
            re.compile(r"system\s+\"", re.IGNORECASE),
            
            # SSRF patterns
            re.compile(r"file://", re.IGNORECASE),
            re.compile(r"ftp://", re.IGNORECASE),
            re.compile(r"gopher://", re.IGNORECASE),
            re.compile(r"dict://", re.IGNORECASE),
            
            # Template injection
            re.compile(r"\{\{.*\}\}", re.IGNORECASE),
            re.compile(r"\{%.*%\}", re.IGNORECASE),
        ]
        return patterns
    
    def process_request(self, request):
        """Process incoming request for security threats"""
        client_ip = self._get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            security_logger.warning(
                f"Blocked IP {client_ip} attempted access",
                extra={'ip': client_ip, 'path': request.path}
            )
            return HttpResponse('Access Denied', status=403)
        
        # Rate limiting
        if self._is_rate_limited(client_ip, request.path):
            self._increment_suspicious_activity(client_ip)
            return HttpResponse('Rate Limit Exceeded', status=429)
        
        # Check for suspicious patterns in request
        if self._detect_malicious_patterns(request):
            self._handle_suspicious_request(request, client_ip)
            return HttpResponse('Bad Request', status=400)
        
        # Validate request size
        if self._check_request_size(request):
            security_logger.warning(
                f"Large request from {client_ip}: {len(request.body)} bytes",
                extra={'ip': client_ip, 'size': len(request.body)}
            )
            return HttpResponseBadRequest('Request too large')
        
        # Add security headers to request context
        request.security_context = {
            'client_ip': client_ip,
            'request_id': secrets.token_urlsafe(16),
            'timestamp': timezone.now()
        }
        
        return None
    
    def process_response(self, request, response):
        """Add comprehensive security headers to response"""
        
        # Core security headers
        security_headers = {
            # Prevent MIME type sniffing
            'X-Content-Type-Options': 'nosniff',
            
            # Prevent clickjacking
            'X-Frame-Options': 'DENY',
            
            # XSS Protection (legacy but still useful)
            'X-XSS-Protection': '1; mode=block',
            
            # Referrer Policy
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            
            # Remove server information
            'Server': 'Web Server',
            
            # Prevent caching of sensitive content
            'Cache-Control': 'no-cache, no-store, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0',
            
            # Content Security Policy
            'Content-Security-Policy': self._generate_csp_header(request),
            
            # Feature Policy / Permissions Policy
            'Permissions-Policy': (
                'geolocation=(), '
                'microphone=(), '
                'camera=(), '
                'payment=(), '
                'usb=(), '
                'magnetometer=(), '
                'gyroscope=(), '
                'speaker=(), '
                'vibrate=(), '
                'fullscreen=(self), '
                'sync-xhr=()'
            ),
            
            # Cross-Origin policies
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
        }
        
        # HTTPS-only headers
        if request.is_secure():
            security_headers.update({
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
                'Expect-CT': 'max-age=86400, enforce'
            })
        
        # Apply headers to response
        for header, value in security_headers.items():
            response[header] = value
        
        # Add security response headers
        self._add_security_response_headers(request, response)
        
        return response
    
    def _get_client_ip(self, request) -> str:
        """Get real client IP address"""
        # Check for forwarded headers (be careful with these in production)
        forwarded_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_X_CLIENT_IP',
            'HTTP_CF_CONNECTING_IP',  # Cloudflare
            'REMOTE_ADDR'
        ]
        
        for header in forwarded_headers:
            ip = request.META.get(header)
            if ip:
                # Handle comma-separated IPs (X-Forwarded-For)
                ip = ip.split(',')[0].strip()
                if self._is_valid_ip(ip):
                    return ip
        
        return request.META.get('REMOTE_ADDR', 'unknown')
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_rate_limited(self, client_ip: str, path: str) -> bool:
        """Check if request should be rate limited"""
        current_time = time.time()
        key = f"rate_limit:{client_ip}:{path}"
        
        # Get current count and timestamp
        rate_data = cache.get(key, {'count': 0, 'window_start': current_time})
        
        # Reset window if needed (60 second window)
        if current_time - rate_data['window_start'] > 60:
            rate_data = {'count': 1, 'window_start': current_time}
        else:
            rate_data['count'] += 1
        
        # Store updated count
        cache.set(key, rate_data, 60)
        
        # Rate limit thresholds
        rate_limits = {
            '/accounts/login/': 5,     # Login attempts
            '/accounts/register/': 3,   # Registration attempts
            '/admin/': 10,             # Admin access
            'default': 100             # General requests
        }
        
        limit = rate_limits.get(path, rate_limits['default'])
        return rate_data['count'] > limit
    
    def _detect_malicious_patterns(self, request) -> bool:
        """Detect malicious patterns in request"""
        # Check URL parameters
        for param_name, param_value in request.GET.items():
            if self._contains_malicious_pattern(str(param_value)):
                security_logger.warning(
                    f"Malicious pattern in GET parameter: {param_name}",
                    extra={'ip': self._get_client_ip(request), 'param': param_name}
                )
                return True
        
        # Check POST data
        if hasattr(request, 'POST'):
            for field_name, field_value in request.POST.items():
                if self._contains_malicious_pattern(str(field_value)):
                    security_logger.warning(
                        f"Malicious pattern in POST field: {field_name}",
                        extra={'ip': self._get_client_ip(request), 'field': field_name}
                    )
                    return True
        
        # Check request headers
        suspicious_headers = ['User-Agent', 'Referer', 'X-Requested-With']
        for header in suspicious_headers:
            value = request.META.get(f'HTTP_{header.upper().replace("-", "_")}', '')
            if self._contains_malicious_pattern(value):
                security_logger.warning(
                    f"Malicious pattern in header: {header}",
                    extra={'ip': self._get_client_ip(request), 'header': header}
                )
                return True
        
        # Check request path
        if self._contains_malicious_pattern(request.path):
            security_logger.warning(
                f"Malicious pattern in path: {request.path}",
                extra={'ip': self._get_client_ip(request)}
            )
            return True
        
        return False
    
    def _contains_malicious_pattern(self, text: str) -> bool:
        """Check if text contains malicious patterns"""
        if not text:
            return False
        
        for pattern in self.suspicious_patterns:
            if pattern.search(text):
                return True
        return False
    
    def _check_request_size(self, request) -> bool:
        """Check if request exceeds size limits"""
        max_size = getattr(settings, 'MAX_REQUEST_SIZE', 10 * 1024 * 1024)  # 10MB default
        
        if hasattr(request, 'body') and len(request.body) > max_size:
            return True
        
        return False
    
    def _handle_suspicious_request(self, request, client_ip: str):
        """Handle suspicious request detection"""
        self._increment_suspicious_activity(client_ip)
        
        # Log security event
        security_logger.error(
            f"Suspicious request detected from {client_ip}",
            extra={
                'ip': client_ip,
                'path': request.path,
                'method': request.method,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'referer': request.META.get('HTTP_REFERER', ''),
            }
        )
    
    def _increment_suspicious_activity(self, client_ip: str):
        """Track suspicious activity and auto-block if needed"""
        key = f"suspicious:{client_ip}"
        count = cache.get(key, 0) + 1
        cache.set(key, count, 3600)  # 1 hour window
        
        # Auto-block after 5 suspicious activities
        if count >= 5:
            self.blocked_ips.add(client_ip)
            security_logger.critical(
                f"Auto-blocked IP {client_ip} due to repeated suspicious activity",
                extra={'ip': client_ip, 'count': count}
            )
    
    def _generate_csp_header(self, request) -> str:
        """Generate Content Security Policy header"""
        # Base CSP policy
        csp_directives = {
            "default-src": ["'self'"],
            "script-src": [
                "'self'",
                "'unsafe-inline'",  # Consider removing in production
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com"
            ],
            "style-src": [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdn.jsdelivr.net"
            ],
            "img-src": [
                "'self'",
                "data:",
                "https:"
            ],
            "font-src": [
                "'self'",
                "https://fonts.gstatic.com",
                "data:"
            ],
            "connect-src": ["'self'"],
            "frame-src": ["'none'"],
            "object-src": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "frame-ancestors": ["'none'"],
            "upgrade-insecure-requests": []
        }
        
        # Build CSP string
        csp_parts = []
        for directive, sources in csp_directives.items():
            if sources:
                csp_parts.append(f"{directive} {' '.join(sources)}")
            else:
                csp_parts.append(directive)
        
        return "; ".join(csp_parts)
    
    def _add_security_response_headers(self, request, response):
        """Add additional security response headers"""
        # Add request tracking header
        if hasattr(request, 'security_context'):
            response['X-Request-ID'] = request.security_context['request_id']
        
        # Remove sensitive server headers
        headers_to_remove = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in headers_to_remove:
            if header in response:
                del response[header]


class InputSanitizationMiddleware(MiddlewareMixin):
    """
    OWASP A03: Injection Prevention
    Sanitizes all user inputs to prevent injection attacks
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Sanitize request data"""
        # Sanitize GET parameters
        if request.GET:
            sanitized_get = {}
            for key, value in request.GET.items():
                sanitized_get[key] = self._sanitize_input(value)
            request.GET = sanitized_get
        
        # Sanitize POST data
        if hasattr(request, 'POST') and request.POST:
            sanitized_post = {}
            for key, value in request.POST.items():
                if key != 'csrfmiddlewaretoken':  # Don't sanitize CSRF token
                    sanitized_post[key] = self._sanitize_input(value)
                else:
                    sanitized_post[key] = value
            request.POST = sanitized_post
        
        return None
    
    def _sanitize_input(self, value):
        """Sanitize individual input value"""
        if not isinstance(value, str):
            return value
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # HTML escape
        value = escape(value)
        
        # Additional sanitization using bleach
        allowed_tags = ['b', 'i', 'u', 'em', 'strong']  # Very restrictive
        allowed_attributes = {}
        
        value = bleach.clean(
            value,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        return value


class AuthenticationSecurityMiddleware(MiddlewareMixin):
    """
    OWASP A07: Identification and Authentication Failures Prevention
    Enhanced authentication security
    """
    
    def process_request(self, request):
        """Process authentication security"""
        if request.user.is_authenticated:
            # Check for session fixation
            if self._detect_session_fixation(request):
                security_logger.warning(
                    f"Session fixation attempt detected for user {request.user.username}",
                    extra={'user': request.user.username, 'ip': self._get_client_ip(request)}
                )
                request.session.cycle_key()
            
            # Update last activity
            self._update_last_activity(request)
            
            # Check for concurrent sessions
            self._check_concurrent_sessions(request)
        
        return None
    
    def _detect_session_fixation(self, request) -> bool:
        """Detect potential session fixation attacks"""
        # Check if session key has changed without logout
        session_key = request.session.session_key
        stored_key = request.session.get('_session_key')
        
        if stored_key and stored_key != session_key:
            return True
        
        # Store current session key
        request.session['_session_key'] = session_key
        return False
    
    def _update_last_activity(self, request):
        """Update user's last activity timestamp"""
        request.session['last_activity'] = timezone.now().isoformat()
    
    def _check_concurrent_sessions(self, request):
        """Check for suspicious concurrent sessions"""
        # Implementation would depend on your session management strategy
        pass
    
    def _get_client_ip(self, request) -> str:
        """Get client IP address"""
        return request.META.get('HTTP_X_FORWARDED_FOR', 
                              request.META.get('REMOTE_ADDR', 'unknown')).split(',')[0].strip()


class DataProtectionMiddleware(MiddlewareMixin):
    """
    OWASP A02: Cryptographic Failures Prevention
    Data protection and encryption middleware
    """
    
    def process_response(self, request, response):
        """Ensure sensitive data is properly protected"""
        
        # Add headers for sensitive data protection
        if self._is_sensitive_endpoint(request.path):
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
        
        # Check for sensitive data in response
        if hasattr(response, 'content'):
            self._check_sensitive_data_exposure(response)
        
        return response
    
    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint handles sensitive data"""
        sensitive_paths = [
            '/accounts/',
            '/admin/',
            '/health/',
            '/api/',
        ]
        return any(path.startswith(p) for p in sensitive_paths)
    
    def _check_sensitive_data_exposure(self, response):
        """Check for accidental sensitive data exposure"""
        if not hasattr(response, 'content'):
            return
        
        content = response.content.decode('utf-8', errors='ignore').lower()
        
        # Check for common sensitive patterns
        sensitive_patterns = [
            r'password\s*[:=]\s*["\']?[^"\'\s]{8,}',
            r'api[_-]?key\s*[:=]\s*["\']?[a-z0-9]{20,}',
            r'secret[_-]?key\s*[:=]\s*["\']?[a-z0-9]{20,}',
            r'token\s*[:=]\s*["\']?[a-z0-9]{20,}',
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                security_logger.warning(
                    "Potential sensitive data exposure detected in response",
                    extra={'pattern': pattern}
                )


# Login attempt tracking
@receiver(user_login_failed)
def handle_failed_login(sender, credentials, request, **kwargs):
    """Handle failed login attempts"""
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR', 
                                request.META.get('REMOTE_ADDR', 'unknown')).split(',')[0].strip()
    
    # Track failed attempts
    key = f"failed_login:{ip_address}"
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, 300)  # 5 minute window
    
    # Log security event
    security_logger.warning(
        f"Failed login attempt #{attempts} from {ip_address}",
        extra={
            'ip': ip_address,
            'username': credentials.get('username', 'unknown'),
            'attempts': attempts
        }
    )
    
    # Temporary lockout after 5 failed attempts
    if attempts >= 5:
        cache.set(f"lockout:{ip_address}", True, 900)  # 15 minute lockout
        security_logger.error(
            f"IP {ip_address} temporarily locked out due to failed login attempts",
            extra={'ip': ip_address, 'attempts': attempts}
        )


class SecurityUtils:
    """Security utility functions"""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_sensitive_data(data: str) -> str:
        """Hash sensitive data for logging"""
        return hashlib.sha256(data.encode()).hexdigest()[:16] + "..."
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL to prevent SSRF attacks"""
        try:
            parsed = urlparse(url)
            
            # Block dangerous schemes
            dangerous_schemes = ['file', 'ftp', 'gopher', 'dict', 'ldap']
            if parsed.scheme.lower() in dangerous_schemes:
                return False
            
            # Block internal IP ranges
            if parsed.hostname:
                try:
                    ip = ipaddress.ip_address(parsed.hostname)
                    if ip.is_private or ip.is_loopback or ip.is_multicast:
                        return False
                except ValueError:
                    pass  # Not an IP address
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize uploaded filename"""
        # Remove path traversal attempts
        filename = filename.replace('../', '').replace('..\\', '')
        
        # Remove null bytes and control characters
        filename = ''.join(char for char in filename if ord(char) >= 32)
        
        # Remove dangerous characters
        dangerous_chars = '<>:"|?*'
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Limit length
        if len(filename) > 100:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:95] + ('.' + ext if ext else '')
        
        return filename
    
    @staticmethod
    def validate_file_type(file_obj, allowed_types: List[str]) -> bool:
        """Validate uploaded file type"""
        try:
            import magic
            file_type = magic.from_buffer(file_obj.read(1024), mime=True)
            file_obj.seek(0)  # Reset file pointer
            
            return file_type in allowed_types
        except ImportError:
            # Fallback to extension-based checking
            filename = getattr(file_obj, 'name', '')
            if '.' not in filename:
                return False
            
            extension = filename.split('.')[-1].lower()
            allowed_extensions = {
                'image/jpeg': ['jpg', 'jpeg'],
                'image/png': ['png'],
                'image/gif': ['gif'],
                'application/pdf': ['pdf'],
                'text/plain': ['txt'],
            }
            
            for mime_type in allowed_types:
                if extension in allowed_extensions.get(mime_type, []):
                    return True
            
            return False