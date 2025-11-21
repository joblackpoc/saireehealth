"""
Real-Time Security Monitoring Middleware
Tracks all HTTP requests and security events automatically
"""

import logging
import time
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser

security_logger = logging.getLogger('security_monitoring')

class RealTimeSecurityMiddleware(MiddlewareMixin):
    """Middleware to track all requests and security events in real-time"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Track incoming requests"""
        request._security_start_time = time.time()
        
        # Get client information
        client_ip = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Track request statistics
        self._update_request_stats(request.path, client_ip, request.user)
        
        # Check for potential DDoS or brute force patterns
        self._check_rate_limiting(client_ip, request.path)
        
        # Log security-sensitive paths
        sensitive_paths = [
            '/admin/', '/accounts/admin/', '/api/', '/security/',
            '/health/api/', '/accounts/api/', '/media/', '/static/admin/'
        ]
        if any(path in request.path for path in sensitive_paths):
            self._log_sensitive_access(request, client_ip)
    
    def process_response(self, request, response):
        """Track response and performance metrics"""
        if hasattr(request, '_security_start_time'):
            response_time = time.time() - request._security_start_time
            
            # Track performance metrics
            self._update_performance_stats(response_time, response.status_code)
            
            # Log failed requests (4xx, 5xx)
            if response.status_code >= 400:
                self._log_failed_request(request, response)
            
            # Check for suspicious patterns
            if response.status_code == 404 and self._is_suspicious_404(request):
                self._log_suspicious_activity(request, self.get_client_ip(request))
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')
    
    def _update_request_stats(self, path, client_ip, user):
        """Update real-time request statistics"""
        try:
            # Get current stats
            stats = cache.get('realtime_request_stats', {
                'total_requests': 0,
                'unique_ips': set(),
                'paths': {},
                'user_requests': {},
                'last_updated': timezone.now().isoformat()
            })
            
            # Update counters
            stats['total_requests'] += 1
            stats['unique_ips'].add(client_ip)
            stats['paths'][path] = stats['paths'].get(path, 0) + 1
            
            if not isinstance(user, AnonymousUser):
                stats['user_requests'][user.username] = stats['user_requests'].get(user.username, 0) + 1
            
            stats['last_updated'] = timezone.now().isoformat()
            
            # Convert set to list for caching (sets aren't JSON serializable)
            stats_to_cache = stats.copy()
            stats_to_cache['unique_ips'] = list(stats['unique_ips'])
            
            cache.set('realtime_request_stats', stats_to_cache, 3600)  # 1 hour
            
        except Exception as e:
            security_logger.error(f"Error updating request stats: {str(e)}")
    
    def _update_performance_stats(self, response_time, status_code):
        """Update performance metrics"""
        try:
            perf_stats = cache.get('realtime_performance_stats', {
                'response_times': [],
                'status_codes': {},
                'avg_response_time': 0.0,
                'total_requests': 0
            })
            
            # Add response time (keep last 1000)
            perf_stats['response_times'].append(response_time)
            if len(perf_stats['response_times']) > 1000:
                perf_stats['response_times'] = perf_stats['response_times'][-1000:]
            
            # Update status code counts
            perf_stats['status_codes'][str(status_code)] = perf_stats['status_codes'].get(str(status_code), 0) + 1
            
            # Calculate average response time
            if perf_stats['response_times']:
                perf_stats['avg_response_time'] = sum(perf_stats['response_times']) / len(perf_stats['response_times'])
            
            perf_stats['total_requests'] += 1
            
            cache.set('realtime_performance_stats', perf_stats, 3600)
            
        except Exception as e:
            security_logger.error(f"Error updating performance stats: {str(e)}")
    
    def _log_sensitive_access(self, request, client_ip):
        """Log access to sensitive paths"""
        try:
            from security_enhancements.security_audit import SecurityAuditTracker, SecurityEventTypes, SecurityEventSeverity
            
            SecurityAuditTracker.log_security_event(
                SecurityEventTypes.DATA_ACCESS,
                f'Access to sensitive path: {request.path}',
                user=request.user if not isinstance(request.user, AnonymousUser) else None,
                ip_address=client_ip,
                severity=SecurityEventSeverity.MEDIUM,
                additional_data={
                    'path': request.path,
                    'method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:100]
                }
            )
        except ImportError:
            pass
        except Exception as e:
            security_logger.error(f"Error logging sensitive access: {str(e)}")
    
    def _log_failed_request(self, request, response):
        """Log failed requests for security monitoring"""
        try:
            from security_enhancements.security_audit import SecurityAuditTracker, SecurityEventTypes, SecurityEventSeverity
            
            severity = SecurityEventSeverity.HIGH if response.status_code >= 500 else SecurityEventSeverity.MEDIUM
            
            SecurityAuditTracker.log_security_event(
                SecurityEventTypes.SYSTEM_ERROR if response.status_code >= 500 else SecurityEventTypes.PERMISSION_DENIED,
                f'HTTP {response.status_code} error on {request.path}',
                user=request.user if not isinstance(request.user, AnonymousUser) else None,
                ip_address=self.get_client_ip(request),
                severity=severity,
                additional_data={
                    'status_code': response.status_code,
                    'path': request.path,
                    'method': request.method
                }
            )
        except ImportError:
            pass
        except Exception as e:
            security_logger.error(f"Error logging failed request: {str(e)}")
    
    def _check_rate_limiting(self, client_ip, path):
        """Check for potential rate limiting violations"""
        try:
            # Track requests per IP per minute
            cache_key = f"rate_limit:{client_ip}:{int(time.time() // 60)}"
            current_count = cache.get(cache_key, 0)
            
            if current_count > 100:  # More than 100 requests per minute
                self._log_rate_limit_violation(client_ip, current_count)
            
            cache.set(cache_key, current_count + 1, 60)  # 60 second TTL
            
        except Exception as e:
            security_logger.error(f"Error checking rate limit: {str(e)}")
    
    def _is_suspicious_404(self, request):
        """Detect suspicious 404 patterns that might indicate scanning"""
        suspicious_patterns = [
            '.php', '.asp', '.aspx', '.jsp', '.cgi',
            'wp-admin', 'phpmyadmin', 'admin.php',
            '.env', '.git', '.svn', 'backup',
            'xmlrpc', 'wp-content', 'wp-includes'
        ]
        
        path = request.path.lower()
        return any(pattern in path for pattern in suspicious_patterns)
    
    def _log_rate_limit_violation(self, client_ip, request_count):
        """Log potential DDoS or brute force attempt"""
        try:
            from security_enhancements.security_audit import SecurityAuditTracker
            
            SecurityAuditTracker.log_security_event(
                'RATE_LIMIT_VIOLATION',
                f'High request rate detected from IP: {client_ip}',
                ip_address=client_ip,
                severity='HIGH',
                additional_data={
                    'request_count_per_minute': request_count,
                    'detection_time': timezone.now().isoformat()
                }
            )
        except Exception as e:
            security_logger.error(f"Error logging rate limit violation: {str(e)}")
    
    def _log_suspicious_activity(self, request, client_ip):
        """Log suspicious 404 activity that might indicate scanning"""
        try:
            from security_enhancements.security_audit import SecurityAuditTracker
            
            SecurityAuditTracker.log_security_event(
                'SUSPICIOUS_SCANNING',
                f'Potential vulnerability scanning detected',
                ip_address=client_ip,
                severity='MEDIUM',
                additional_data={
                    'requested_path': request.path,
                    'method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:100]
                }
            )
        except Exception as e:
            security_logger.error(f"Error logging suspicious activity: {str(e)}")


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Add security headers to all responses"""
    
    def process_response(self, request, response):
        """Add security headers"""
        # Security headers for protection
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
        
        # Only add HSTS on HTTPS connections
        if request.is_secure():  # HTTPS only
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        return response