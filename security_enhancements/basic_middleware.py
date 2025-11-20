"""
Minimal Security Headers Middleware
Provides basic security headers without aggressive content filtering
"""
from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger(__name__)


class BasicSecurityHeadersMiddleware(MiddlewareMixin):
    """
    Basic security headers middleware without content filtering
    Only adds essential security headers
    """
    
    def process_response(self, request, response):
        """Add basic security headers to response"""
        
        # Basic security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Only add HSTS in production with HTTPS
        if not getattr(request, 'is_secure', lambda: False)():
            pass  # Skip HSTS for non-HTTPS
        else:
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response


class MinimalCSPMiddleware(MiddlewareMixin):
    """
    Minimal Content Security Policy middleware
    Allows necessary resources for the admin health report
    """
    
    def process_response(self, request, response):
        """Add minimal CSP header"""
        
        # Very permissive CSP for development/admin functionality
        csp_policy = (
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: blob: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        response['Content-Security-Policy'] = csp_policy
        return response