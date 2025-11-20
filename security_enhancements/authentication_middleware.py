"""
Phase 5: Authentication & Authorization Middleware
Advanced security middleware for authentication and authorization hardening

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
Component: Authentication Middleware Stack
"""

import json
import time
from typing import Dict, List, Optional, Tuple, Any
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from datetime import datetime, timedelta
import logging

from .authentication_hardening import (
    MultiFactorAuthentication,
    RoleBasedAccessControl,
    AdvancedSessionManager,
    OAuth2JWTSecurity,
    BiometricAuthentication,
    AccountSecurityManager
)

# Enhanced Security Logging
security_logger = logging.getLogger('security_core')

class AuthenticationHardeningMiddleware(MiddlewareMixin):
    """
    Main authentication hardening middleware
    Orchestrates all authentication security components
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.mfa = MultiFactorAuthentication()
        self.rbac = RoleBasedAccessControl()
        self.session_manager = AdvancedSessionManager()
        self.jwt_security = OAuth2JWTSecurity()
        self.biometric_auth = BiometricAuthentication()
        self.account_security = AccountSecurityManager()
        
        # Configuration
        self.enabled = getattr(settings, 'AUTHENTICATION_HARDENING_ENABLED', True)
        self.enforce_mfa = getattr(settings, 'ENFORCE_MFA', False)
        self.require_secure_sessions = getattr(settings, 'REQUIRE_SECURE_SESSIONS', True)
        self.jwt_header_name = getattr(settings, 'JWT_HEADER_NAME', 'Authorization')
        
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
            
        # Pre-processing: Authentication checks
        auth_result = self.process_authentication(request)
        if isinstance(auth_result, HttpResponse):
            return auth_result
        
        response = self.get_response(request)
        
        # Post-processing: Security headers and session management
        self.process_response_security(request, response)
        
        return response
    
    def process_authentication(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process authentication with multiple security layers"""
        try:
            # Skip authentication for excluded paths
            if self._is_excluded_path(request.path):
                return None
            
            # Account lockout check
            user_identifier = self._get_user_identifier(request)
            if user_identifier:
                is_locked, unlock_time = self.account_security.is_account_locked(user_identifier)
                if is_locked:
                    security_logger.warning(f"Access denied for locked account: {user_identifier}")
                    return JsonResponse({
                        'error': 'Account is temporarily locked',
                        'unlock_time': unlock_time.isoformat() if unlock_time else None
                    }, status=423)  # HTTP 423 Locked
            
            # JWT token authentication
            jwt_result = self._process_jwt_authentication(request)
            if jwt_result:
                return jwt_result
            
            # Session-based authentication
            session_result = self._process_session_authentication(request)
            if session_result:
                return session_result
            
            # MFA enforcement check
            if self.enforce_mfa and hasattr(request, 'user') and request.user.is_authenticated:
                mfa_result = self._enforce_mfa_verification(request)
                if mfa_result:
                    return mfa_result
            
            return None
            
        except Exception as e:
            security_logger.error(f"Authentication processing error: {str(e)}")
            return JsonResponse({'error': 'Authentication system error'}, status=500)
    
    def process_response_security(self, request: HttpRequest, response: HttpResponse):
        """Add security headers and process response"""
        try:
            # Security headers
            response['X-Frame-Options'] = 'DENY'
            response['X-Content-Type-Options'] = 'nosniff'
            response['X-XSS-Protection'] = '1; mode=block'
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
            
            # HSTS header for HTTPS
            if request.is_secure():
                response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
            
            # Session security
            if hasattr(request, 'session'):
                response['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
                response['Pragma'] = 'no-cache'
                response['Expires'] = '0'
            
        except Exception as e:
            security_logger.error(f"Response security processing error: {str(e)}")
    
    def _process_jwt_authentication(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process JWT token authentication"""
        try:
            auth_header = request.META.get(f'HTTP_{self.jwt_header_name.upper().replace("-", "_")}')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return None
            
            token = auth_header.split(' ')[1]
            is_valid, payload = self.jwt_security.validate_jwt_token(token, 'access')
            
            if not is_valid:
                security_logger.warning(f"Invalid JWT token from {request.META.get('REMOTE_ADDR')}")
                return JsonResponse({'error': 'Invalid or expired token'}, status=401)
            
            # Set user context
            user_id = payload.get('user_id')
            if user_id:
                User = get_user_model()
                try:
                    request.user = User.objects.get(id=user_id)
                    request.auth_method = 'jwt'
                    request.token_scopes = payload.get('scopes', [])
                except User.DoesNotExist:
                    return JsonResponse({'error': 'User not found'}, status=401)
            
            return None
            
        except Exception as e:
            security_logger.error(f"JWT authentication error: {str(e)}")
            return JsonResponse({'error': 'JWT authentication error'}, status=500)
    
    def _process_session_authentication(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process session-based authentication with enhanced security"""
        try:
            if not self.require_secure_sessions:
                return None
            
            session_id = request.session.session_key
            if not session_id:
                return None
            
            # Validate secure session
            is_valid, session_data = self.session_manager.validate_session(
                session_id, request.META
            )
            
            if not is_valid:
                security_logger.warning(f"Invalid session from {request.META.get('REMOTE_ADDR')}")
                request.session.flush()  # Clear invalid session
                return JsonResponse({'error': 'Session validation failed'}, status=401)
            
            # Set session context
            request.secure_session_data = session_data
            request.auth_method = 'session'
            
            return None
            
        except Exception as e:
            security_logger.error(f"Session authentication error: {str(e)}")
            return None
    
    def _enforce_mfa_verification(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Enforce MFA verification for authenticated users"""
        try:
            user_id = request.user.id
            mfa_verified_key = f"mfa_verified_{user_id}"
            
            # Check if MFA is already verified for this session
            if cache.get(mfa_verified_key):
                return None
            
            # Check if user has MFA enabled
            mfa_enabled_key = f"mfa_enabled_{user_id}"
            if not cache.get(mfa_enabled_key):
                return None
            
            # Require MFA verification
            security_logger.info(f"MFA verification required for user {user_id}")
            return JsonResponse({
                'error': 'MFA verification required',
                'redirect': '/auth/mfa-verify/',
                'user_id': user_id
            }, status=403)
            
        except Exception as e:
            security_logger.error(f"MFA enforcement error: {str(e)}")
            return None
    
    def _get_user_identifier(self, request: HttpRequest) -> Optional[str]:
        """Extract user identifier from request"""
        try:
            # Try to get from authenticated user
            if hasattr(request, 'user') and request.user.is_authenticated:
                return request.user.username or str(request.user.id)
            
            # Try to get from POST data
            if request.method == 'POST':
                if hasattr(request, 'POST'):
                    return request.POST.get('username') or request.POST.get('email')
            
            # Try to get from JWT token
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                is_valid, payload = self.jwt_security.validate_jwt_token(token, 'access')
                if is_valid:
                    return str(payload.get('user_id', ''))
            
            return None
            
        except Exception as e:
            security_logger.error(f"User identifier extraction error: {str(e)}")
            return None
    
    def _is_excluded_path(self, path: str) -> bool:
        """Check if path is excluded from authentication checks"""
        excluded_paths = getattr(settings, 'AUTHENTICATION_EXCLUDED_PATHS', [
            '/health/',
            '/ping/',
            '/static/',
            '/media/',
            '/admin/login/',
            '/api/auth/login/',
            '/api/auth/register/'
        ])
        
        return any(path.startswith(excluded) for excluded in excluded_paths)


class MFAEnforcementMiddleware(MiddlewareMixin):
    """
    Middleware to enforce Multi-Factor Authentication
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.mfa = MultiFactorAuthentication()
        self.enabled = getattr(settings, 'MFA_ENFORCEMENT_ENABLED', True)
        self.protected_paths = getattr(settings, 'MFA_PROTECTED_PATHS', [
            '/admin/', '/api/admin/', '/dashboard/', '/profile/edit/'
        ])
    
    def __call__(self, request):
        if not self.enabled or not request.user.is_authenticated:
            return self.get_response(request)
        
        # Check if current path requires MFA
        requires_mfa = any(request.path.startswith(path) for path in self.protected_paths)
        
        if requires_mfa:
            mfa_result = self._check_mfa_status(request)
            if isinstance(mfa_result, HttpResponse):
                return mfa_result
        
        return self.get_response(request)
    
    def _check_mfa_status(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Check MFA verification status"""
        try:
            user_id = request.user.id
            
            # Check MFA verification status
            mfa_verified_key = f"mfa_verified_{user_id}"
            if cache.get(mfa_verified_key):
                return None  # MFA already verified
            
            # Check if user has MFA enabled
            mfa_secret_key = f"mfa_secret_{user_id}"
            if not cache.get(mfa_secret_key):
                # Redirect to MFA setup
                security_logger.info(f"MFA setup required for user {user_id}")
                return JsonResponse({
                    'error': 'MFA setup required',
                    'redirect': '/auth/mfa-setup/',
                    'message': 'Multi-factor authentication must be configured for your account'
                }, status=403)
            
            # Redirect to MFA verification
            security_logger.info(f"MFA verification required for user {user_id}")
            return JsonResponse({
                'error': 'MFA verification required',
                'redirect': '/auth/mfa-verify/',
                'message': 'Please complete multi-factor authentication'
            }, status=403)
            
        except Exception as e:
            security_logger.error(f"MFA status check error: {str(e)}")
            return JsonResponse({'error': 'MFA system error'}, status=500)


class RBACAuthorizationMiddleware(MiddlewareMixin):
    """
    Role-Based Access Control Authorization Middleware
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.rbac = RoleBasedAccessControl()
        self.enabled = getattr(settings, 'RBAC_ENFORCEMENT_ENABLED', True)
        
        # Define resource mappings
        self.resource_mappings = getattr(settings, 'RBAC_RESOURCE_MAPPINGS', {
            '/api/users/': 'user_management',
            '/api/health/': 'health_data',
            '/api/admin/': 'admin_functions',
            '/api/analytics/': 'analytics_data',
            '/api/reports/': 'report_access'
        })
    
    def __call__(self, request):
        if not self.enabled or not request.user.is_authenticated:
            return self.get_response(request)
        
        # Check authorization for protected resources
        auth_result = self._check_authorization(request)
        if isinstance(auth_result, HttpResponse):
            return auth_result
        
        response = self.get_response(request)
        
        # Log access for audit trail
        self._log_resource_access(request, response)
        
        return response
    
    def _check_authorization(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Check user authorization for requested resource"""
        try:
            # Determine required permission based on HTTP method and path
            permission = self._get_required_permission(request)
            if not permission:
                return None  # No specific permission required
            
            # Determine resource context
            resource, resource_id = self._get_resource_context(request)
            
            # Check permission
            user_id = request.user.id
            allowed, metadata = self.rbac.check_permission(
                user_id, permission, resource, resource_id
            )
            
            if not allowed:
                security_logger.warning(f"Access denied for user {user_id}: {permission} on {resource}")
                return JsonResponse({
                    'error': 'Access denied',
                    'required_permission': permission,
                    'resource': resource,
                    'user_roles': metadata.get('user_roles', [])
                }, status=403)
            
            # Store authorization context in request
            request.authorization_metadata = metadata
            
            return None
            
        except Exception as e:
            security_logger.error(f"Authorization check error: {str(e)}")
            return JsonResponse({'error': 'Authorization system error'}, status=500)
    
    def _get_required_permission(self, request: HttpRequest) -> Optional[str]:
        """Determine required permission based on request"""
        try:
            method = request.method
            path = request.path
            
            # Map HTTP methods to permission actions
            method_actions = {
                'GET': 'view',
                'POST': 'add',
                'PUT': 'change',
                'PATCH': 'change',
                'DELETE': 'delete'
            }
            
            action = method_actions.get(method, 'view')
            
            # Map paths to resources
            for path_pattern, resource in self.resource_mappings.items():
                if path.startswith(path_pattern):
                    return f"{resource}.{action}"
            
            return None
            
        except Exception as e:
            security_logger.error(f"Permission determination error: {str(e)}")
            return None
    
    def _get_resource_context(self, request: HttpRequest) -> Tuple[Optional[str], Optional[int]]:
        """Extract resource and resource ID from request"""
        try:
            path = request.path
            
            # Extract resource from path mapping
            resource = None
            for path_pattern, mapped_resource in self.resource_mappings.items():
                if path.startswith(path_pattern):
                    resource = mapped_resource
                    break
            
            # Extract resource ID from URL (assuming pattern /api/resource/123/)
            path_parts = [p for p in path.split('/') if p]
            resource_id = None
            
            if len(path_parts) >= 3:
                try:
                    resource_id = int(path_parts[-1])
                except ValueError:
                    pass
            
            return resource, resource_id
            
        except Exception as e:
            security_logger.error(f"Resource context extraction error: {str(e)}")
            return None, None
    
    def _log_resource_access(self, request: HttpRequest, response: HttpResponse):
        """Log resource access for audit trail"""
        try:
            access_log = {
                'user_id': request.user.id,
                'username': request.user.username,
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'timestamp': timezone.now().isoformat(),
                'ip_address': request.META.get('REMOTE_ADDR'),
                'user_agent': request.META.get('HTTP_USER_AGENT'),
                'authorization_metadata': getattr(request, 'authorization_metadata', {})
            }
            
            # Store in cache for audit dashboard
            audit_key = f"access_log_{int(time.time())}_{request.user.id}"
            cache.set(audit_key, access_log, 86400 * 7)  # Keep for 7 days
            
            # Log successful access
            if 200 <= response.status_code < 300:
                security_logger.info(f"Resource access: User {request.user.id} accessed {request.path}")
            elif response.status_code == 403:
                security_logger.warning(f"Access denied: User {request.user.id} denied access to {request.path}")
            
        except Exception as e:
            security_logger.error(f"Access logging error: {str(e)}")


class BiometricAuthMiddleware(MiddlewareMixin):
    """
    Biometric Authentication Middleware
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.biometric_auth = BiometricAuthentication()
        self.enabled = getattr(settings, 'BIOMETRIC_AUTH_ENABLED', False)
        self.required_endpoints = getattr(settings, 'BIOMETRIC_REQUIRED_ENDPOINTS', [
            '/api/admin/', '/api/sensitive-data/'
        ])
    
    def __call__(self, request):
        if not self.enabled or not request.user.is_authenticated:
            return self.get_response(request)
        
        # Check if biometric verification is required
        requires_biometric = any(
            request.path.startswith(endpoint) for endpoint in self.required_endpoints
        )
        
        if requires_biometric:
            biometric_result = self._check_biometric_verification(request)
            if isinstance(biometric_result, HttpResponse):
                return biometric_result
        
        return self.get_response(request)
    
    def _check_biometric_verification(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Check biometric verification status"""
        try:
            user_id = request.user.id
            
            # Check if biometric verification is already completed
            biometric_verified_key = f"biometric_verified_{user_id}"
            if cache.get(biometric_verified_key):
                return None
            
            # Require biometric verification
            security_logger.info(f"Biometric verification required for user {user_id}")
            return JsonResponse({
                'error': 'Biometric verification required',
                'redirect': '/auth/biometric-verify/',
                'message': 'Please complete biometric authentication for this sensitive operation'
            }, status=403)
            
        except Exception as e:
            security_logger.error(f"Biometric verification check error: {str(e)}")
            return JsonResponse({'error': 'Biometric system error'}, status=500)


class SessionSecurityMiddleware(MiddlewareMixin):
    """
    Enhanced Session Security Middleware
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.session_manager = AdvancedSessionManager()
        self.enabled = getattr(settings, 'SESSION_SECURITY_ENABLED', True)
        self.max_session_age = getattr(settings, 'SESSION_MAX_AGE', 3600)  # 1 hour
    
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        # Process session security
        session_result = self._process_session_security(request)
        if isinstance(session_result, HttpResponse):
            return session_result
        
        response = self.get_response(request)
        
        # Update session tracking
        self._update_session_tracking(request, response)
        
        return response
    
    def _process_session_security(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process session security validation"""
        try:
            if not request.user.is_authenticated:
                return None
            
            session_key = request.session.session_key
            if not session_key:
                return None
            
            # Validate session fingerprint and detect anomalies
            is_valid, session_data = self.session_manager.validate_session(
                session_key, request.META
            )
            
            if not is_valid:
                # Invalid session detected
                security_logger.warning(f"Invalid session detected for user {request.user.id}")
                request.session.flush()
                
                return JsonResponse({
                    'error': 'Session security validation failed',
                    'redirect': '/auth/login/',
                    'message': 'Your session has been terminated for security reasons'
                }, status=401)
            
            # Check for session hijacking indicators
            if self._detect_session_hijacking(request, session_data):
                security_logger.error(f"Session hijacking detected for user {request.user.id}")
                request.session.flush()
                
                return JsonResponse({
                    'error': 'Session hijacking detected',
                    'redirect': '/auth/login/',
                    'message': 'Suspicious session activity detected. Please log in again.'
                }, status=401)
            
            return None
            
        except Exception as e:
            security_logger.error(f"Session security processing error: {str(e)}")
            return None
    
    def _detect_session_hijacking(self, request: HttpRequest, session_data: Dict) -> bool:
        """Detect potential session hijacking"""
        try:
            # IP address validation
            current_ip = request.META.get('REMOTE_ADDR')
            session_ip = session_data.get('ip_address')
            
            if current_ip != session_ip:
                return True
            
            # User agent validation
            current_ua = request.META.get('HTTP_USER_AGENT', '')
            session_ua = session_data.get('user_agent', '')
            
            if current_ua != session_ua:
                return True
            
            # Check for rapid requests from different locations
            # This would require GeoIP integration
            
            return False
            
        except Exception as e:
            security_logger.error(f"Session hijacking detection error: {str(e)}")
            return False
    
    def _update_session_tracking(self, request: HttpRequest, response: HttpResponse):
        """Update session tracking information"""
        try:
            if not request.user.is_authenticated:
                return
            
            session_key = request.session.session_key
            if not session_key:
                return
            
            # Update session activity
            tracking_data = {
                'last_activity': timezone.now().isoformat(),
                'last_ip': request.META.get('REMOTE_ADDR'),
                'last_user_agent': request.META.get('HTTP_USER_AGENT'),
                'request_count': request.session.get('request_count', 0) + 1,
                'last_path': request.path
            }
            
            # Update session data
            for key, value in tracking_data.items():
                request.session[key] = value
            
        except Exception as e:
            security_logger.error(f"Session tracking update error: {str(e)}")


class AuthenticationAnalyticsMiddleware(MiddlewareMixin):
    """
    Authentication Analytics and Monitoring Middleware
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.enabled = getattr(settings, 'AUTH_ANALYTICS_ENABLED', True)
    
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        start_time = time.time()
        
        # Pre-process analytics
        self._track_authentication_attempt(request)
        
        response = self.get_response(request)
        
        # Post-process analytics
        processing_time = time.time() - start_time
        self._track_authentication_response(request, response, processing_time)
        
        return response
    
    def _track_authentication_attempt(self, request: HttpRequest):
        """Track authentication attempts for analytics"""
        try:
            # Only track auth-related requests
            if not self._is_auth_request(request):
                return
            
            attempt_data = {
                'timestamp': timezone.now().isoformat(),
                'ip_address': request.META.get('REMOTE_ADDR'),
                'user_agent': request.META.get('HTTP_USER_AGENT'),
                'path': request.path,
                'method': request.method,
                'is_authenticated': request.user.is_authenticated if hasattr(request, 'user') else False,
                'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
                'session_key': request.session.session_key if hasattr(request, 'session') else None,
                'has_mfa': self._check_mfa_status(request),
                'auth_method': getattr(request, 'auth_method', 'session')
            }
            
            # Store analytics data
            analytics_key = f"auth_analytics_{int(time.time())}_{secrets.token_hex(4)}"
            cache.set(analytics_key, attempt_data, 86400 * 30)  # Keep for 30 days
            
        except Exception as e:
            security_logger.error(f"Authentication analytics tracking error: {str(e)}")
    
    def _track_authentication_response(self, request: HttpRequest, 
                                     response: HttpResponse, processing_time: float):
        """Track authentication response metrics"""
        try:
            if not self._is_auth_request(request):
                return
            
            response_data = {
                'timestamp': timezone.now().isoformat(),
                'status_code': response.status_code,
                'processing_time': processing_time,
                'path': request.path,
                'success': 200 <= response.status_code < 300,
                'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
                'security_flags': {
                    'mfa_verified': getattr(request, 'mfa_verified', False),
                    'biometric_verified': getattr(request, 'biometric_verified', False),
                    'session_secure': getattr(request, 'session_secure', False)
                }
            }
            
            # Store response analytics
            response_key = f"auth_response_{int(time.time())}_{secrets.token_hex(4)}"
            cache.set(response_key, response_data, 86400 * 30)  # Keep for 30 days
            
            # Update real-time metrics
            self._update_realtime_metrics(response_data)
            
        except Exception as e:
            security_logger.error(f"Authentication response tracking error: {str(e)}")
    
    def _is_auth_request(self, request: HttpRequest) -> bool:
        """Check if request is authentication-related"""
        auth_paths = [
            '/auth/', '/login/', '/logout/', '/register/',
            '/api/auth/', '/api/login/', '/mfa/', '/biometric/'
        ]
        
        return any(request.path.startswith(path) for path in auth_paths)
    
    def _check_mfa_status(self, request: HttpRequest) -> bool:
        """Check if user has MFA enabled"""
        try:
            if not hasattr(request, 'user') or not request.user.is_authenticated:
                return False
            
            mfa_verified_key = f"mfa_verified_{request.user.id}"
            return bool(cache.get(mfa_verified_key))
            
        except Exception:
            return False
    
    def _update_realtime_metrics(self, response_data: Dict):
        """Update real-time authentication metrics"""
        try:
            metrics_key = "auth_realtime_metrics"
            metrics = cache.get(metrics_key, {
                'total_requests': 0,
                'successful_auths': 0,
                'failed_auths': 0,
                'avg_processing_time': 0.0,
                'last_updated': timezone.now().isoformat()
            })
            
            # Update counters
            metrics['total_requests'] += 1
            
            if response_data['success']:
                metrics['successful_auths'] += 1
            else:
                metrics['failed_auths'] += 1
            
            # Update average processing time
            current_avg = metrics.get('avg_processing_time', 0.0)
            new_time = response_data['processing_time']
            total_requests = metrics['total_requests']
            
            metrics['avg_processing_time'] = (
                (current_avg * (total_requests - 1) + new_time) / total_requests
            )
            
            metrics['last_updated'] = timezone.now().isoformat()
            
            # Store updated metrics
            cache.set(metrics_key, metrics, 86400)  # 24 hours
            
        except Exception as e:
            security_logger.error(f"Real-time metrics update error: {str(e)}")

import secrets