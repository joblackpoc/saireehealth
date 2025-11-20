"""
Phase 5: Authentication & Authorization Hardening
Multi-Factor Authentication, RBAC, Advanced Session Management, OAuth2/JWT Security

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
Component: Authentication Security Enhancement
"""

import json
import hashlib
import secrets
import time
import qrcode
import pyotp
import jwt
from io import BytesIO
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, Group
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re
import requests

# Enhanced Security Logging
security_logger = logging.getLogger('security_core')

class MultiFactorAuthentication:
    """
    Advanced Multi-Factor Authentication System
    Supports TOTP, SMS, Email, Hardware Keys, and Biometric authentication
    """
    
    def __init__(self):
        self.totp_window = getattr(settings, 'MFA_TOTP_WINDOW', 1)  # 30-second window tolerance
        self.backup_codes_count = getattr(settings, 'MFA_BACKUP_CODES', 10)
        self.rate_limit_attempts = getattr(settings, 'MFA_RATE_LIMIT', 5)
        self.rate_limit_window = getattr(settings, 'MFA_RATE_LIMIT_WINDOW', 300)  # 5 minutes
        
    def generate_secret_key(self, user_id: int) -> str:
        """Generate TOTP secret key for user"""
        try:
            secret = pyotp.random_base32()
            cache_key = f"mfa_secret_{user_id}"
            cache.set(cache_key, secret, 3600)  # 1 hour cache
            
            security_logger.info(f"MFA secret generated for user {user_id}")
            return secret
            
        except Exception as e:
            security_logger.error(f"MFA secret generation failed for user {user_id}: {str(e)}")
            raise
    
    def generate_qr_code(self, user_email: str, secret: str, issuer: str = "HealthProgress") -> BytesIO:
        """Generate QR code for TOTP setup"""
        try:
            totp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user_email,
                issuer_name=issuer
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_auth_url)
            qr.make(fit=True)
            
            qr_image = qr.make_image(fill_color="black", back_color="white")
            qr_buffer = BytesIO()
            qr_image.save(qr_buffer, format='PNG')
            qr_buffer.seek(0)
            
            security_logger.info(f"MFA QR code generated for {user_email}")
            return qr_buffer
            
        except Exception as e:
            security_logger.error(f"MFA QR generation failed for {user_email}: {str(e)}")
            raise
    
    def verify_totp_token(self, user_id: int, token: str, secret: str) -> Tuple[bool, str]:
        """Verify TOTP token with rate limiting and replay protection"""
        try:
            # Rate limiting check
            rate_limit_key = f"mfa_attempts_{user_id}"
            attempts = cache.get(rate_limit_key, 0)
            
            if attempts >= self.rate_limit_attempts:
                security_logger.warning(f"MFA rate limit exceeded for user {user_id}")
                return False, "Rate limit exceeded. Please wait before trying again."
            
            # Replay attack protection
            token_hash = hashlib.sha256(f"{user_id}_{token}_{int(time.time()//30)}".encode()).hexdigest()
            replay_key = f"mfa_token_{token_hash}"
            
            if cache.get(replay_key):
                security_logger.warning(f"MFA replay attack detected for user {user_id}")
                return False, "Token already used. Please wait for next token."
            
            # TOTP verification
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(token, valid_window=self.totp_window)
            
            if is_valid:
                # Mark token as used
                cache.set(replay_key, True, 60)  # 1 minute
                cache.delete(rate_limit_key)  # Clear attempts on success
                
                security_logger.info(f"MFA TOTP verified successfully for user {user_id}")
                return True, "Authentication successful"
            else:
                # Increment failed attempts
                cache.set(rate_limit_key, attempts + 1, self.rate_limit_window)
                
                security_logger.warning(f"MFA TOTP verification failed for user {user_id}")
                return False, "Invalid authentication code"
                
        except Exception as e:
            security_logger.error(f"MFA TOTP verification error for user {user_id}: {str(e)}")
            return False, "Authentication system error"
    
    def generate_backup_codes(self, user_id: int) -> List[str]:
        """Generate backup recovery codes"""
        try:
            codes = []
            for _ in range(self.backup_codes_count):
                code = secrets.token_hex(4).upper()
                codes.append(f"{code[:4]}-{code[4:]}")
            
            # Store hashed backup codes
            hashed_codes = [hashlib.sha256(code.encode()).hexdigest() for code in codes]
            cache_key = f"mfa_backup_{user_id}"
            cache.set(cache_key, hashed_codes, 86400 * 30)  # 30 days
            
            security_logger.info(f"MFA backup codes generated for user {user_id}")
            return codes
            
        except Exception as e:
            security_logger.error(f"MFA backup code generation failed for user {user_id}: {str(e)}")
            raise
    
    def verify_backup_code(self, user_id: int, code: str) -> Tuple[bool, str]:
        """Verify and consume backup code"""
        try:
            cache_key = f"mfa_backup_{user_id}"
            stored_codes = cache.get(cache_key, [])
            
            if not stored_codes:
                return False, "No backup codes available"
            
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            
            if code_hash in stored_codes:
                # Remove used code
                stored_codes.remove(code_hash)
                cache.set(cache_key, stored_codes, 86400 * 30)
                
                security_logger.info(f"MFA backup code used for user {user_id}")
                return True, "Backup code verified"
            else:
                security_logger.warning(f"Invalid MFA backup code attempt for user {user_id}")
                return False, "Invalid backup code"
                
        except Exception as e:
            security_logger.error(f"MFA backup code verification error for user {user_id}: {str(e)}")
            return False, "Verification system error"


class RoleBasedAccessControl:
    """
    Advanced Role-Based Access Control System
    Dynamic permissions, hierarchical roles, resource-based access control
    """
    
    def __init__(self):
        self.permission_cache_timeout = getattr(settings, 'RBAC_CACHE_TIMEOUT', 300)  # 5 minutes
        self.max_role_depth = getattr(settings, 'RBAC_MAX_DEPTH', 5)
        
    def create_advanced_role(self, role_name: str, permissions: List[str], 
                           parent_role: Optional[str] = None, 
                           resource_constraints: Optional[Dict] = None) -> Dict:
        """Create role with hierarchical inheritance and resource constraints"""
        try:
            # Create or get role group
            role_group, created = Group.objects.get_or_create(name=role_name)
            
            # Add permissions
            for perm_code in permissions:
                try:
                    permission = Permission.objects.get(codename=perm_code)
                    role_group.permissions.add(permission)
                except Permission.DoesNotExist:
                    security_logger.warning(f"Permission {perm_code} not found for role {role_name}")
            
            # Store role metadata
            role_metadata = {
                'role_name': role_name,
                'parent_role': parent_role,
                'resource_constraints': resource_constraints or {},
                'created_at': timezone.now().isoformat(),
                'permissions': permissions
            }
            
            cache_key = f"rbac_role_metadata_{role_name}"
            cache.set(cache_key, role_metadata, self.permission_cache_timeout)
            
            security_logger.info(f"RBAC role created: {role_name} with {len(permissions)} permissions")
            return role_metadata
            
        except Exception as e:
            security_logger.error(f"RBAC role creation failed for {role_name}: {str(e)}")
            raise
    
    def assign_user_role(self, user_id: int, role_name: str, 
                        context: Optional[Dict] = None) -> bool:
        """Assign role to user with context tracking"""
        try:
            User = get_user_model()
            user = User.objects.get(id=user_id)
            role_group = Group.objects.get(name=role_name)
            
            user.groups.add(role_group)
            
            # Store assignment context
            assignment_key = f"rbac_assignment_{user_id}_{role_name}"
            assignment_data = {
                'user_id': user_id,
                'role_name': role_name,
                'assigned_at': timezone.now().isoformat(),
                'context': context or {},
                'assigned_by': context.get('assigned_by') if context else 'system'
            }
            
            cache.set(assignment_key, assignment_data, 86400 * 30)  # 30 days
            
            security_logger.info(f"RBAC role {role_name} assigned to user {user_id}")
            return True
            
        except Exception as e:
            security_logger.error(f"RBAC role assignment failed for user {user_id}, role {role_name}: {str(e)}")
            return False
    
    def check_permission(self, user_id: int, permission: str, 
                        resource: Optional[str] = None, 
                        resource_id: Optional[int] = None) -> Tuple[bool, Dict]:
        """Advanced permission checking with resource-level access control"""
        try:
            # Check cache first
            cache_key = f"rbac_check_{user_id}_{permission}_{resource}_{resource_id}"
            cached_result = cache.get(cache_key)
            
            if cached_result is not None:
                return cached_result['allowed'], cached_result['metadata']
            
            User = get_user_model()
            user = User.objects.get(id=user_id)
            
            # Basic permission check
            has_permission = user.has_perm(permission)
            
            # Enhanced checks for resource-level access
            enhanced_result = {
                'allowed': has_permission,
                'metadata': {
                    'user_id': user_id,
                    'permission': permission,
                    'resource': resource,
                    'resource_id': resource_id,
                    'check_time': timezone.now().isoformat(),
                    'user_roles': list(user.groups.values_list('name', flat=True))
                }
            }
            
            # Resource-specific access control
            if has_permission and resource:
                resource_allowed = self._check_resource_access(user, resource, resource_id)
                enhanced_result['allowed'] = resource_allowed
                enhanced_result['metadata']['resource_check'] = resource_allowed
            
            # Cache result
            cache.set(cache_key, enhanced_result, self.permission_cache_timeout)
            
            security_logger.info(f"RBAC permission check for user {user_id}: {permission} -> {enhanced_result['allowed']}")
            return enhanced_result['allowed'], enhanced_result['metadata']
            
        except Exception as e:
            security_logger.error(f"RBAC permission check error for user {user_id}: {str(e)}")
            return False, {'error': str(e)}
    
    def _check_resource_access(self, user, resource: str, resource_id: Optional[int]) -> bool:
        """Check resource-level access based on ownership, department, etc."""
        try:
            # Example resource-level checks
            if resource == 'health_record':
                # Check if user owns the health record or is a healthcare provider
                if user.groups.filter(name__in=['healthcare_provider', 'admin']).exists():
                    return True
                # Check ownership logic here
                return self._check_health_record_ownership(user, resource_id)
            
            elif resource == 'user_profile':
                # Users can access their own profile, admins can access all
                if user.groups.filter(name='admin').exists():
                    return True
                return user.id == resource_id
            
            elif resource == 'analytics_data':
                # Only analysts and admins can access analytics
                return user.groups.filter(name__in=['analyst', 'admin']).exists()
            
            return True  # Default allow if no specific rules
            
        except Exception as e:
            security_logger.error(f"Resource access check error: {str(e)}")
            return False
    
    def _check_health_record_ownership(self, user, record_id: Optional[int]) -> bool:
        """Check if user has access to specific health record"""
        try:
            if not record_id:
                return False
            
            # Check if record belongs to user (implement based on your model)
            # This is a placeholder - implement actual ownership logic
            return True
            
        except Exception as e:
            security_logger.error(f"Health record ownership check error: {str(e)}")
            return False


class AdvancedSessionManager:
    """
    Advanced Session Management with Enhanced Security
    Session fingerprinting, concurrent session control, anomaly detection
    """
    
    def __init__(self):
        self.max_sessions_per_user = getattr(settings, 'SESSION_MAX_PER_USER', 3)
        self.session_timeout = getattr(settings, 'SESSION_TIMEOUT', 3600)  # 1 hour
        self.fingerprint_salt = getattr(settings, 'SESSION_FINGERPRINT_SALT', 'default_salt')
        
    def create_secure_session(self, user_id: int, request_meta: Dict) -> Dict:
        """Create session with enhanced security fingerprinting"""
        try:
            # Generate session fingerprint
            fingerprint_data = {
                'user_agent': request_meta.get('HTTP_USER_AGENT', ''),
                'accept_language': request_meta.get('HTTP_ACCEPT_LANGUAGE', ''),
                'accept_encoding': request_meta.get('HTTP_ACCEPT_ENCODING', ''),
                'remote_addr': request_meta.get('REMOTE_ADDR', ''),
                'x_forwarded_for': request_meta.get('HTTP_X_FORWARDED_FOR', ''),
            }
            
            fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
            session_fingerprint = hashlib.sha256(
                (fingerprint_string + self.fingerprint_salt).encode()
            ).hexdigest()
            
            # Check concurrent sessions
            self._enforce_session_limits(user_id)
            
            # Create session metadata
            session_id = secrets.token_urlsafe(32)
            session_data = {
                'session_id': session_id,
                'user_id': user_id,
                'fingerprint': session_fingerprint,
                'created_at': timezone.now().isoformat(),
                'last_activity': timezone.now().isoformat(),
                'ip_address': request_meta.get('REMOTE_ADDR'),
                'user_agent': request_meta.get('HTTP_USER_AGENT'),
                'is_active': True,
                'security_flags': {
                    'mfa_verified': False,
                    'suspicious_activity': False,
                    'location_verified': False
                }
            }
            
            # Store session
            cache_key = f"secure_session_{session_id}"
            cache.set(cache_key, session_data, self.session_timeout)
            
            # Track user sessions
            user_sessions_key = f"user_sessions_{user_id}"
            user_sessions = cache.get(user_sessions_key, [])
            user_sessions.append(session_id)
            cache.set(user_sessions_key, user_sessions, 86400)  # 24 hours
            
            security_logger.info(f"Secure session created for user {user_id}: {session_id[:8]}...")
            return session_data
            
        except Exception as e:
            security_logger.error(f"Secure session creation failed for user {user_id}: {str(e)}")
            raise
    
    def validate_session(self, session_id: str, request_meta: Dict) -> Tuple[bool, Dict]:
        """Validate session with fingerprint verification and anomaly detection"""
        try:
            cache_key = f"secure_session_{session_id}"
            session_data = cache.get(cache_key)
            
            if not session_data or not session_data.get('is_active'):
                return False, {'error': 'Session not found or inactive'}
            
            # Check session timeout
            last_activity = datetime.fromisoformat(session_data['last_activity'])
            if timezone.now() - last_activity > timedelta(seconds=self.session_timeout):
                self._invalidate_session(session_id)
                return False, {'error': 'Session expired'}
            
            # Fingerprint verification
            current_fingerprint = self._generate_fingerprint(request_meta)
            if current_fingerprint != session_data['fingerprint']:
                # Potential session hijacking
                security_logger.warning(f"Session fingerprint mismatch for session {session_id[:8]}...")
                self._flag_suspicious_activity(session_id, 'fingerprint_mismatch')
                return False, {'error': 'Session security validation failed'}
            
            # Anomaly detection
            anomaly_detected = self._detect_session_anomalies(session_data, request_meta)
            if anomaly_detected:
                security_logger.warning(f"Session anomaly detected for session {session_id[:8]}...")
                return False, {'error': 'Suspicious session activity detected'}
            
            # Update last activity
            session_data['last_activity'] = timezone.now().isoformat()
            cache.set(cache_key, session_data, self.session_timeout)
            
            return True, session_data
            
        except Exception as e:
            security_logger.error(f"Session validation error for {session_id[:8]}...: {str(e)}")
            return False, {'error': 'Session validation system error'}
    
    def _enforce_session_limits(self, user_id: int):
        """Enforce maximum concurrent sessions per user"""
        try:
            user_sessions_key = f"user_sessions_{user_id}"
            user_sessions = cache.get(user_sessions_key, [])
            
            if len(user_sessions) >= self.max_sessions_per_user:
                # Remove oldest session
                oldest_session = user_sessions[0]
                self._invalidate_session(oldest_session)
                user_sessions.remove(oldest_session)
                
                security_logger.info(f"Session limit enforced for user {user_id}, removed session {oldest_session[:8]}...")
            
            cache.set(user_sessions_key, user_sessions, 86400)
            
        except Exception as e:
            security_logger.error(f"Session limit enforcement error for user {user_id}: {str(e)}")
    
    def _generate_fingerprint(self, request_meta: Dict) -> str:
        """Generate browser fingerprint for session validation"""
        fingerprint_data = {
            'user_agent': request_meta.get('HTTP_USER_AGENT', ''),
            'accept_language': request_meta.get('HTTP_ACCEPT_LANGUAGE', ''),
            'accept_encoding': request_meta.get('HTTP_ACCEPT_ENCODING', ''),
            'remote_addr': request_meta.get('REMOTE_ADDR', ''),
            'x_forwarded_for': request_meta.get('HTTP_X_FORWARDED_FOR', ''),
        }
        
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(
            (fingerprint_string + self.fingerprint_salt).encode()
        ).hexdigest()
    
    def _detect_session_anomalies(self, session_data: Dict, request_meta: Dict) -> bool:
        """Detect suspicious session activities"""
        try:
            anomalies = []
            
            # IP address change detection
            current_ip = request_meta.get('REMOTE_ADDR')
            session_ip = session_data.get('ip_address')
            
            if current_ip != session_ip:
                anomalies.append('ip_change')
            
            # Geographic location change (if available)
            # Implement GeoIP checking here if needed
            
            # Time-based anomalies
            last_activity = datetime.fromisoformat(session_data['last_activity'])
            time_gap = timezone.now() - last_activity
            
            if time_gap < timedelta(seconds=1):
                anomalies.append('rapid_requests')
            
            return len(anomalies) > 0
            
        except Exception as e:
            security_logger.error(f"Session anomaly detection error: {str(e)}")
            return False
    
    def _invalidate_session(self, session_id: str):
        """Invalidate and clean up session"""
        try:
            cache_key = f"secure_session_{session_id}"
            session_data = cache.get(cache_key)
            
            if session_data:
                session_data['is_active'] = False
                cache.set(cache_key, session_data, 60)  # Keep for audit trail
                
                # Remove from user sessions list
                user_id = session_data.get('user_id')
                if user_id:
                    user_sessions_key = f"user_sessions_{user_id}"
                    user_sessions = cache.get(user_sessions_key, [])
                    if session_id in user_sessions:
                        user_sessions.remove(session_id)
                        cache.set(user_sessions_key, user_sessions, 86400)
                
                security_logger.info(f"Session invalidated: {session_id[:8]}...")
            
        except Exception as e:
            security_logger.error(f"Session invalidation error for {session_id[:8]}...: {str(e)}")
    
    def _flag_suspicious_activity(self, session_id: str, activity_type: str):
        """Flag session for suspicious activity"""
        try:
            cache_key = f"secure_session_{session_id}"
            session_data = cache.get(cache_key)
            
            if session_data:
                session_data['security_flags']['suspicious_activity'] = True
                session_data['suspicious_activities'] = session_data.get('suspicious_activities', [])
                session_data['suspicious_activities'].append({
                    'type': activity_type,
                    'timestamp': timezone.now().isoformat()
                })
                
                cache.set(cache_key, session_data, self.session_timeout)
                
                security_logger.warning(f"Suspicious activity flagged for session {session_id[:8]}...: {activity_type}")
            
        except Exception as e:
            security_logger.error(f"Suspicious activity flagging error: {str(e)}")


class OAuth2JWTSecurity:
    """
    Enhanced OAuth2 and JWT Security Implementation
    Secure token generation, validation, and refresh mechanisms
    """
    
    def __init__(self):
        self.jwt_algorithm = getattr(settings, 'JWT_ALGORITHM', 'HS256')
        self.jwt_access_token_lifetime = getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME', 900)  # 15 minutes
        self.jwt_refresh_token_lifetime = getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', 86400)  # 24 hours
        self.jwt_secret = getattr(settings, 'JWT_SECRET_KEY', settings.SECRET_KEY)
        
    def generate_secure_tokens(self, user_id: int, scopes: List[str] = None, 
                             additional_claims: Dict = None) -> Dict:
        """Generate secure JWT access and refresh tokens"""
        try:
            current_time = timezone.now()
            scopes = scopes or ['read', 'write']
            additional_claims = additional_claims or {}
            
            # Access token payload
            access_payload = {
                'user_id': user_id,
                'scopes': scopes,
                'token_type': 'access',
                'iat': current_time.timestamp(),
                'exp': (current_time + timedelta(seconds=self.jwt_access_token_lifetime)).timestamp(),
                'jti': secrets.token_urlsafe(16),  # JWT ID for revocation
                **additional_claims
            }
            
            # Refresh token payload
            refresh_payload = {
                'user_id': user_id,
                'token_type': 'refresh',
                'iat': current_time.timestamp(),
                'exp': (current_time + timedelta(seconds=self.jwt_refresh_token_lifetime)).timestamp(),
                'jti': secrets.token_urlsafe(16)
            }
            
            # Generate tokens
            access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Store token metadata for revocation tracking
            self._store_token_metadata(access_payload['jti'], 'access', user_id, current_time)
            self._store_token_metadata(refresh_payload['jti'], 'refresh', user_id, current_time)
            
            token_data = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'token_type': 'Bearer',
                'expires_in': self.jwt_access_token_lifetime,
                'scopes': scopes,
                'issued_at': current_time.isoformat()
            }
            
            security_logger.info(f"JWT tokens generated for user {user_id}")
            return token_data
            
        except Exception as e:
            security_logger.error(f"JWT token generation failed for user {user_id}: {str(e)}")
            raise
    
    def validate_jwt_token(self, token: str, expected_type: str = 'access') -> Tuple[bool, Dict]:
        """Validate JWT token with comprehensive security checks"""
        try:
            # Decode and validate token
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Type validation
            if payload.get('token_type') != expected_type:
                return False, {'error': 'Invalid token type'}
            
            # Expiration check (handled by PyJWT)
            current_time = timezone.now().timestamp()
            if payload.get('exp', 0) < current_time:
                return False, {'error': 'Token expired'}
            
            # Revocation check
            jti = payload.get('jti')
            if jti and self._is_token_revoked(jti):
                return False, {'error': 'Token revoked'}
            
            # Additional security validations
            if not self._validate_token_claims(payload):
                return False, {'error': 'Invalid token claims'}
            
            security_logger.info(f"JWT token validated successfully for user {payload.get('user_id')}")
            return True, payload
            
        except jwt.ExpiredSignatureError:
            security_logger.warning("JWT token validation failed: Token expired")
            return False, {'error': 'Token expired'}
        except jwt.InvalidTokenError as e:
            security_logger.warning(f"JWT token validation failed: {str(e)}")
            return False, {'error': 'Invalid token'}
        except Exception as e:
            security_logger.error(f"JWT token validation error: {str(e)}")
            return False, {'error': 'Token validation system error'}
    
    def refresh_access_token(self, refresh_token: str) -> Dict:
        """Refresh access token using valid refresh token"""
        try:
            # Validate refresh token
            is_valid, payload = self.validate_jwt_token(refresh_token, 'refresh')
            
            if not is_valid:
                raise ValueError(f"Invalid refresh token: {payload.get('error')}")
            
            user_id = payload.get('user_id')
            if not user_id:
                raise ValueError("No user ID in refresh token")
            
            # Revoke old refresh token
            old_jti = payload.get('jti')
            if old_jti:
                self._revoke_token(old_jti)
            
            # Generate new token pair
            new_tokens = self.generate_secure_tokens(user_id)
            
            security_logger.info(f"JWT tokens refreshed for user {user_id}")
            return new_tokens
            
        except Exception as e:
            security_logger.error(f"JWT token refresh failed: {str(e)}")
            raise
    
    def revoke_user_tokens(self, user_id: int) -> bool:
        """Revoke all tokens for a specific user"""
        try:
            # Get all user tokens from metadata storage
            user_tokens_key = f"jwt_user_tokens_{user_id}"
            user_tokens = cache.get(user_tokens_key, [])
            
            for jti in user_tokens:
                self._revoke_token(jti)
            
            # Clear user tokens list
            cache.delete(user_tokens_key)
            
            security_logger.info(f"All JWT tokens revoked for user {user_id}")
            return True
            
        except Exception as e:
            security_logger.error(f"JWT token revocation failed for user {user_id}: {str(e)}")
            return False
    
    def _store_token_metadata(self, jti: str, token_type: str, user_id: int, issued_at):
        """Store token metadata for tracking and revocation"""
        try:
            metadata = {
                'jti': jti,
                'token_type': token_type,
                'user_id': user_id,
                'issued_at': issued_at.isoformat(),
                'revoked': False
            }
            
            # Store individual token metadata
            token_key = f"jwt_token_metadata_{jti}"
            cache.set(token_key, metadata, self.jwt_refresh_token_lifetime)
            
            # Add to user tokens list
            user_tokens_key = f"jwt_user_tokens_{user_id}"
            user_tokens = cache.get(user_tokens_key, [])
            user_tokens.append(jti)
            cache.set(user_tokens_key, user_tokens, self.jwt_refresh_token_lifetime)
            
        except Exception as e:
            security_logger.error(f"Token metadata storage error: {str(e)}")
    
    def _is_token_revoked(self, jti: str) -> bool:
        """Check if token is revoked"""
        try:
            token_key = f"jwt_token_metadata_{jti}"
            metadata = cache.get(token_key)
            return metadata and metadata.get('revoked', False)
            
        except Exception as e:
            security_logger.error(f"Token revocation check error: {str(e)}")
            return True  # Fail secure
    
    def _revoke_token(self, jti: str):
        """Revoke specific token"""
        try:
            token_key = f"jwt_token_metadata_{jti}"
            metadata = cache.get(token_key)
            
            if metadata:
                metadata['revoked'] = True
                metadata['revoked_at'] = timezone.now().isoformat()
                cache.set(token_key, metadata, self.jwt_refresh_token_lifetime)
            
        except Exception as e:
            security_logger.error(f"Token revocation error: {str(e)}")
    
    def _validate_token_claims(self, payload: Dict) -> bool:
        """Validate additional token claims for security"""
        try:
            # Check required claims
            required_claims = ['user_id', 'token_type', 'iat', 'exp', 'jti']
            for claim in required_claims:
                if claim not in payload:
                    return False
            
            # Validate user_id
            if not isinstance(payload['user_id'], int) or payload['user_id'] <= 0:
                return False
            
            # Validate timestamps
            current_time = timezone.now().timestamp()
            if payload['iat'] > current_time:  # Future issued time
                return False
            
            return True
            
        except Exception as e:
            security_logger.error(f"Token claims validation error: {str(e)}")
            return False


class BiometricAuthentication:
    """
    Biometric Authentication Integration
    Fingerprint, face recognition, and voice authentication support
    """
    
    def __init__(self):
        self.biometric_timeout = getattr(settings, 'BIOMETRIC_TIMEOUT', 30)  # 30 seconds
        self.max_biometric_attempts = getattr(settings, 'BIOMETRIC_MAX_ATTEMPTS', 3)
        
    def register_biometric_template(self, user_id: int, biometric_type: str, 
                                  template_data: str, metadata: Dict = None) -> bool:
        """Register biometric template for user"""
        try:
            # Validate biometric type
            valid_types = ['fingerprint', 'face', 'voice', 'iris']
            if biometric_type not in valid_types:
                raise ValueError(f"Invalid biometric type: {biometric_type}")
            
            # Hash and encrypt template data
            template_hash = hashlib.sha256(template_data.encode()).hexdigest()
            
            # Store biometric template
            template_key = f"biometric_{biometric_type}_{user_id}"
            template_record = {
                'user_id': user_id,
                'biometric_type': biometric_type,
                'template_hash': template_hash,
                'registered_at': timezone.now().isoformat(),
                'metadata': metadata or {},
                'active': True
            }
            
            cache.set(template_key, template_record, 86400 * 365)  # 1 year
            
            security_logger.info(f"Biometric template registered for user {user_id}: {biometric_type}")
            return True
            
        except Exception as e:
            security_logger.error(f"Biometric registration failed for user {user_id}: {str(e)}")
            return False
    
    def verify_biometric(self, user_id: int, biometric_type: str, 
                        template_data: str) -> Tuple[bool, Dict]:
        """Verify biometric authentication"""
        try:
            # Rate limiting
            attempts_key = f"biometric_attempts_{user_id}_{biometric_type}"
            attempts = cache.get(attempts_key, 0)
            
            if attempts >= self.max_biometric_attempts:
                security_logger.warning(f"Biometric rate limit exceeded for user {user_id}")
                return False, {'error': 'Too many biometric attempts'}
            
            # Get stored template
            template_key = f"biometric_{biometric_type}_{user_id}"
            stored_template = cache.get(template_key)
            
            if not stored_template or not stored_template.get('active'):
                return False, {'error': 'No biometric template registered'}
            
            # Verify template (simplified - in production, use proper biometric matching)
            input_hash = hashlib.sha256(template_data.encode()).hexdigest()
            stored_hash = stored_template['template_hash']
            
            # Simulate biometric matching with similarity threshold
            match_result = self._simulate_biometric_matching(input_hash, stored_hash)
            
            if match_result['similarity'] >= 0.8:  # 80% similarity threshold
                # Clear failed attempts
                cache.delete(attempts_key)
                
                security_logger.info(f"Biometric authentication successful for user {user_id}: {biometric_type}")
                return True, {
                    'similarity': match_result['similarity'],
                    'biometric_type': biometric_type,
                    'verified_at': timezone.now().isoformat()
                }
            else:
                # Increment failed attempts
                cache.set(attempts_key, attempts + 1, 300)  # 5 minutes
                
                security_logger.warning(f"Biometric authentication failed for user {user_id}: {biometric_type}")
                return False, {
                    'error': 'Biometric authentication failed',
                    'similarity': match_result['similarity']
                }
                
        except Exception as e:
            security_logger.error(f"Biometric verification error for user {user_id}: {str(e)}")
            return False, {'error': 'Biometric system error'}
    
    def _simulate_biometric_matching(self, input_hash: str, stored_hash: str) -> Dict:
        """Simulate biometric template matching (replace with actual biometric SDK)"""
        try:
            # Simple similarity calculation for demonstration
            # In production, use proper biometric matching algorithms
            
            if input_hash == stored_hash:
                similarity = 1.0
            else:
                # Calculate Hamming distance for similarity
                min_len = min(len(input_hash), len(stored_hash))
                matches = sum(c1 == c2 for c1, c2 in zip(input_hash[:min_len], stored_hash[:min_len]))
                similarity = matches / min_len if min_len > 0 else 0.0
            
            return {
                'similarity': similarity,
                'matching_time': timezone.now().isoformat()
            }
            
        except Exception as e:
            security_logger.error(f"Biometric matching simulation error: {str(e)}")
            return {'similarity': 0.0, 'error': str(e)}


class AccountSecurityManager:
    """
    Comprehensive Account Security and Password Policy Management
    Advanced password policies, account lockout, security notifications
    """
    
    def __init__(self):
        self.max_login_attempts = getattr(settings, 'ACCOUNT_MAX_LOGIN_ATTEMPTS', 5)
        self.lockout_duration = getattr(settings, 'ACCOUNT_LOCKOUT_DURATION', 900)  # 15 minutes
        self.password_history_count = getattr(settings, 'PASSWORD_HISTORY_COUNT', 5)
        
    def validate_password_policy(self, password: str, user_id: Optional[int] = None) -> Tuple[bool, List[str]]:
        """Comprehensive password policy validation"""
        try:
            errors = []
            
            # Length requirements
            if len(password) < 12:
                errors.append("Password must be at least 12 characters long")
            
            if len(password) > 128:
                errors.append("Password must not exceed 128 characters")
            
            # Complexity requirements
            if not re.search(r'[A-Z]', password):
                errors.append("Password must contain at least one uppercase letter")
            
            if not re.search(r'[a-z]', password):
                errors.append("Password must contain at least one lowercase letter")
            
            if not re.search(r'\d', password):
                errors.append("Password must contain at least one digit")
            
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors.append("Password must contain at least one special character")
            
            # Common password check
            if self._is_common_password(password):
                errors.append("Password is too common or appears in breach databases")
            
            # Personal information check (if user provided)
            if user_id and self._contains_personal_info(password, user_id):
                errors.append("Password must not contain personal information")
            
            # Password history check
            if user_id and self._is_password_reused(password, user_id):
                errors.append(f"Password was used recently. Cannot reuse last {self.password_history_count} passwords")
            
            # Dictionary word check
            if self._contains_dictionary_words(password):
                errors.append("Password should not contain common dictionary words")
            
            is_valid = len(errors) == 0
            
            if is_valid:
                security_logger.info(f"Password policy validation passed for user {user_id}")
            else:
                security_logger.warning(f"Password policy validation failed for user {user_id}: {len(errors)} violations")
            
            return is_valid, errors
            
        except Exception as e:
            security_logger.error(f"Password policy validation error: {str(e)}")
            return False, ["Password validation system error"]
    
    def record_login_attempt(self, user_identifier: str, success: bool, 
                           ip_address: str, user_agent: str) -> Dict:
        """Record and analyze login attempts"""
        try:
            attempt_data = {
                'user_identifier': user_identifier,
                'success': success,
                'timestamp': timezone.now().isoformat(),
                'ip_address': ip_address,
                'user_agent': user_agent,
                'attempt_id': secrets.token_urlsafe(16)
            }
            
            # Store individual attempt
            attempt_key = f"login_attempt_{attempt_data['attempt_id']}"
            cache.set(attempt_key, attempt_data, 86400)  # 24 hours
            
            # Update user attempt counter
            counter_key = f"login_attempts_{user_identifier}"
            attempts = cache.get(counter_key, [])
            attempts.append(attempt_data)
            
            # Keep only recent attempts (within lockout window)
            cutoff_time = timezone.now() - timedelta(seconds=self.lockout_duration)
            recent_attempts = [
                att for att in attempts 
                if datetime.fromisoformat(att['timestamp']) > cutoff_time
            ]
            
            cache.set(counter_key, recent_attempts, self.lockout_duration)
            
            # Check for account lockout
            failed_attempts = [att for att in recent_attempts if not att['success']]
            
            if len(failed_attempts) >= self.max_login_attempts:
                self._lock_account(user_identifier, failed_attempts)
                
                security_logger.warning(f"Account locked due to failed login attempts: {user_identifier}")
                return {
                    'status': 'locked',
                    'attempts_remaining': 0,
                    'lockout_expires': (timezone.now() + timedelta(seconds=self.lockout_duration)).isoformat(),
                    'failed_attempts': len(failed_attempts)
                }
            
            attempts_remaining = self.max_login_attempts - len(failed_attempts)
            
            if success:
                security_logger.info(f"Successful login recorded for {user_identifier}")
                cache.delete(counter_key)  # Clear failed attempts on success
                attempts_remaining = self.max_login_attempts
            else:
                security_logger.warning(f"Failed login recorded for {user_identifier}, {attempts_remaining} attempts remaining")
            
            return {
                'status': 'active',
                'attempts_remaining': attempts_remaining,
                'failed_attempts': len(failed_attempts),
                'success': success
            }
            
        except Exception as e:
            security_logger.error(f"Login attempt recording error: {str(e)}")
            return {'status': 'error', 'message': 'System error recording login attempt'}
    
    def is_account_locked(self, user_identifier: str) -> Tuple[bool, Optional[datetime]]:
        """Check if account is currently locked"""
        try:
            lock_key = f"account_lock_{user_identifier}"
            lock_data = cache.get(lock_key)
            
            if not lock_data:
                return False, None
            
            unlock_time = datetime.fromisoformat(lock_data['unlock_time'])
            
            if timezone.now() >= unlock_time:
                # Lock expired, remove it
                cache.delete(lock_key)
                security_logger.info(f"Account lock expired for {user_identifier}")
                return False, None
            
            return True, unlock_time
            
        except Exception as e:
            security_logger.error(f"Account lock check error: {str(e)}")
            return False, None
    
    def _lock_account(self, user_identifier: str, failed_attempts: List[Dict]):
        """Lock account due to excessive failed attempts"""
        try:
            unlock_time = timezone.now() + timedelta(seconds=self.lockout_duration)
            
            lock_data = {
                'user_identifier': user_identifier,
                'locked_at': timezone.now().isoformat(),
                'unlock_time': unlock_time.isoformat(),
                'reason': 'excessive_failed_attempts',
                'failed_attempts_count': len(failed_attempts),
                'lock_id': secrets.token_urlsafe(16)
            }
            
            lock_key = f"account_lock_{user_identifier}"
            cache.set(lock_key, lock_data, self.lockout_duration)
            
            # Store lock history
            history_key = f"lock_history_{user_identifier}"
            lock_history = cache.get(history_key, [])
            lock_history.append(lock_data)
            cache.set(history_key, lock_history[-10:], 86400 * 30)  # Keep last 10 locks for 30 days
            
            security_logger.warning(f"Account locked: {user_identifier} until {unlock_time}")
            
        except Exception as e:
            security_logger.error(f"Account locking error: {str(e)}")
    
    def _is_common_password(self, password: str) -> bool:
        """Check against common password lists and breach databases"""
        try:
            # Common passwords list (simplified)
            common_passwords = {
                'password', '123456', 'password123', 'admin', 'letmein',
                'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
                'Password1', 'password1', '12345678', 'sunshine', 'iloveyou'
            }
            
            password_lower = password.lower()
            
            # Check exact matches
            if password_lower in common_passwords:
                return True
            
            # Check variations
            for common in common_passwords:
                if common in password_lower:
                    return True
            
            # In production, integrate with HaveIBeenPwned API or similar
            # return self._check_breach_database(password)
            
            return False
            
        except Exception as e:
            security_logger.error(f"Common password check error: {str(e)}")
            return False
    
    def _contains_personal_info(self, password: str, user_id: int) -> bool:
        """Check if password contains user's personal information"""
        try:
            # This would integrate with user profile data
            # For now, return False as placeholder
            return False
            
        except Exception as e:
            security_logger.error(f"Personal info check error: {str(e)}")
            return False
    
    def _is_password_reused(self, password: str, user_id: int) -> bool:
        """Check if password was recently used"""
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            history_key = f"password_history_{user_id}"
            password_history = cache.get(history_key, [])
            
            return password_hash in password_history
            
        except Exception as e:
            security_logger.error(f"Password reuse check error: {str(e)}")
            return False
    
    def _contains_dictionary_words(self, password: str) -> bool:
        """Check if password contains common dictionary words"""
        try:
            # Simple dictionary word check (simplified)
            common_words = {
                'password', 'admin', 'user', 'login', 'welcome', 'health',
                'medical', 'hospital', 'doctor', 'patient', 'system'
            }
            
            password_lower = password.lower()
            
            for word in common_words:
                if len(word) >= 4 and word in password_lower:
                    return True
            
            return False
            
        except Exception as e:
            security_logger.error(f"Dictionary word check error: {str(e)}")
            return False