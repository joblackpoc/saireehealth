"""
OWASP Secure Authentication System
Comprehensive authentication security following OWASP guidelines
"""

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpRequest
from django.utils import timezone
from django.conf import settings
import logging
import pyotp
import qrcode
from io import BytesIO
import base64
import json

logger = logging.getLogger('security_enhancements')
User = get_user_model()

class SecureAuthenticationBackend(BaseBackend):
    """
    Enhanced authentication backend with security features
    """
    
    def authenticate(self, request: HttpRequest, username: str = None, password: str = None, **kwargs):
        """Authenticate user with enhanced security checks"""
        
        if not username or not password:
            return None
        
        # Check for account lockout
        if self._is_account_locked(username):
            logger.warning(f"Authentication attempt on locked account: {username}")
            return None
        
        # Check for IP-based lockout
        client_ip = self._get_client_ip(request)
        if self._is_ip_locked(client_ip):
            logger.warning(f"Authentication attempt from locked IP: {client_ip}")
            return None
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # Prevent username enumeration by taking same time as valid user
            self._fake_password_check(password)
            self._record_failed_attempt(username, client_ip)
            return None
        
        # Check if user account is active
        if not user.is_active:
            logger.warning(f"Authentication attempt on inactive account: {username}")
            return None
        
        # Verify password
        if not user.check_password(password):
            self._record_failed_attempt(username, client_ip)
            return None
        
        # Check for password expiration
        if self._is_password_expired(user):
            logger.info(f"Password expired for user: {username}")
            # You might want to redirect to password change instead of blocking
            return None
        
        # Clear failed attempts on successful login
        self._clear_failed_attempts(username, client_ip)
        
        # Log successful authentication
        logger.info(f"Successful authentication for user: {username} from IP: {client_ip}")
        return user
    
    def get_user(self, user_id: int):
        """Get user by ID"""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address"""
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is temporarily locked"""
        key = f"account_lock:{username}"
        return cache.get(key, False)
    
    def _is_ip_locked(self, ip_address: str) -> bool:
        """Check if IP is temporarily locked"""
        key = f"ip_lock:{ip_address}"
        return cache.get(key, False)
    
    def _record_failed_attempt(self, username: str, ip_address: str):
        """Record failed authentication attempt"""
        current_time = time.time()
        
        # Record attempt for username
        username_key = f"failed_attempts:{username}"
        username_attempts = cache.get(username_key, [])
        username_attempts.append(current_time)
        
        # Keep only attempts from last 15 minutes
        username_attempts = [t for t in username_attempts if current_time - t < 900]
        cache.set(username_key, username_attempts, 900)
        
        # Lock account if too many attempts
        if len(username_attempts) >= getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5):
            cache.set(f"account_lock:{username}", True, getattr(settings, 'ACCOUNT_LOCKOUT_TIME', 1800))
            logger.warning(f"Account locked due to failed attempts: {username}")
        
        # Record attempt for IP
        ip_key = f"failed_attempts:{ip_address}"
        ip_attempts = cache.get(ip_key, [])
        ip_attempts.append(current_time)
        
        # Keep only attempts from last 15 minutes
        ip_attempts = [t for t in ip_attempts if current_time - t < 900]
        cache.set(ip_key, ip_attempts, 900)
        
        # Lock IP if too many attempts
        if len(ip_attempts) >= getattr(settings, 'MAX_IP_ATTEMPTS', 10):
            cache.set(f"ip_lock:{ip_address}", True, getattr(settings, 'IP_LOCKOUT_TIME', 3600))
            logger.warning(f"IP locked due to failed attempts: {ip_address}")
    
    def _clear_failed_attempts(self, username: str, ip_address: str):
        """Clear failed attempt records"""
        cache.delete(f"failed_attempts:{username}")
        cache.delete(f"failed_attempts:{ip_address}")
        cache.delete(f"account_lock:{username}")
    
    def _fake_password_check(self, password: str):
        """Fake password check to prevent timing attacks"""
        # Simulate the time it takes to hash a password
        fake_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), b'fake_salt', 100000)
    
    def _is_password_expired(self, user) -> bool:
        """Check if user's password has expired"""
        if not hasattr(user, 'password_changed_date'):
            return False
        
        password_age_limit = getattr(settings, 'PASSWORD_AGE_LIMIT_DAYS', 90)
        if user.password_changed_date:
            expiry_date = user.password_changed_date + timedelta(days=password_age_limit)
            return timezone.now() > expiry_date
        
        return False


class MultiFactorAuthentication:
    """
    Multi-Factor Authentication implementation
    """
    
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate TOTP secret for user"""
        return secrets.token_hex(20)
    
    @staticmethod
    def generate_qr_code(user, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            user.email,
            issuer_name=getattr(settings, 'TOTP_ISSUER', 'HealthProgress')
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    @staticmethod
    def verify_totp(secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    @staticmethod
    def generate_backup_codes(count: int = 8) -> List[str]:
        """Generate backup codes for MFA recovery"""
        codes = []
        for _ in range(count):
            code = ''.join([secrets.choice('0123456789') for _ in range(8)])
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes
    
    @staticmethod
    def hash_backup_code(code: str) -> str:
        """Hash backup code for secure storage"""
        return hashlib.sha256(code.encode()).hexdigest()


class SessionSecurity:
    """
    Enhanced session security management
    """
    
    @staticmethod
    def create_secure_session(request: HttpRequest, user) -> Dict[str, Any]:
        """Create secure session with additional security measures"""
        session_data = {
            'user_id': user.id,
            'created_at': timezone.now().isoformat(),
            'ip_address': SessionSecurity._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
            'session_token': secrets.token_urlsafe(32)
        }
        
        # Store session fingerprint
        request.session['security_fingerprint'] = SessionSecurity._generate_fingerprint(request)
        request.session['created_at'] = session_data['created_at']
        request.session['last_activity'] = timezone.now().isoformat()
        
        # Set secure session configuration
        request.session.set_expiry(getattr(settings, 'SESSION_COOKIE_AGE', 3600))
        
        return session_data
    
    @staticmethod
    def validate_session(request: HttpRequest) -> bool:
        """Validate session security"""
        if not request.session.session_key:
            return False
        
        # Check session fingerprint
        stored_fingerprint = request.session.get('security_fingerprint')
        current_fingerprint = SessionSecurity._generate_fingerprint(request)
        
        if stored_fingerprint != current_fingerprint:
            logger.warning(f"Session fingerprint mismatch for user {request.user.id if request.user.is_authenticated else 'anonymous'}")
            return False
        
        # Check session age
        created_at = request.session.get('created_at')
        if created_at:
            created_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            max_age = timedelta(hours=getattr(settings, 'SESSION_MAX_AGE_HOURS', 24))
            
            if timezone.now() - created_time > max_age:
                logger.info("Session expired due to age")
                return False
        
        # Update last activity
        request.session['last_activity'] = timezone.now().isoformat()
        
        return True
    
    @staticmethod
    def _generate_fingerprint(request: HttpRequest) -> str:
        """Generate session fingerprint"""
        components = [
            request.META.get('HTTP_USER_AGENT', ''),
            request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
            request.META.get('HTTP_ACCEPT_ENCODING', ''),
            SessionSecurity._get_client_ip(request)
        ]
        
        fingerprint_data = '|'.join(components)
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    @staticmethod
    def _get_client_ip(request: HttpRequest) -> str:
        """Get client IP address"""
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class PasswordPolicy:
    """
    Advanced password policy implementation
    """
    
    @staticmethod
    def validate_password_strength(password: str, user=None) -> Dict[str, Any]:
        """Comprehensive password strength validation"""
        result = {
            'valid': True,
            'score': 0,
            'errors': [],
            'suggestions': []
        }
        
        # Length check
        if len(password) < 12:
            result['valid'] = False
            result['errors'].append("Password must be at least 12 characters long")
        elif len(password) >= 16:
            result['score'] += 2
        else:
            result['score'] += 1
        
        # Character variety
        char_types = {
            'lowercase': any(c.islower() for c in password),
            'uppercase': any(c.isupper() for c in password),
            'digits': any(c.isdigit() for c in password),
            'special': any(not c.isalnum() for c in password)
        }
        
        char_type_count = sum(char_types.values())
        if char_type_count < 3:
            result['valid'] = False
            result['errors'].append("Password must contain at least 3 different character types")
        else:
            result['score'] += char_type_count
        
        # Check for common patterns
        if PasswordPolicy._has_sequential_chars(password):
            result['score'] -= 2
            result['suggestions'].append("Avoid sequential characters")
        
        if PasswordPolicy._has_repeated_patterns(password):
            result['score'] -= 2
            result['suggestions'].append("Avoid repeated patterns")
        
        # Check against user information
        if user and PasswordPolicy._contains_user_info(password, user):
            result['valid'] = False
            result['errors'].append("Password should not contain personal information")
        
        # Check against common passwords
        if PasswordPolicy._is_common_password(password):
            result['valid'] = False
            result['errors'].append("Password is too common")
        
        # Normalize score
        result['score'] = max(0, min(10, result['score']))
        
        return result
    
    @staticmethod
    def _has_sequential_chars(password: str, min_length: int = 4) -> bool:
        """Check for sequential characters"""
        sequences = [
            '0123456789', '9876543210',
            'abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
        ]
        
        password_lower = password.lower()
        
        for seq in sequences:
            for i in range(len(seq) - min_length + 1):
                if seq[i:i + min_length] in password_lower:
                    return True
        
        return False
    
    @staticmethod
    def _has_repeated_patterns(password: str, min_length: int = 3) -> bool:
        """Check for repeated patterns"""
        # Check for repeated characters
        import re
        if re.search(r'(.)\1{2,}', password):
            return True
        
        # Check for repeated substrings
        for i in range(len(password) - min_length):
            pattern = password[i:i + min_length]
            if password.count(pattern) > 1:
                return True
        
        return False
    
    @staticmethod
    def _contains_user_info(password: str, user):
        """Check if password contains user information"""
        password_lower = password.lower()
        
        user_info = [
            user.username.lower() if user.username else '',
            user.first_name.lower() if hasattr(user, 'first_name') and user.first_name else '',
            user.last_name.lower() if hasattr(user, 'last_name') and user.last_name else '',
            user.email.split('@')[0].lower() if user.email else ''
        ]
        
        for info in user_info:
            if info and len(info) > 2 and info in password_lower:
                return True
        
        return False
    
    @staticmethod
    def _is_common_password(password: str) -> bool:
        """Check against common passwords"""
        common_passwords = [
            'password', '123456', '123456789', '12345678', '12345',
            'qwerty', 'abc123', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'dragon', 'master',
            'iloveyou', 'sunshine', 'princess', 'football', 'charlie',
            'aa123456', 'donald', 'password1', 'qwerty123'
        ]
        
        return password.lower() in common_passwords


class AuthenticationLogger:
    """
    Comprehensive authentication event logging
    """
    
    @staticmethod
    def log_login_attempt(username: str, ip_address: str, success: bool, **kwargs):
        """Log login attempt"""
        event_data = {
            'event': 'login_attempt',
            'username': username,
            'ip_address': ip_address,
            'success': success,
            'timestamp': timezone.now().isoformat(),
            **kwargs
        }
        
        if success:
            logger.info(f"Successful login: {username} from {ip_address}", extra=event_data)
        else:
            logger.warning(f"Failed login: {username} from {ip_address}", extra=event_data)
    
    @staticmethod
    def log_logout(username: str, ip_address: str, **kwargs):
        """Log logout event"""
        event_data = {
            'event': 'logout',
            'username': username,
            'ip_address': ip_address,
            'timestamp': timezone.now().isoformat(),
            **kwargs
        }
        
        logger.info(f"User logout: {username} from {ip_address}", extra=event_data)
    
    @staticmethod
    def log_password_change(username: str, ip_address: str, **kwargs):
        """Log password change"""
        event_data = {
            'event': 'password_change',
            'username': username,
            'ip_address': ip_address,
            'timestamp': timezone.now().isoformat(),
            **kwargs
        }
        
        logger.info(f"Password changed: {username} from {ip_address}", extra=event_data)
    
    @staticmethod
    def log_mfa_event(username: str, ip_address: str, event_type: str, success: bool, **kwargs):
        """Log MFA event"""
        event_data = {
            'event': f'mfa_{event_type}',
            'username': username,
            'ip_address': ip_address,
            'success': success,
            'timestamp': timezone.now().isoformat(),
            **kwargs
        }
        
        logger.info(f"MFA {event_type}: {username} from {ip_address} - Success: {success}", extra=event_data)
    
    @staticmethod
    def log_security_event(event_type: str, username: str, ip_address: str, details: Dict[str, Any]):
        """Log general security event"""
        event_data = {
            'event': event_type,
            'username': username,
            'ip_address': ip_address,
            'timestamp': timezone.now().isoformat(),
            'details': details
        }
        
        logger.warning(f"Security event {event_type}: {username} from {ip_address}", extra=event_data)