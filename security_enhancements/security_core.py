"""
Enhanced Security Core Utilities for HealthProgress
Comprehensive security functions including threat detection, logging, and sanitization
"""
import re
import hashlib
import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from django.core.cache import cache
from django.conf import settings
from cryptography.fernet import Fernet
import pyotp
try:
    from bleach import clean
except ImportError:
    # Fallback HTML sanitizer if bleach is not available
    def clean(text, tags=None, attributes=None, strip=False):
        import html
        # Basic HTML escaping as fallback
        return html.escape(text)

# Configure security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

class SecurityLogger:
    """Enhanced Security Event Logging System"""
    
    @staticmethod
    def log_security_event(event_type: str, severity: str, details: Dict[str, Any], 
                          request=None, user=None):
        """
        Log security events with comprehensive details
        
        Args:
            event_type: Type of security event (sql_injection, xss, etc.)
            severity: critical, high, medium, low
            details: Dictionary with event details
            request: Django request object
            user: User object if authenticated
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'details': details
        }
        
        if request:
            log_entry.update({
                'ip': SecurityCore.get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'path': request.path,
                'method': request.method,
            })
        
        if user:
            log_entry['user_id'] = user.id
            log_entry['username'] = user.username
        
        # Log to file
        security_logger.warning(json.dumps(log_entry))
        
        # Store in cache for real-time monitoring
        cache_key = f"security_events:{datetime.now().strftime('%Y%m%d')}"
        events = cache.get(cache_key, [])
        events.append(log_entry)
        cache.set(cache_key, events, timeout=86400)  # 24 hours
        
        # Increment metrics
        SecurityCore.increment_security_metric(event_type)
        
        # Check for IP blocking
        if severity in ['critical', 'high'] and request:
            SecurityCore.check_and_block_ip(request, event_type)
    
    @staticmethod
    def get_recent_events(hours: int = 24) -> List[Dict]:
        """Get recent security events"""
        events = []
        for i in range(hours // 24 + 1):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            cache_key = f"security_events:{date}"
            events.extend(cache.get(cache_key, []))
        return events


class ThreatDetector:
    """Advanced Threat Detection Engine"""
    
    # Enhanced SQL Injection Patterns
    SQL_PATTERNS = [
        # UNION attacks
        r"\bUNION\s+(ALL\s+)?SELECT\b",
        # Time-based blind
        r"\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\b",
        # Boolean-based blind
        r"\b(AND|OR)\s+\d+\s*=\s*\d+",
        # Stacked queries
        r";\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)\b",
        # Comment injection
        r"(/\*|\*/|--|#)",
        # String concatenation
        r"CONCAT\s*\(",
        # Information schema
        r"\bINFORMATION_SCHEMA\b",
        # Database functions
        r"\b(DATABASE|VERSION|USER|CURRENT_USER)\s*\(\)",
        # Hex encoding
        r"0x[0-9a-fA-F]+",
    ]
    
    # Enhanced XSS Patterns
    XSS_PATTERNS = [
        # Script tags
        r"<\s*script\b",
        # Event handlers
        r"\bon\w+\s*=",
        # JavaScript protocol
        r"\bjavascript:",
        # Data protocol
        r"\bdata:text/html",
        # SVG attacks
        r"<\s*svg\b",
        # Base64 encoding
        r"\batob\s*\(",
        # Template literals
        r"`.*\$\{.*\}.*`",
        # Unicode escapes
        r"\\u[0-9a-fA-F]{4}",
        # HTML entities
        r"&#x?[0-9a-fA-F]+;",
    ]
    
    # Path Traversal Patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e[/\\]",
        r"\x2e\x2e[/\\]",
        r"file://",
        r"^/etc/",
        r"^/proc/",
        r"\x00",  # Null byte
    ]
    
    # Command Injection Patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[|&;`$]",
        r"\$\(.*\)",
        r"`.*`",
        r"\beval\b",
        r"\bexec\b",
        r"\bsystem\b",
        r"\bpassthru\b",
        r"\bshell_exec\b",
    ]
    
    # LDAP Injection Patterns
    LDAP_PATTERNS = [
        r"\*\)",
        r"\(\|",
        r"\(&",
        r"\(!\(",
    ]
    
    # NoSQL Injection Patterns
    NOSQL_PATTERNS = [
        r"\$where",
        r"\$ne",
        r"\$gt",
        r"\$regex",
        r"\{\s*\$",
    ]
    
    # XXE Patterns
    XXE_PATTERNS = [
        r"<!ENTITY",
        r"SYSTEM",
        r"<!DOCTYPE",
        r"file://",
        r"php://",
    ]
    
    @classmethod
    def detect_sql_injection(cls, value: str) -> bool:
        """Detect SQL injection attempts"""
        if not value:
            return False
        value = value.lower()
        return any(re.search(pattern, value, re.IGNORECASE) for pattern in cls.SQL_PATTERNS)
    
    @classmethod
    def detect_xss(cls, value: str) -> bool:
        """Detect XSS attempts"""
        if not value:
            return False
        return any(re.search(pattern, value, re.IGNORECASE) for pattern in cls.XSS_PATTERNS)
    
    @classmethod
    def detect_path_traversal(cls, value: str) -> bool:
        """Detect path traversal attempts"""
        if not value:
            return False
        return any(re.search(pattern, value, re.IGNORECASE) for pattern in cls.PATH_TRAVERSAL_PATTERNS)
    
    @classmethod
    def detect_command_injection(cls, value: str) -> bool:
        """Detect command injection attempts"""
        if not value:
            return False
        return any(re.search(pattern, value) for pattern in cls.COMMAND_INJECTION_PATTERNS)
    
    @classmethod
    def detect_ldap_injection(cls, value: str) -> bool:
        """Detect LDAP injection attempts"""
        if not value:
            return False
        return any(re.search(pattern, value) for pattern in cls.LDAP_PATTERNS)
    
    @classmethod
    def detect_nosql_injection(cls, value: str) -> bool:
        """Detect NoSQL injection attempts"""
        if not value:
            return False
        return any(re.search(pattern, value) for pattern in cls.NOSQL_PATTERNS)
    
    @classmethod
    def detect_xxe(cls, value: str) -> bool:
        """Detect XXE attempts"""
        if not value:
            return False
        return any(re.search(pattern, value, re.IGNORECASE) for pattern in cls.XXE_PATTERNS)
    
    @classmethod
    def detect_all_threats(cls, value: str) -> Dict[str, bool]:
        """Detect all threat types"""
        if not value:
            return {}
        
        return {
            'sql_injection': cls.detect_sql_injection(value),
            'xss': cls.detect_xss(value),
            'path_traversal': cls.detect_path_traversal(value),
            'command_injection': cls.detect_command_injection(value),
            'ldap_injection': cls.detect_ldap_injection(value),
            'nosql_injection': cls.detect_nosql_injection(value),
            'xxe': cls.detect_xxe(value),
        }


class SecurityCore:
    """Core Security Functions"""
    
    @staticmethod
    def get_client_ip(request) -> str:
        """Extract client IP with proxy support"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        
        # Validate IP format
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            return 'unknown'
        return ip
    
    @staticmethod
    def parse_user_agent(user_agent: str) -> Dict[str, Any]:
        """Parse user agent for device and browser info"""
        info = {
            'is_bot': False,
            'is_mobile': False,
            'browser': 'unknown',
            'os': 'unknown',
        }
        
        if not user_agent:
            return info
        
        user_agent_lower = user_agent.lower()
        
        # Bot detection
        bot_patterns = ['bot', 'crawler', 'spider', 'scraper']
        info['is_bot'] = any(pattern in user_agent_lower for pattern in bot_patterns)
        
        # Mobile detection
        mobile_patterns = ['mobile', 'android', 'iphone', 'ipad']
        info['is_mobile'] = any(pattern in user_agent_lower for pattern in mobile_patterns)
        
        # Browser detection
        if 'chrome' in user_agent_lower:
            info['browser'] = 'chrome'
        elif 'firefox' in user_agent_lower:
            info['browser'] = 'firefox'
        elif 'safari' in user_agent_lower:
            info['browser'] = 'safari'
        elif 'edge' in user_agent_lower:
            info['browser'] = 'edge'
        
        # OS detection
        if 'windows' in user_agent_lower:
            info['os'] = 'windows'
        elif 'mac' in user_agent_lower:
            info['os'] = 'macos'
        elif 'linux' in user_agent_lower:
            info['os'] = 'linux'
        elif 'android' in user_agent_lower:
            info['os'] = 'android'
        elif 'ios' in user_agent_lower:
            info['os'] = 'ios'
        
        return info
    
    @staticmethod
    def check_and_block_ip(request, reason: str):
        """Check and potentially block IP based on security events"""
        ip = SecurityCore.get_client_ip(request)
        cache_key = f"security_violations:{ip}"
        
        violations = cache.get(cache_key, [])
        violations.append({
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
        })
        
        # Block IP if too many violations
        if len(violations) >= getattr(settings, 'IP_BLOCK_THRESHOLD', 5):
            block_key = f"blocked_ip:{ip}"
            cache.set(block_key, True, timeout=3600)  # Block for 1 hour
            SecurityLogger.log_security_event(
                'ip_blocked',
                'critical',
                {'ip': ip, 'violations': len(violations)},
                request=request
            )
        
        cache.set(cache_key, violations, timeout=300)  # 5 minutes
    
    @staticmethod
    def is_ip_blocked(request) -> bool:
        """Check if IP is blocked"""
        ip = SecurityCore.get_client_ip(request)
        block_key = f"blocked_ip:{ip}"
        return cache.get(block_key, False)
    
    @staticmethod
    def increment_security_metric(metric_name: str):
        """Increment security metric counter"""
        cache_key = f"security_metric:{metric_name}:{datetime.now().strftime('%Y%m%d')}"
        count = cache.get(cache_key, 0)
        cache.set(cache_key, count + 1, timeout=86400)
    
    @staticmethod
    def get_security_metrics(days: int = 7) -> Dict[str, int]:
        """Get security metrics for specified days"""
        metrics = {}
        metric_types = [
            'sql_injection', 'xss', 'path_traversal', 'command_injection',
            'ldap_injection', 'nosql_injection', 'xxe', 'ip_blocked'
        ]
        
        for metric_type in metric_types:
            total = 0
            for i in range(days):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
                cache_key = f"security_metric:{metric_type}:{date}"
                total += cache.get(cache_key, 0)
            metrics[metric_type] = total
        
        return metrics


class InputSanitizer:
    """Input Sanitization Engine"""
    
    @staticmethod
    def sanitize_text(value: str, max_length: int = 1000) -> str:
        """Sanitize plain text input"""
        if not value:
            return ""
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Limit length
        value = value[:max_length]
        
        # Remove control characters except newlines and tabs
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t')
        
        return value.strip()
    
    @staticmethod
    def sanitize_html(value: str, allowed_tags: List[str] = None) -> str:
        """Sanitize HTML input"""
        if not value:
            return ""
        
        if allowed_tags is None:
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a']
        
        allowed_attributes = {'a': ['href', 'title']}
        
        return clean(
            value,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
    
    @staticmethod
    def sanitize_email(value: str) -> str:
        """Sanitize email input"""
        if not value:
            return ""
        
        value = value.strip().lower()
        
        # Basic email validation
        if not re.match(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$', value):
            return ""
        
        return value
    
    @staticmethod
    def sanitize_filename(value: str) -> str:
        """Sanitize filename"""
        if not value:
            return ""
        
        # Remove path separators
        value = value.replace('/', '').replace('\\', '')
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Only allow alphanumeric, dots, dashes, underscores
        value = re.sub(r'[^a-zA-Z0-9._-]', '_', value)
        
        # Limit length
        value = value[:255]
        
        return value
    
    @staticmethod
    def sanitize_url(value: str) -> str:
        """Sanitize URL input"""
        if not value:
            return ""
        
        value = value.strip()
        
        # Only allow http(s) protocols
        if not re.match(r'^https?://', value):
            return ""
        
        # Check for suspicious patterns
        suspicious = ['javascript:', 'data:', 'vbscript:', 'file:']
        if any(pattern in value.lower() for pattern in suspicious):
            return ""
        
        return value


class CryptoUtils:
    """Cryptographic Utilities"""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256 (use Django's built-in for production)"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def generate_totp_secret() -> str:
        """Generate TOTP secret for 2FA"""
        return pyotp.random_base32()
    
    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    @staticmethod
    def encrypt_data(data: str, key: bytes = None) -> str:
        """Encrypt data using Fernet"""
        if key is None:
            key = getattr(settings, 'FERNET_SECRET_KEY', Fernet.generate_key())
        
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return encrypted.decode()
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes = None) -> str:
        """Decrypt data using Fernet"""
        if key is None:
            key = getattr(settings, 'FERNET_SECRET_KEY', Fernet.generate_key())
        
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data.encode())
        return decrypted.decode()
    
    @staticmethod
    def calculate_password_strength(password: str) -> Dict[str, Any]:
        """Calculate password strength score"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")
        
        # Complexity checks
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 2
        
        # Common patterns check
        common_patterns = ['123', 'abc', 'password', 'qwerty']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("Avoid common patterns")
        
        strength = 'weak'
        if score >= 7:
            strength = 'strong'
        elif score >= 4:
            strength = 'medium'
        
        return {
            'score': max(0, score),
            'strength': strength,
            'feedback': feedback
        }