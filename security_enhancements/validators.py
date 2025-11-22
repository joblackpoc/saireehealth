"""
OWASP Django Security Validators
Comprehensive input validation following OWASP guidelines
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
import logging

logger = logging.getLogger('security_enhancements')

class OWASPPasswordValidator:
    """
    Enhanced password validator following OWASP password guidelines
    """
    
    def __init__(self, min_length=12, max_length=128):
        self.min_length = min_length
        self.max_length = max_length
    
    def validate(self, password, user=None):
        """Validate password against OWASP requirements"""
        errors = []
        
        # Length validation
        if len(password) < self.min_length:
            errors.append(
                ValidationError(
                    _('Password must be at least %(min_length)d characters long.'),
                    code='password_too_short',
                    params={'min_length': self.min_length}
                )
            )
        
        if len(password) > self.max_length:
            errors.append(
                ValidationError(
                    _('Password must not exceed %(max_length)d characters.'),
                    code='password_too_long',
                    params={'max_length': self.max_length}
                )
            )
        
        # Character variety validation
        has_upper = re.search(r'[A-Z]', password)
        has_lower = re.search(r'[a-z]', password)
        has_digit = re.search(r'\d', password)
        has_special = re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password)
        
        char_types = sum([bool(has_upper), bool(has_lower), bool(has_digit), bool(has_special)])
        
        if char_types < 3:
            errors.append(
                ValidationError(
                    _('Password must contain at least 3 of the following: uppercase letters, lowercase letters, digits, special characters.'),
                    code='password_no_variety'
                )
            )
        
        # Check for common patterns
        if self._has_common_patterns(password):
            errors.append(
                ValidationError(
                    _('Password contains common patterns that are easily guessed.'),
                    code='password_common_patterns'
                )
            )
        
        # Check against user information
        if user and self._similar_to_user_info(password, user):
            errors.append(
                ValidationError(
                    _('Password is too similar to your personal information.'),
                    code='password_too_similar'
                )
            )
        
        if errors:
            raise ValidationError(errors)
    
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common password patterns"""
        password_lower = password.lower()
        
        # Sequential characters
        sequences = [
            '123456789', '987654321', 'abcdefghij', 'zyxwvutsrq',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm'
        ]
        
        for seq in sequences:
            for i in range(len(seq) - 3):
                if seq[i:i+4] in password_lower:
                    return True
        
        # Repeated patterns
        if re.search(r'(.)\1{3,}', password):  # Same character repeated 4+ times
            return True
        
        if re.search(r'(.{2,})\1{2,}', password):  # Pattern repeated 3+ times
            return True
        
        return False
    
    def _similar_to_user_info(self, password: str, user) -> bool:
        """Check if password is similar to user information"""
        user_info = []
        
        if hasattr(user, 'username'):
            user_info.append(user.username.lower())
        if hasattr(user, 'email'):
            user_info.append(user.email.lower().split('@')[0])
        if hasattr(user, 'first_name'):
            user_info.append(user.first_name.lower())
        if hasattr(user, 'last_name'):
            user_info.append(user.last_name.lower())
        
        password_lower = password.lower()
        
        for info in user_info:
            if info and len(info) > 3:
                if info in password_lower or password_lower in info:
                    return True
        
        return False
    
    def get_help_text(self):
        return _(
            'Your password must be at least %(min_length)d characters long, '
            'contain at least 3 different types of characters (uppercase, lowercase, digits, special characters), '
            'and not contain common patterns or personal information.'
        ) % {'min_length': self.min_length}


class InputValidator:
    """
    Comprehensive input validator for preventing injection attacks
    """
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r"('|(\\'))+.*(\\').*(('|(\\'))|($))",
        r"((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"union\s+.*select",
        r"select.*from",
        r"insert\s+into",
        r"delete\s+from",
        r"update.*set",
        r"drop\s+table",
        r"create\s+table",
        r"alter\s+table",
        r"exec\s*\(",
        r"execute\s*\(",
        r"sp_\w+",
        r"xp_\w+",
        r"/\*.*\*/",
        r"--.*$",
        r";\s*(drop|delete|insert|update|create|alter)",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>",
        r"<applet[^>]*>.*?</applet>",
        r"<meta[^>]*>",
        r"<link[^>]*>",
        r"<form[^>]*>.*?</form>",
        r"<input[^>]*>",
        r"<textarea[^>]*>.*?</textarea>",
        r"<img[^>]*onerror",
        r"<svg[^>]*>.*?</svg>",
        r"expression\s*\(",
        r"url\s*\(",
        r"@import",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"..%2f",
        r"%2e%2e%5c",
        r"..%5c",
        r"%252e%252e%252f",
        r"..%252f",
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]",
        r"\$\(",
        r"`.*`",
        r"\|\s*(cat|ls|pwd|id|whoami|ps|netstat|ifconfig)",
        r";\s*(cat|ls|pwd|id|whoami|ps|netstat|ifconfig)",
        r"&&\s*(cat|ls|pwd|id|whoami|ps|netstat|ifconfig)",
        r"\|\|\s*(cat|ls|pwd|id|whoami|ps|netstat|ifconfig)",
    ]
    
    # LDAP injection patterns
    LDAP_INJECTION_PATTERNS = [
        r"[*()\\&|!>=<~]",
        r"\(\s*\|\s*\(",
        r"\(\s*&\s*\(",
        r"objectclass\s*=",
        r"cn\s*=",
        r"uid\s*=",
    ]
    
    @classmethod
    def validate_input(cls, value: str, input_type: str = 'general') -> bool:
        """
        Validate input against injection patterns
        
        Args:
            value: Input value to validate
            input_type: Type of input (general, sql, xss, path, command, ldap)
        
        Returns:
            True if input is safe, False if potentially malicious
        """
        if not isinstance(value, str):
            return True
        
        value = value.lower()
        
        patterns_to_check = []
        
        if input_type == 'sql':
            patterns_to_check = cls.SQL_INJECTION_PATTERNS
        elif input_type == 'xss':
            patterns_to_check = cls.XSS_PATTERNS
        elif input_type == 'path':
            patterns_to_check = cls.PATH_TRAVERSAL_PATTERNS
        elif input_type == 'command':
            patterns_to_check = cls.COMMAND_INJECTION_PATTERNS
        elif input_type == 'ldap':
            patterns_to_check = cls.LDAP_INJECTION_PATTERNS
        else:  # general - check all patterns
            patterns_to_check = (
                cls.SQL_INJECTION_PATTERNS +
                cls.XSS_PATTERNS +
                cls.PATH_TRAVERSAL_PATTERNS +
                cls.COMMAND_INJECTION_PATTERNS +
                cls.LDAP_INJECTION_PATTERNS
            )
        
        for pattern in patterns_to_check:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                logger.warning(f"Malicious pattern detected: {pattern} in input: {value[:100]}...")
                return False
        
        return True
    
    @classmethod
    def sanitize_input(cls, value: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize input by removing/encoding dangerous characters
        
        Args:
            value: Input to sanitize
            max_length: Maximum allowed length
        
        Returns:
            Sanitized input
        """
        if not isinstance(value, str):
            return str(value)
        
        # Remove null bytes and control characters
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\t\n\r')
        
        # Normalize whitespace
        value = ' '.join(value.split())
        
        # Truncate if necessary
        if max_length and len(value) > max_length:
            value = value[:max_length]
        
        return value
    
    @classmethod
    def validate_email(cls, email: str) -> bool:
        """Enhanced email validation"""
        # Basic format check
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[<>"\']',  # Suspicious characters
            r'javascript:',
            r'data:',
            r'\.\.',  # Path traversal
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return False
        
        return True
    
    @classmethod
    def validate_url(cls, url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
        """
        Validate URL to prevent SSRF and other attacks
        
        Args:
            url: URL to validate
            allowed_schemes: List of allowed URL schemes
        
        Returns:
            True if URL is safe, False otherwise
        """
        if not url:
            return False
        
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
        
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme.lower() not in allowed_schemes:
                return False
            
            # Block dangerous schemes
            dangerous_schemes = ['file', 'ftp', 'gopher', 'dict', 'ldap', 'sftp']
            if parsed.scheme.lower() in dangerous_schemes:
                return False
            
            # Validate hostname
            if not parsed.hostname:
                return False
            
            # Block internal IP addresses
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved:
                    return False
            except ValueError:
                pass  # Not an IP address, continue with hostname validation
            
            # Block localhost variations
            localhost_patterns = [
                r'^localhost$',
                r'^127\.',
                r'^0\.0\.0\.0$',
                r'^::1$',
                r'^0:0:0:0:0:0:0:1$',
            ]
            
            for pattern in localhost_patterns:
                if re.match(pattern, parsed.hostname, re.IGNORECASE):
                    return False
            
            return True
            
        except Exception:
            return False
    
    @classmethod
    def validate_filename(cls, filename: str) -> bool:
        """
        Validate uploaded filename
        
        Args:
            filename: Filename to validate
        
        Returns:
            True if filename is safe, False otherwise
        """
        if not filename:
            return False
        
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        # Check for dangerous extensions
        dangerous_extensions = [
            'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js',
            'jar', 'jsp', 'php', 'asp', 'aspx', 'sh', 'ps1', 'py'
        ]
        
        if '.' in filename:
            extension = filename.split('.')[-1].lower()
            if extension in dangerous_extensions:
                return False
        
        # Check for suspicious characters
        suspicious_chars = ['<', '>', ':', '"', '|', '?', '*', '\x00']
        for char in suspicious_chars:
            if char in filename:
                return False
        
        # Check length
        if len(filename) > 255:
            return False
        
        return True
    
    @classmethod
    def validate_json_input(cls, json_str: str, max_depth: int = 10, max_length: int = 10000) -> bool:
        """
        Validate JSON input for security
        
        Args:
            json_str: JSON string to validate
            max_depth: Maximum nesting depth
            max_length: Maximum JSON string length
        
        Returns:
            True if JSON is safe, False otherwise
        """
        if len(json_str) > max_length:
            return False
        
        try:
            import json
            
            def check_depth(obj, depth=0):
                if depth > max_depth:
                    return False
                
                if isinstance(obj, dict):
                    for value in obj.values():
                        if not check_depth(value, depth + 1):
                            return False
                elif isinstance(obj, list):
                    for item in obj:
                        if not check_depth(item, depth + 1):
                            return False
                
                return True
            
            parsed = json.loads(json_str)
            return check_depth(parsed)
            
        except (json.JSONDecodeError, RecursionError):
            return False


class FileValidator:
    """File upload security validator"""
    
    ALLOWED_MIME_TYPES = {
        'image': [
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'image/bmp'
        ],
        'document': [
            'application/pdf',
            'text/plain',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ],
        'archive': [
            'application/zip',
            'application/x-rar-compressed'
        ]
    }
    
    MAX_FILE_SIZES = {
        'image': 5 * 1024 * 1024,      # 5MB
        'document': 10 * 1024 * 1024,   # 10MB
        'archive': 50 * 1024 * 1024,    # 50MB
        'default': 2 * 1024 * 1024      # 2MB
    }
    
    @classmethod
    def validate_file(cls, file_obj, file_type: str = 'default') -> Dict[str, Any]:
        """
        Comprehensive file validation
        
        Args:
            file_obj: Uploaded file object
            file_type: Type of file (image, document, archive, default)
        
        Returns:
            Dict with validation results
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check file size
        max_size = cls.MAX_FILE_SIZES.get(file_type, cls.MAX_FILE_SIZES['default'])
        if hasattr(file_obj, 'size') and file_obj.size > max_size:
            result['valid'] = False
            result['errors'].append(f'File size ({file_obj.size} bytes) exceeds maximum allowed ({max_size} bytes)')
        
        # Check filename
        filename = getattr(file_obj, 'name', '')
        if not InputValidator.validate_filename(filename):
            result['valid'] = False
            result['errors'].append('Invalid filename')
        
        # Check MIME type
        if file_type in cls.ALLOWED_MIME_TYPES:
            allowed_types = cls.ALLOWED_MIME_TYPES[file_type]
            if not cls._validate_mime_type(file_obj, allowed_types):
                result['valid'] = False
                result['errors'].append('Invalid file type')
        
        # Check for malicious content
        if hasattr(file_obj, 'read'):
            file_content = file_obj.read(1024)  # Read first 1KB
            file_obj.seek(0)  # Reset file pointer
            
            if cls._contains_malicious_content(file_content):
                result['valid'] = False
                result['errors'].append('File contains potentially malicious content')
        
        return result
    
    @classmethod
    def _validate_mime_type(cls, file_obj, allowed_types: List[str]) -> bool:
        """Validate file MIME type"""
        try:
            import magic
            
            # Read a sample to determine MIME type
            file_sample = file_obj.read(1024)
            file_obj.seek(0)  # Reset file pointer
            
            mime_type = magic.from_buffer(file_sample, mime=True)
            return mime_type in allowed_types
            
        except ImportError:
            # Fallback to filename extension checking
            filename = getattr(file_obj, 'name', '')
            if not filename or '.' not in filename:
                return False
            
            extension = filename.split('.')[-1].lower()
            extension_mapping = {
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'png': 'image/png',
                'gif': 'image/gif',
                'pdf': 'application/pdf',
                'txt': 'text/plain',
            }
            
            inferred_mime = extension_mapping.get(extension)
            return inferred_mime in allowed_types if inferred_mime else False
    
    @classmethod
    def _contains_malicious_content(cls, content: bytes) -> bool:
        """Check file content for malicious patterns"""
        # Convert to string for pattern matching (handle encoding errors)
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
        except UnicodeDecodeError:
            content_str = str(content).lower()
        
        # Check for suspicious patterns in file content
        malicious_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'<?php',
            r'<%.*%>',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\(',
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, content_str, re.IGNORECASE):
                return True
        
        return False