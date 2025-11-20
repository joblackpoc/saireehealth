"""
Advanced Sanitization Framework for HealthProgress
Comprehensive input/output sanitization with multi-encoding support
Expert Blue Team Implementation - ETH Standards
"""
import re
import html
import json
import base64
import urllib.parse
from typing import Dict, Any, List, Optional, Union
from django.utils.html import escape, strip_tags
from django.core.exceptions import ValidationError
from .security_core import SecurityLogger

# Try to import bleach for advanced HTML cleaning
try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False


class AdvancedSanitizer:
    """
    Multi-vector input sanitization engine with encoding detection and normalization
    """
    
    # Allowed HTML tags and attributes for rich text content
    ALLOWED_HTML_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'
    ]
    
    ALLOWED_HTML_ATTRIBUTES = {
        '*': ['class'],
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height']
    }
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js',
        '.jar', '.app', '.deb', '.pkg', '.dmg', '.sh', '.ps1', '.php',
        '.asp', '.aspx', '.jsp', '.py', '.pl', '.rb', '.cgi'
    }
    
    def __init__(self):
        self.encoding_patterns = self._compile_encoding_patterns()
    
    def _compile_encoding_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for various encoding detection"""
        return {
            'html_entities': re.compile(r'&[a-zA-Z][a-zA-Z0-9]*;|&#[0-9]+;|&#x[0-9a-fA-F]+;'),
            'url_encoded': re.compile(r'%[0-9a-fA-F]{2}'),
            'unicode_escaped': re.compile(r'\\u[0-9a-fA-F]{4}'),
            'hex_encoded': re.compile(r'0x[0-9a-fA-F]+'),
            'base64_pattern': re.compile(r'[A-Za-z0-9+/]*[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}='),
            'double_encoding': re.compile(r'%25[0-9a-fA-F]{2}'),
            'null_bytes': re.compile(r'%00|\\x00|\\0'),
        }
    
    def sanitize_input(self, data: Any, data_type: str = 'string', context: str = 'general') -> Dict[str, Any]:
        """
        Comprehensive input sanitization based on data type and context
        """
        result = {
            'sanitized': None,
            'violations': [],
            'encoding_detected': [],
            'risk_score': 0,
            'original_length': 0,
            'sanitized_length': 0
        }
        
        if data is None:
            result['sanitized'] = None
            return result
        
        # Convert to string for processing
        original_data = str(data)
        result['original_length'] = len(original_data)
        
        # Detect and decode multiple encodings
        decoded_data = self._decode_multiple_encodings(original_data, result)
        
        # Apply context-specific sanitization
        if data_type == 'html':
            result['sanitized'] = self._sanitize_html(decoded_data, result)
        elif data_type == 'url':
            result['sanitized'] = self._sanitize_url(decoded_data, result)
        elif data_type == 'filename':
            result['sanitized'] = self._sanitize_filename(decoded_data, result)
        elif data_type == 'email':
            result['sanitized'] = self._sanitize_email(decoded_data, result)
        elif data_type == 'json':
            result['sanitized'] = self._sanitize_json(decoded_data, result)
        elif data_type == 'sql':
            result['sanitized'] = self._sanitize_sql(decoded_data, result)
        else:
            result['sanitized'] = self._sanitize_string(decoded_data, result)
        
        result['sanitized_length'] = len(str(result['sanitized']))
        
        # Calculate risk score based on violations
        result['risk_score'] = min(len(result['violations']) * 10, 100)
        
        return result
    
    def _decode_multiple_encodings(self, data: str, result: Dict) -> str:
        """
        Detect and decode multiple layers of encoding to prevent evasion
        """
        decoded = data
        max_iterations = 5  # Prevent infinite loops
        iteration = 0
        
        while iteration < max_iterations:
            original_decoded = decoded
            
            # HTML entity decoding
            if self.encoding_patterns['html_entities'].search(decoded):
                try:
                    decoded = html.unescape(decoded)
                    result['encoding_detected'].append('html_entities')
                except Exception:
                    pass
            
            # URL decoding
            if self.encoding_patterns['url_encoded'].search(decoded):
                try:
                    decoded = urllib.parse.unquote(decoded)
                    result['encoding_detected'].append('url_encoded')
                except Exception:
                    pass
            
            # Unicode escape decoding
            if self.encoding_patterns['unicode_escaped'].search(decoded):
                try:
                    decoded = decoded.encode().decode('unicode-escape')
                    result['encoding_detected'].append('unicode_escaped')
                except Exception:
                    pass
            
            # Double URL encoding detection
            if self.encoding_patterns['double_encoding'].search(decoded):
                result['violations'].append('Double URL encoding detected')
                result['encoding_detected'].append('double_encoding')
            
            # Null byte detection
            if self.encoding_patterns['null_bytes'].search(decoded):
                result['violations'].append('Null byte injection detected')
                decoded = decoded.replace('%00', '').replace('\\x00', '').replace('\\0', '')
            
            # Base64 detection (potential payload hiding)
            if len(decoded) > 20 and self.encoding_patterns['base64_pattern'].match(decoded):
                try:
                    base64_decoded = base64.b64decode(decoded).decode('utf-8')
                    if self._contains_suspicious_content(base64_decoded):
                        result['violations'].append('Suspicious Base64 payload detected')
                        result['encoding_detected'].append('base64_suspicious')
                    else:
                        decoded = base64_decoded
                        result['encoding_detected'].append('base64_decoded')
                except Exception:
                    pass
            
            # Break if no changes made
            if decoded == original_decoded:
                break
                
            iteration += 1
        
        if iteration >= max_iterations:
            result['violations'].append('Maximum encoding iterations reached - possible evasion attempt')
        
        return decoded
    
    def _contains_suspicious_content(self, content: str) -> bool:
        """Check if decoded content contains suspicious patterns"""
        suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'shell\s*\(',
            r'cmd\s*\(',
            r'union\s+select',
            r'drop\s+table',
            r'\.\./.*',
            r'/etc/passwd',
            r'\\windows\\system32',
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in suspicious_patterns)
    
    def _sanitize_html(self, data: str, result: Dict) -> str:
        """Sanitize HTML content while preserving safe formatting"""
        if not BLEACH_AVAILABLE:
            # Fallback to basic HTML escaping
            sanitized = html.escape(data)
            result['violations'].append('HTML sanitization limited - bleach not available')
            return sanitized
        
        try:
            # Use bleach for comprehensive HTML sanitization
            sanitized = bleach.clean(
                data,
                tags=self.ALLOWED_HTML_TAGS,
                attributes=self.ALLOWED_HTML_ATTRIBUTES,
                strip=True,
                strip_comments=True
            )
            
            # Additional checks for dangerous patterns
            dangerous_html_patterns = [
                r'javascript:',
                r'vbscript:',
                r'data:text/html',
                r'expression\s*\(',
                r'@import',
                r'behavior\s*:',
            ]
            
            for pattern in dangerous_html_patterns:
                if re.search(pattern, sanitized, re.IGNORECASE):
                    result['violations'].append(f'Dangerous HTML pattern removed: {pattern}')
                    sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
            
            return sanitized
            
        except Exception as e:
            result['violations'].append(f'HTML sanitization error: {str(e)}')
            return html.escape(data)
    
    def _sanitize_url(self, data: str, result: Dict) -> str:
        """Sanitize URL input and validate against dangerous protocols"""
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(data)
            
            # Check for dangerous protocols
            dangerous_protocols = [
                'javascript', 'vbscript', 'data', 'file', 'ftp',
                'gopher', 'ldap', 'dict', 'finger', 'telnet'
            ]
            
            if parsed.scheme.lower() in dangerous_protocols:
                result['violations'].append(f'Dangerous protocol blocked: {parsed.scheme}')
                return ''
            
            # Validate domain for external URLs
            if parsed.netloc:
                # Block private/local IP addresses in production
                if self._is_private_ip(parsed.netloc):
                    result['violations'].append('Private IP address blocked in URL')
                    return ''
            
            # Reconstruct clean URL
            clean_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment for security
            ))
            
            return clean_url
            
        except Exception as e:
            result['violations'].append(f'URL sanitization error: {str(e)}')
            return ''
    
    def _sanitize_filename(self, data: str, result: Dict) -> str:
        """Sanitize filename to prevent path traversal and dangerous files"""
        # Remove path components
        filename = data.split('/')[-1].split('\\')[-1]
        
        # Check for dangerous extensions
        file_ext = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        if file_ext in self.DANGEROUS_EXTENSIONS:
            result['violations'].append(f'Dangerous file extension blocked: {file_ext}')
            filename = filename.replace(file_ext, '.txt')
        
        # Remove dangerous characters
        dangerous_chars = r'[<>:"/\\|?*\x00-\x1f\x7f-\x9f]'
        sanitized = re.sub(dangerous_chars, '_', filename)
        
        # Limit length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
            result['violations'].append('Filename truncated to 255 characters')
        
        # Ensure filename is not empty
        if not sanitized or sanitized == '.':
            sanitized = 'unnamed_file.txt'
            result['violations'].append('Empty filename replaced with default')
        
        return sanitized
    
    def _sanitize_email(self, data: str, result: Dict) -> str:
        """Sanitize email address"""
        # Basic email pattern validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, data):
            result['violations'].append('Invalid email format')
            return ''
        
        # Check for suspicious patterns in email
        suspicious_email_patterns = [
            r'javascript:',
            r'<script',
            r'@.*@',  # Double @ symbols
            r'\.{2,}',  # Multiple consecutive dots
        ]
        
        for pattern in suspicious_email_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                result['violations'].append(f'Suspicious email pattern: {pattern}')
                return ''
        
        return data.lower().strip()
    
    def _sanitize_json(self, data: str, result: Dict) -> str:
        """Sanitize JSON input"""
        try:
            # Parse JSON to validate structure
            parsed = json.loads(data)
            
            # Re-serialize to clean formatting and remove any dangerous constructs
            clean_json = json.dumps(parsed, ensure_ascii=True, separators=(',', ':'))
            
            # Check for dangerous patterns in the JSON string
            dangerous_json_patterns = [
                r'__proto__',
                r'constructor',
                r'prototype',
                r'eval\s*\(',
                r'function\s*\(',
            ]
            
            for pattern in dangerous_json_patterns:
                if re.search(pattern, clean_json, re.IGNORECASE):
                    result['violations'].append(f'Dangerous JSON pattern: {pattern}')
            
            return clean_json
            
        except json.JSONDecodeError:
            result['violations'].append('Invalid JSON format')
            return '{}'
    
    def _sanitize_sql(self, data: str, result: Dict) -> str:
        """Sanitize input that might be used in SQL contexts"""
        # SQL injection patterns to remove/escape
        sql_dangerous_patterns = [
            r"';.*--",
            r"'.*union.*select",
            r"'.*drop.*table",
            r"'.*insert.*into",
            r"'.*delete.*from",
            r"'.*update.*set",
            r"/\*.*\*/",
            r"--.*$",
        ]
        
        sanitized = data
        for pattern in sql_dangerous_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                result['violations'].append(f'SQL injection pattern removed: {pattern}')
                sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Escape single quotes
        sanitized = sanitized.replace("'", "''")
        
        return sanitized
    
    def _sanitize_string(self, data: str, result: Dict) -> str:
        """General string sanitization"""
        # Remove null bytes
        sanitized = data.replace('\x00', '')
        
        # Remove control characters except common whitespace
        sanitized = ''.join(char for char in sanitized 
                          if ord(char) >= 32 or char in '\t\n\r')
        
        # Limit length to prevent DoS
        max_length = 10000  # Configurable
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
            result['violations'].append(f'String truncated to {max_length} characters')
        
        return sanitized
    
    def _is_private_ip(self, hostname: str) -> bool:
        """Check if hostname is a private IP address"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False  # Not an IP address
    
    def sanitize_batch(self, data_dict: Dict[str, Any], schema: Dict[str, str]) -> Dict[str, Any]:
        """
        Sanitize multiple fields according to schema
        """
        results = {}
        
        for field_name, value in data_dict.items():
            data_type = schema.get(field_name, 'string')
            sanitization_result = self.sanitize_input(value, data_type)
            
            results[field_name] = {
                'value': sanitization_result['sanitized'],
                'violations': sanitization_result['violations'],
                'risk_score': sanitization_result['risk_score']
            }
            
            # Log high-risk sanitizations
            if sanitization_result['risk_score'] > 30:
                SecurityLogger.log_security_event(
                    'high_risk_sanitization',
                    'medium',
                    {
                        'field': field_name,
                        'risk_score': sanitization_result['risk_score'],
                        'violations': sanitization_result['violations']
                    }
                )
        
        return results


class OutputSanitizer:
    """
    Output sanitization to prevent data leakage and XSS in responses
    """
    
    @staticmethod
    def sanitize_response_data(data: Any, context: str = 'json') -> Any:
        """
        Sanitize data before sending in responses
        """
        if isinstance(data, dict):
            return {key: OutputSanitizer.sanitize_response_data(value, context) 
                   for key, value in data.items()}
        elif isinstance(data, list):
            return [OutputSanitizer.sanitize_response_data(item, context) 
                   for item in data]
        elif isinstance(data, str):
            if context == 'html':
                return html.escape(data)
            elif context == 'json':
                # Ensure proper JSON encoding
                return data.replace('</', '<\\/')  # Prevent script injection in JSON
            else:
                return data
        else:
            return data
    
    @staticmethod
    def remove_sensitive_fields(data: Dict[str, Any], user_role: str = 'user') -> Dict[str, Any]:
        """
        Remove sensitive fields from response based on user role
        """
        # Always remove these sensitive fields
        always_remove = {
            'password', 'password_hash', 'salt', 'secret_key', 'api_key',
            'private_key', 'token', 'session_key', 'csrf_token'
        }
        
        # Remove these for non-admin users
        admin_only = {
            'created_by_id', 'last_modified_by', 'internal_notes',
            'system_flags', 'debug_info'
        }
        
        # Remove these for regular users
        staff_only = {
            'email', 'phone', 'address', 'ssn', 'medical_record_number'
        }
        
        fields_to_remove = always_remove.copy()
        
        if user_role not in ['admin', 'superuser']:
            fields_to_remove.update(admin_only)
            
        if user_role not in ['staff', 'admin', 'superuser']:
            fields_to_remove.update(staff_only)
        
        return {key: value for key, value in data.items() 
               if key not in fields_to_remove}