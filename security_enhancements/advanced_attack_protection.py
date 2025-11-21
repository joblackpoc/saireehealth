"""
Advanced Cyber Security Protection
Comprehensive protection against sophisticated attack vectors
"""

import re
import os
import logging
import hashlib
import base64
import json
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, unquote
from django.core.exceptions import SuspiciousOperation, ValidationError
from django.utils.html import escape, strip_tags
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
import bleach

logger = logging.getLogger('security_enhancements')

class PathTraversalProtection:
    """Protection against Path Traversal and Local File Inclusion attacks"""
    
    # Dangerous path traversal patterns
    TRAVERSAL_PATTERNS = [
        r'\.\./',           # ../
        r'\.\.\/',          # ..\
        r'\.\.\\',          # ..\
        r'%2e%2e%2f',       # URL encoded ../
        r'%252e%252e%252f', # Double URL encoded ../
        r'%c0%ae%c0%ae/',   # UTF-8 encoded ../
        r'0x2e0x2e0x2f',    # Hex encoded ../
        r'file://',         # File protocol
        r'file:\\',         # File protocol (Windows)
        r'/etc/passwd',     # Unix password file
        r'/etc/shadow',     # Unix shadow file
        r'/proc/',          # Unix process info
        r'\\windows\\',     # Windows system
        r'\\system32\\',    # Windows system32
        r'boot\.ini',       # Windows boot file
        r'web\.config',     # .NET config file
        r'\.htaccess',      # Apache config
        r'\.htpasswd',      # Apache password
    ]
    
    @classmethod
    def validate_path(cls, path: str) -> bool:
        """Validate path for traversal attempts"""
        if not path:
            return True
        
        # Normalize and decode the path
        normalized_path = cls._normalize_path(path)
        
        # Check against known traversal patterns
        for pattern in cls.TRAVERSAL_PATTERNS:
            if re.search(pattern, normalized_path, re.IGNORECASE):
                logger.warning(f"Path traversal attempt detected: {path}")
                return False
        
        # Check for null bytes
        if '\x00' in path or '%00' in path:
            logger.warning(f"Null byte injection attempt: {path}")
            return False
        
        # Check for suspicious file extensions
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.php', '.asp', '.jsp']
        if any(ext in normalized_path.lower() for ext in dangerous_extensions):
            logger.warning(f"Dangerous file extension detected: {path}")
            return False
        
        return True
    
    @classmethod
    def _normalize_path(cls, path: str) -> str:
        """Normalize path with multiple encoding schemes"""
        # URL decode multiple times to handle double encoding
        for _ in range(3):
            try:
                path = unquote(path)
            except:
                break
        
        # Replace backslashes with forward slashes
        path = path.replace('\\', '/')
        
        # Remove duplicate slashes
        path = re.sub(r'/+', '/', path)
        
        return path.lower()


class RemoteFileInclusionProtection:
    """Protection against Remote File Inclusion (RFI) attacks"""
    
    # Suspicious URL patterns for RFI
    RFI_PATTERNS = [
        r'https?://[^/]+/.*\.(php|asp|jsp|py|rb|pl)',  # Remote script files
        r'ftp://.*\.(php|asp|jsp|py|rb|pl)',        # FTP script files
        r'data:text/html;base64,',                   # Data URI HTML
        r'javascript:',                              # JavaScript URI
        r'vbscript:',                                # VBScript URI
        r'file:///',                                 # File protocol
        r'php://filter',                             # PHP filter
        r'php://input',                              # PHP input
        r'expect://',                                # Expect protocol
        r'zip://',                                   # ZIP protocol
    ]
    
    @classmethod
    def validate_url(cls, url: str) -> bool:
        """Validate URL for RFI attempts"""
        if not url:
            return True
        
        # Check against RFI patterns
        for pattern in cls.RFI_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                logger.warning(f"Remote file inclusion attempt: {url}")
                return False
        
        # Parse URL for additional checks
        try:
            parsed = urlparse(url)
            
            # Block non-HTTP(S) protocols
            if parsed.scheme and parsed.scheme.lower() not in ['http', 'https', '']:
                logger.warning(f"Suspicious protocol in URL: {url}")
                return False
            
            # Check for IP addresses (potential internal network access)
            if parsed.hostname:
                import ipaddress
                try:
                    ip = ipaddress.ip_address(parsed.hostname)
                    if ip.is_private or ip.is_loopback:
                        logger.warning(f"Private IP address in URL: {url}")
                        return False
                except ValueError:
                    pass  # Not an IP address
        
        except Exception as e:
            logger.warning(f"Error parsing URL {url}: {str(e)}")
            return False
        
        return True


class CommandInjectionProtection:
    """Protection against Command Injection attacks"""
    
    # Command injection patterns
    COMMAND_PATTERNS = [
        r'[;&|`$(){}[\]<>]',                # Shell metacharacters
        r'\|\s*\w+',                        # Pipe to command
        r'&&\s*\w+',                        # AND command
        r'\|\|\s*\w+',                      # OR command
        r';\s*\w+',                         # Semicolon command
        r'`[^`]+`',                         # Backticks
        r'\$\([^)]+\)',                     # Command substitution
        r'>\s*[/\\]',                       # Output redirection
        r'<\s*[/\\]',                       # Input redirection
        r'\bcurl\b',                        # curl command
        r'\bwget\b',                        # wget command
        r'\bnc\b',                          # netcat
        r'\btelnet\b',                      # telnet
        r'\bssh\b',                         # ssh
        r'\bftp\b',                         # ftp
        r'\brm\b',                          # remove command
        r'\bmv\b',                          # move command
        r'\bcp\b',                          # copy command
        r'\bcat\b',                         # cat command
        r'\bchmod\b',                       # chmod command
        r'\bchown\b',                       # chown command
        r'\bps\b',                          # process list
        r'\bkill\b',                        # kill process
        r'\bnetstat\b',                     # network status
        r'\bifconfig\b',                    # interface config
        r'\bping\b',                        # ping command
        r'\bnslookup\b',                    # DNS lookup
        r'\bdig\b',                         # DNS query
    ]
    
    @classmethod
    def validate_input(cls, input_data: str) -> bool:
        """Validate input for command injection attempts"""
        if not input_data:
            return True
        
        # Check for command injection patterns
        for pattern in cls.COMMAND_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"Command injection attempt detected: {input_data[:100]}")
                return False
        
        # Check for encoded command injection
        try:
            # Base64 decode attempt
            if len(input_data) % 4 == 0:
                try:
                    decoded = base64.b64decode(input_data).decode('utf-8', errors='ignore')
                    if not cls.validate_input(decoded):
                        return False
                except:
                    pass
            
            # URL decode attempt
            decoded = unquote(input_data)
            if decoded != input_data:
                return cls.validate_input(decoded)
        
        except Exception:
            pass
        
        return True


class XSSProtection:
    """Comprehensive Cross-Site Scripting (XSS) Protection"""
    
    # Reflected XSS patterns
    REFLECTED_XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',           # Script tags
        r'javascript:',                         # JavaScript protocol
        r'vbscript:',                          # VBScript protocol
        r'on\w+\s*=',                          # Event handlers
        r'<iframe[^>]*>',                      # Iframe tags
        r'<object[^>]*>',                      # Object tags
        r'<embed[^>]*>',                       # Embed tags
        r'<applet[^>]*>',                      # Applet tags
        r'<meta[^>]*http-equiv',               # Meta refresh
        r'<link[^>]*>',                        # Link tags
        r'<img[^>]*onerror',                   # Image onerror
        r'<svg[^>]*onload',                    # SVG onload
        r'<body[^>]*onload',                   # Body onload
        r'expression\s*\(',                    # CSS expressions
        r'@import',                            # CSS import
        r'url\s*\(\s*["\']?javascript:',       # CSS JavaScript URL
    ]
    
    # DOM-based XSS patterns
    DOM_XSS_PATTERNS = [
        r'document\.write',                     # document.write
        r'document\.writeln',                   # document.writeln
        r'innerHTML\s*=',                       # innerHTML assignment
        r'outerHTML\s*=',                       # outerHTML assignment
        r'eval\s*\(',                          # eval function
        r'setTimeout\s*\(',                     # setTimeout
        r'setInterval\s*\(',                    # setInterval
        r'Function\s*\(',                       # Function constructor
        r'execScript\s*\(',                     # execScript (IE)
        r'location\s*=',                        # location assignment
        r'location\.href\s*=',                  # location.href
        r'location\.replace\s*\(',              # location.replace
        r'window\.open\s*\(',                   # window.open
    ]
    
    @classmethod
    def validate_reflected_xss(cls, input_data: str) -> bool:
        """Validate input for reflected XSS"""
        if not input_data:
            return True
        
        # Decode HTML entities first
        decoded = cls._decode_html_entities(input_data)
        
        # Check for reflected XSS patterns
        for pattern in cls.REFLECTED_XSS_PATTERNS:
            if re.search(pattern, decoded, re.IGNORECASE | re.DOTALL):
                logger.warning(f"Reflected XSS attempt detected: {input_data[:100]}")
                return False
        
        return True
    
    @classmethod
    def validate_dom_xss(cls, input_data: str) -> bool:
        """Validate input for DOM-based XSS"""
        if not input_data:
            return True
        
        # Check for DOM XSS patterns
        for pattern in cls.DOM_XSS_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"DOM-based XSS attempt detected: {input_data[:100]}")
                return False
        
        return True
    
    @classmethod
    def sanitize_output(cls, data: str, context: str = 'html') -> str:
        """Sanitize data for safe output"""
        if not data:
            return data
        
        if context == 'html':
            # Use bleach for HTML sanitization
            allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
            allowed_attributes = {}
            return bleach.clean(data, tags=allowed_tags, attributes=allowed_attributes)
        
        elif context == 'json':
            # Escape for JSON context
            return json.dumps(data)[1:-1]  # Remove quotes
        
        elif context == 'url':
            # URL encode
            from urllib.parse import quote
            return quote(data)
        
        else:
            # Default HTML escape
            return escape(data)
    
    @classmethod
    def _decode_html_entities(cls, text: str) -> str:
        """Decode HTML entities for analysis"""
        import html
        return html.unescape(text)


class SQLInjectionProtection:
    """Advanced SQL Injection Protection"""
    
    # Error-based SQL injection patterns
    ERROR_BASED_PATTERNS = [
        r"'[^']*'[^']*'",                      # Quote manipulation
        r'"[^"]*"[^"]*"',                      # Double quote manipulation
        r'\b(and|or)\s+\d+\s*=\s*\d+',        # Boolean conditions
        r'\b(and|or)\s+[\'"`]\w+[\'"`]\s*=\s*[\'"`]\w+[\'"`]',  # String conditions
        r'\bunion\s+select\b',                  # UNION SELECT
        r'\bselect\s+.*\bfrom\s+',             # SELECT statements
        r'\binsert\s+into\b',                  # INSERT statements
        r'\bupdate\s+.*\bset\b',               # UPDATE statements
        r'\bdelete\s+from\b',                  # DELETE statements
        r'\bdrop\s+table\b',                   # DROP TABLE
        r'\bcreate\s+table\b',                 # CREATE TABLE
        r'\balter\s+table\b',                  # ALTER TABLE
        r'\bexec\s*\(',                        # EXEC function
        r'\bexecute\s*\(',                     # EXECUTE function
        r'@@version',                          # Version disclosure
        r'@@servername',                       # Server name
        r'\buser\s*\(\s*\)',                   # USER() function
        r'\bdatabase\s*\(\s*\)',               # DATABASE() function
        r'\bversion\s*\(\s*\)',                # VERSION() function
        r'\bsystem_user\s*\(\s*\)',            # SYSTEM_USER() function
        r'\bschema\s*\(\s*\)',                 # SCHEMA() function
        r'\bload_file\s*\(',                   # LOAD_FILE() function
        r'\binto\s+outfile\b',                 # INTO OUTFILE
        r'\binto\s+dumpfile\b',                # INTO DUMPFILE
    ]
    
    # UNION-based SQL injection patterns
    UNION_BASED_PATTERNS = [
        r'\bunion\s+all\s+select\b',           # UNION ALL SELECT
        r'\bunion\s+select\s+null\b',          # UNION SELECT NULL
        r'\bunion\s+select\s+\d+',             # UNION SELECT numbers
        r'\bunion\s+select\s+[\'"`]',          # UNION SELECT strings
        r'\bunion\s+select\s+concat\s*\(',     # UNION SELECT CONCAT
        r'\bunion\s+select\s+group_concat\s*\(',  # UNION SELECT GROUP_CONCAT
        r'\bunion\s+select\s+0x[0-9a-f]+',     # UNION SELECT hex
        r'\bunion\s+select\s+unhex\s*\(',      # UNION SELECT UNHEX
        r'\bunion\s+select\s+char\s*\(',       # UNION SELECT CHAR
        r'\bunion\s+select\s+ascii\s*\(',      # UNION SELECT ASCII
        r'\bunion\s+select\s+substring\s*\(',  # UNION SELECT SUBSTRING
        r'\bunion\s+select\s+mid\s*\(',        # UNION SELECT MID
        r'\bunion\s+select\s+left\s*\(',       # UNION SELECT LEFT
        r'\bunion\s+select\s+right\s*\(',      # UNION SELECT RIGHT
        r'\bunion\s+select\s+length\s*\(',     # UNION SELECT LENGTH
        r'\bunion\s+select\s+count\s*\(',      # UNION SELECT COUNT
    ]
    
    # Time-based blind SQL injection patterns
    TIME_BASED_PATTERNS = [
        r'\bsleep\s*\(\s*\d+\s*\)',           # SLEEP function
        r'\bwaitfor\s+delay\b',                # WAITFOR DELAY (SQL Server)
        r'\bbenchmark\s*\(',                   # BENCHMARK function (MySQL)
        r'\bpg_sleep\s*\(',                    # pg_sleep (PostgreSQL)
        r'\bdbms_pipe\.receive_message\s*\(',  # Oracle delay
    ]
    
    # Boolean-based blind SQL injection patterns
    BOOLEAN_BASED_PATTERNS = [
        r'\band\s+\d+\s*=\s*\d+',             # AND number comparison
        r'\bor\s+\d+\s*=\s*\d+',              # OR number comparison
        r'\band\s+length\s*\(',                # AND LENGTH
        r'\bor\s+length\s*\(',                 # OR LENGTH
        r'\band\s+substring\s*\(',             # AND SUBSTRING
        r'\bor\s+substring\s*\(',              # OR SUBSTRING
        r'\band\s+ascii\s*\(',                 # AND ASCII
        r'\bor\s+ascii\s*\(',                  # OR ASCII
        r'\band\s+exists\s*\(',                # AND EXISTS
        r'\bor\s+exists\s*\(',                 # OR EXISTS
    ]
    
    @classmethod
    def validate_error_based(cls, input_data: str) -> bool:
        """Validate input for error-based SQL injection"""
        if not input_data:
            return True
        
        for pattern in cls.ERROR_BASED_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"Error-based SQL injection detected: {input_data[:100]}")
                return False
        
        return True
    
    @classmethod
    def validate_union_based(cls, input_data: str) -> bool:
        """Validate input for UNION-based SQL injection"""
        if not input_data:
            return True
        
        for pattern in cls.UNION_BASED_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"UNION-based SQL injection detected: {input_data[:100]}")
                return False
        
        return True
    
    @classmethod
    def validate_time_based(cls, input_data: str) -> bool:
        """Validate input for time-based blind SQL injection"""
        if not input_data:
            return True
        
        for pattern in cls.TIME_BASED_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"Time-based SQL injection detected: {input_data[:100]}")
                return False
        
        return True
    
    @classmethod
    def validate_boolean_based(cls, input_data: str) -> bool:
        """Validate input for boolean-based blind SQL injection"""
        if not input_data:
            return True
        
        for pattern in cls.BOOLEAN_BASED_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                logger.warning(f"Boolean-based SQL injection detected: {input_data[:100]}")
                return False
        
        return True
    
    @classmethod
    def validate_all_sql_injection(cls, input_data: str) -> bool:
        """Comprehensive SQL injection validation"""
        return (cls.validate_error_based(input_data) and
                cls.validate_union_based(input_data) and
                cls.validate_time_based(input_data) and
                cls.validate_boolean_based(input_data))


class AdvancedSecurityMiddleware(MiddlewareMixin):
    """Advanced security middleware for comprehensive attack protection"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Process incoming request for security threats"""
        
        # Skip security checks for certain paths
        skip_paths = ['/health/api/status/', '/static/', '/media/']
        if any(skip_path in request.path for skip_path in skip_paths):
            return None
        
        try:
            # Validate request path for traversal attempts
            if not PathTraversalProtection.validate_path(request.path):
                self._log_security_event(request, 'PATH_TRAVERSAL', 'Path traversal attempt detected')
                raise SuspiciousOperation("Invalid path detected")
            
            # Validate GET parameters
            for param_name, param_value in request.GET.items():
                if not self._validate_parameter(param_name, param_value, request):
                    self._log_security_event(request, 'MALICIOUS_INPUT', f'Malicious GET parameter: {param_name}')
                    raise SuspiciousOperation("Malicious input detected")
            
            # Validate POST data
            if request.method == 'POST':
                if hasattr(request, 'POST'):
                    for field_name, field_value in request.POST.items():
                        if field_name != 'csrfmiddlewaretoken':  # Skip CSRF token
                            if not self._validate_parameter(field_name, field_value, request):
                                self._log_security_event(request, 'MALICIOUS_INPUT', f'Malicious POST field: {field_name}')
                                raise SuspiciousOperation("Malicious input detected")
                
                # Validate JSON body if present
                if hasattr(request, 'body') and request.content_type == 'application/json':
                    try:
                        body = request.body.decode('utf-8')
                        if not self._validate_json_body(body, request):
                            self._log_security_event(request, 'MALICIOUS_JSON', 'Malicious JSON payload')
                            raise SuspiciousOperation("Malicious JSON detected")
                    except Exception:
                        pass  # Invalid JSON will be handled by view
            
        except SuspiciousOperation:
            raise
        except Exception as e:
            logger.error(f"Error in security validation: {str(e)}")
        
        return None
    
    def _validate_parameter(self, name: str, value: str, request: HttpRequest) -> bool:
        """Validate individual parameter for various attack patterns"""
        if not value:
            return True
        
        value_str = str(value)
        
        # Path traversal validation
        if not PathTraversalProtection.validate_path(value_str):
            return False
        
        # Remote file inclusion validation
        if not RemoteFileInclusionProtection.validate_url(value_str):
            return False
        
        # Command injection validation
        if not CommandInjectionProtection.validate_input(value_str):
            return False
        
        # XSS validation
        if not XSSProtection.validate_reflected_xss(value_str):
            return False
        
        if not XSSProtection.validate_dom_xss(value_str):
            return False
        
        # SQL injection validation
        if not SQLInjectionProtection.validate_all_sql_injection(value_str):
            return False
        
        return True
    
    def _validate_json_body(self, body: str, request: HttpRequest) -> bool:
        """Validate JSON request body"""
        try:
            # Parse JSON to validate structure
            json_data = json.loads(body)
            
            # Recursively validate all string values in JSON
            return self._validate_json_recursive(json_data, request)
        
        except json.JSONDecodeError:
            return True  # Let the view handle invalid JSON
        except Exception as e:
            logger.error(f"Error validating JSON: {str(e)}")
            return False
    
    def _validate_json_recursive(self, data: Any, request: HttpRequest) -> bool:
        """Recursively validate JSON data structure"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(key, str) and not self._validate_parameter('json_key', key, request):
                    return False
                if not self._validate_json_recursive(value, request):
                    return False
        
        elif isinstance(data, list):
            for item in data:
                if not self._validate_json_recursive(item, request):
                    return False
        
        elif isinstance(data, str):
            if not self._validate_parameter('json_value', data, request):
                return False
        
        return True
    
    def _log_security_event(self, request: HttpRequest, event_type: str, description: str):
        """Log security event"""
        try:
            from security_enhancements.security_audit import SecurityAuditTracker
            
            client_ip = self._get_client_ip(request)
            user = request.user if hasattr(request, 'user') and request.user.is_authenticated else None
            
            SecurityAuditTracker.log_security_event(
                event_type,
                description,
                user=user,
                ip_address=client_ip,
                severity='HIGH',
                additional_data={
                    'path': request.path,
                    'method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:200],
                    'referer': request.META.get('HTTP_REFERER', '')[:200]
                }
            )
        except Exception as e:
            logger.error(f"Error logging security event: {str(e)}")
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address"""
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')
    
    def process_response(self, request, response):
        """Process response to add security headers and sanitize output"""
        
        # Add additional security headers for XSS protection
        if not hasattr(response, 'streaming') or not response.streaming:
            # Add X-Content-Type-Options if not present
            if 'X-Content-Type-Options' not in response:
                response['X-Content-Type-Options'] = 'nosniff'
            
            # Add X-Frame-Options if not present
            if 'X-Frame-Options' not in response:
                response['X-Frame-Options'] = 'DENY'
            
            # Add Content Security Policy for XSS protection
            if 'Content-Security-Policy' not in response:
                csp = ("default-src 'self'; "
                       "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                       "style-src 'self' 'unsafe-inline'; "
                       "img-src 'self' data: blob:; "
                       "font-src 'self'; "
                       "connect-src 'self'; "
                       "media-src 'self'; "
                       "object-src 'none'; "
                       "child-src 'self'; "
                       "frame-ancestors 'none'; "
                       "base-uri 'self'; "
                       "form-action 'self';")
                response['Content-Security-Policy'] = csp
        
        return response