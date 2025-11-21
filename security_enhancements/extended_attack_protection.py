"""
Extended Advanced Attack Protection
Protection against SQLMap, Brute Force, File Upload, ORM and Template Injection attacks
"""

import re
import os
import logging
import hashlib
import base64
import json
import time
import magic
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urlparse, unquote
from django.core.exceptions import SuspiciousOperation, ValidationError
from django.utils.html import escape
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from django.core.files.uploadedfile import UploadedFile
from django.template import Template, Context
from django.template.exceptions import TemplateSyntaxError
from django.db import connection
import bleach

logger = logging.getLogger('security_enhancements')

class SQLMapProtection:
    """Protection against SQLMap automated SQL injection tool"""
    
    # SQLMap specific patterns and signatures
    SQLMAP_SIGNATURES = [
        # User-Agent signatures
        r'sqlmap/[\d\.]+',
        r'sqlmap',
        # Parameter manipulation patterns
        r'AND\s+\d+=\d+\s+--',
        r'OR\s+\d+=\d+\s+--',
        r'UNION\s+ALL\s+SELECT\s+NULL',
        r'UNION\s+SELECT\s+NULL',
        # Time-based signatures
        r'SLEEP\(\d+\)',
        r'BENCHMARK\(\d+',
        r'WAITFOR\s+DELAY',
        r'pg_sleep\(\d+\)',
        # Error-based signatures
        r'EXTRACTVALUE\(',
        r'UPDATEXML\(',
        r'XMLType\(',
        # Boolean-based signatures
        r'AND\s+\d+\s*=\s*\d+',
        r'OR\s+\d+\s*=\s*\d+',
        # Information gathering
        r'@@version',
        r'@@hostname',
        r'version\(\)',
        r'database\(\)',
        r'user\(\)',
        # File operations
        r'load_file\(',
        r'into\s+outfile',
        r'into\s+dumpfile',
        # SQLMap specific payloads
        r'%27%20UNION%20ALL%20SELECT',
        r'%27%20AND%20%27\d+%27%3D%27\d+',
        r'%27%20OR%20%27\d+%27%3D%27\d+',
        # Encoded SQLMap signatures
        r'CONCAT\(0x[0-9a-fA-F]+\)',
        r'CHAR\(\d+,\d+',
        r'HEX\([^)]+\)',
        # Advanced SQLMap techniques
        r'CASE\s+WHEN\s+\d+=\d+\s+THEN',
        r'IF\(\d+=\d+,SLEEP\(\d+\),0\)',
        r'\(SELECT\s+COUNT\(\*\)\s+FROM\s+INFORMATION_SCHEMA\.',
    ]
    
    # SQLMap common parameter names
    SQLMAP_PARAMETERS = [
        'id', 'pid', 'uid', 'user_id', 'product_id', 'article_id',
        'page_id', 'cat_id', 'category_id', 'item_id', 'news_id'
    ]
    
    # SQLMap evasion techniques
    EVASION_PATTERNS = [
        r'\/\*.*?\*\/',              # Comment evasion
        r'--\s*.*$',                 # Comment evasion
        r'\s+',                      # Space evasion
        r'%20',                      # URL encoded space
        r'%09',                      # Tab character
        r'%0a',                      # Line feed
        r'%0d',                      # Carriage return
        r'%2f\*.*?\*\%2f',          # URL encoded comments
        r'REVERSE\([^)]+\)',         # Function-based evasion
        r'SUBSTRING\([^)]+\)',       # Substring evasion
    ]
    
    @classmethod
    def detect_sqlmap_attack(cls, request: HttpRequest) -> Tuple[bool, str]:
        """Detect SQLMap automated attacks"""
        
        # Check User-Agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        for pattern in cls.SQLMAP_SIGNATURES[:2]:  # First two are UA patterns
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True, f"SQLMap User-Agent detected: {user_agent}"
        
        # Check all request parameters
        all_params = {}
        all_params.update(request.GET.dict())
        if hasattr(request, 'POST'):
            all_params.update(request.POST.dict())
        
        for param_name, param_value in all_params.items():
            if param_value:
                # Check for SQLMap signatures in values
                for pattern in cls.SQLMAP_SIGNATURES[2:]:  # Skip UA patterns
                    if re.search(pattern, str(param_value), re.IGNORECASE):
                        return True, f"SQLMap signature in parameter '{param_name}': {pattern}"
                
                # Check for evasion techniques
                for pattern in cls.EVASION_PATTERNS:
                    if re.search(pattern, str(param_value), re.IGNORECASE):
                        return True, f"SQLMap evasion technique in parameter '{param_name}': {pattern}"
        
        # Check for suspicious parameter combinations
        if cls._check_parameter_manipulation(all_params):
            return True, "SQLMap parameter manipulation pattern detected"
        
        return False, ""
    
    @classmethod
    def _check_parameter_manipulation(cls, params: Dict[str, str]) -> bool:
        """Check for SQLMap-style parameter manipulation"""
        
        # Look for multiple similar parameters with slight variations
        param_variations = {}
        for param_name in params.keys():
            base_name = re.sub(r'\d+$', '', param_name)
            if base_name in param_variations:
                param_variations[base_name] += 1
            else:
                param_variations[base_name] = 1
        
        # If we have multiple variations of the same parameter, it's suspicious
        for base_name, count in param_variations.items():
            if count > 3 and base_name in cls.SQLMAP_PARAMETERS:
                return True
        
        return False


class BruteForceProtection:
    """Advanced brute force attack protection"""
    
    # Brute force indicators
    BRUTE_FORCE_PATTERNS = [
        # Common username lists
        r'\b(admin|administrator|root|user|test|guest|demo)\b',
        # Password patterns
        r'\b(password|123456|admin|root|test|guest)\b',
        # Rapid-fire indicators
        r'Content-Length:\s*0',      # Empty requests
        r'User-Agent:.*(?:curl|wget|python|perl|ruby)',  # Automation tools
    ]
    
    # Suspicious login patterns
    LOGIN_ATTACK_INDICATORS = [
        'rapid_requests',     # Too many requests in short time
        'user_enumeration',   # Testing different usernames
        'password_spraying',  # Same password, different users
        'credential_stuffing' # Different credentials rapidly
    ]
    
    @classmethod
    def detect_brute_force(cls, request: HttpRequest, view_name: str = '') -> Tuple[bool, str, str]:
        """Detect brute force attacks"""
        
        client_ip = cls._get_client_ip(request)
        
        # Check rate limiting
        if cls._check_request_rate(client_ip, view_name):
            return True, 'rapid_requests', f"High request rate from {client_ip}"
        
        # Check for authentication endpoints
        if any(endpoint in request.path.lower() for endpoint in ['/login', '/signin', '/auth', '/admin']):
            
            # Check for user enumeration
            if cls._check_user_enumeration(request, client_ip):
                return True, 'user_enumeration', "User enumeration attack detected"
            
            # Check for password spraying
            if cls._check_password_spraying(request, client_ip):
                return True, 'password_spraying', "Password spraying attack detected"
            
            # Check for credential stuffing
            if cls._check_credential_stuffing(request, client_ip):
                return True, 'credential_stuffing', "Credential stuffing attack detected"
        
        return False, '', ''
    
    @classmethod
    def _check_request_rate(cls, client_ip: str, view_name: str) -> bool:
        """Check request rate for brute force detection"""
        cache_key = f"bf_rate:{client_ip}:{view_name}"
        current_minute = int(time.time() // 60)
        
        # Get current request count for this minute
        minute_key = f"{cache_key}:{current_minute}"
        request_count = cache.get(minute_key, 0)
        
        # Thresholds based on endpoint type
        thresholds = {
            'login': 10,      # 10 login attempts per minute
            'admin': 5,       # 5 admin attempts per minute
            'api': 100,       # 100 API requests per minute
            'default': 60     # 60 general requests per minute
        }
        
        threshold = thresholds.get(view_name, thresholds['default'])
        
        if request_count >= threshold:
            return True
        
        # Increment counter
        cache.set(minute_key, request_count + 1, 120)  # 2 minute TTL
        return False
    
    @classmethod
    def _check_user_enumeration(cls, request: HttpRequest, client_ip: str) -> bool:
        """Check for user enumeration attempts"""
        if request.method != 'POST':
            return False
        
        username = request.POST.get('username', '') or request.POST.get('email', '')
        if not username:
            return False
        
        # Track unique usernames from this IP
        cache_key = f"bf_users:{client_ip}"
        usernames = cache.get(cache_key, set())
        
        if isinstance(usernames, list):
            usernames = set(usernames)
        
        usernames.add(username.lower())
        
        # If more than 10 different usernames in 10 minutes, it's enumeration
        if len(usernames) > 10:
            return True
        
        cache.set(cache_key, list(usernames), 600)  # 10 minute TTL
        return False
    
    @classmethod
    def _check_password_spraying(cls, request: HttpRequest, client_ip: str) -> bool:
        """Check for password spraying attacks"""
        if request.method != 'POST':
            return False
        
        password = request.POST.get('password', '')
        if not password:
            return False
        
        # Track password attempts from this IP
        cache_key = f"bf_passwords:{client_ip}"
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        attempts = cache.get(cache_key, {})
        attempts[password_hash] = attempts.get(password_hash, 0) + 1
        
        # If same password used more than 20 times in 30 minutes
        if attempts[password_hash] > 20:
            return True
        
        cache.set(cache_key, attempts, 1800)  # 30 minute TTL
        return False
    
    @classmethod
    def _check_credential_stuffing(cls, request: HttpRequest, client_ip: str) -> bool:
        """Check for credential stuffing attacks"""
        if request.method != 'POST':
            return False
        
        username = request.POST.get('username', '') or request.POST.get('email', '')
        password = request.POST.get('password', '')
        
        if not username or not password:
            return False
        
        # Track credential pairs from this IP
        cache_key = f"bf_credentials:{client_ip}"
        credential_hash = hashlib.md5(f"{username}:{password}".encode()).hexdigest()
        
        credentials = cache.get(cache_key, set())
        if isinstance(credentials, list):
            credentials = set(credentials)
        
        credentials.add(credential_hash)
        
        # If more than 50 different credential pairs in 1 hour
        if len(credentials) > 50:
            return True
        
        cache.set(cache_key, list(credentials), 3600)  # 1 hour TTL
        return False
    
    @classmethod
    def _get_client_ip(cls, request: HttpRequest) -> str:
        """Get client IP address"""
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class FileUploadProtection:
    """Unrestricted file upload protection"""
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = {
        # Executable files
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbe',
        '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.ps1', '.ps1xml',
        '.ps2', '.ps2xml', '.psc1', '.psc2', '.msh', '.msh1', '.msh2',
        '.mshxml', '.msh1xml', '.msh2xml',
        
        # Server-side scripts
        '.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx',
        '.jsp', '.jspx', '.cfm', '.cfc', '.pl', '.py', '.rb', '.sh',
        '.cgi', '.htaccess', '.htpasswd',
        
        # Archive files (can contain malware)
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        
        # Document macros
        '.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm',
        
        # Other dangerous formats
        '.swf', '.jar', '.class', '.dex', '.apk', '.ipa'
    }
    
    # Allowed MIME types (whitelist approach)
    ALLOWED_MIME_TYPES = {
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
        'image/tiff', 'image/svg+xml',
        'application/pdf',
        'text/plain', 'text/csv',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    }
    
    # Magic number signatures for file type validation
    MAGIC_SIGNATURES = {
        b'\xFF\xD8\xFF': 'image/jpeg',
        b'\x89PNG\r\n\x1A\n': 'image/png',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'%PDF': 'application/pdf',
        b'PK\x03\x04': 'application/zip',  # Also used by Office documents
    }
    
    @classmethod
    def validate_file_upload(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Comprehensive file upload validation"""
        
        if not uploaded_file:
            return False, "No file provided"
        
        # 1. File extension validation
        if not cls._validate_extension(uploaded_file.name):
            return False, f"Dangerous file extension: {uploaded_file.name}"
        
        # 2. File size validation
        if not cls._validate_file_size(uploaded_file):
            return False, "File size exceeds maximum allowed"
        
        # 3. MIME type validation
        if not cls._validate_mime_type(uploaded_file):
            return False, f"Invalid MIME type: {uploaded_file.content_type}"
        
        # 4. Magic number validation
        if not cls._validate_magic_numbers(uploaded_file):
            return False, "File content doesn't match declared type"
        
        # 5. Malware signature detection
        if not cls._scan_for_malware_signatures(uploaded_file):
            return False, "Potential malware detected in file"
        
        # 6. Filename validation
        if not cls._validate_filename(uploaded_file.name):
            return False, "Invalid filename detected"
        
        return True, "File validation passed"
    
    @classmethod
    def _validate_extension(cls, filename: str) -> bool:
        """Validate file extension"""
        if not filename:
            return False
        
        # Get file extension
        ext = os.path.splitext(filename.lower())[1]
        
        # Check against dangerous extensions
        if ext in cls.DANGEROUS_EXTENSIONS:
            return False
        
        # Check for double extensions (e.g., file.jpg.php)
        parts = filename.lower().split('.')
        if len(parts) > 2:
            for part in parts[1:]:  # Skip first part (filename)
                if f'.{part}' in cls.DANGEROUS_EXTENSIONS:
                    return False
        
        return True
    
    @classmethod
    def _validate_file_size(cls, uploaded_file: UploadedFile) -> bool:
        """Validate file size"""
        max_size = getattr(settings, 'MAX_UPLOAD_SIZE', 10 * 1024 * 1024)  # 10MB default
        return uploaded_file.size <= max_size
    
    @classmethod
    def _validate_mime_type(cls, uploaded_file: UploadedFile) -> bool:
        """Validate MIME type"""
        return uploaded_file.content_type in cls.ALLOWED_MIME_TYPES
    
    @classmethod
    def _validate_magic_numbers(cls, uploaded_file: UploadedFile) -> bool:
        """Validate file content using magic numbers"""
        try:
            # Read first 1024 bytes
            uploaded_file.seek(0)
            header = uploaded_file.read(1024)
            uploaded_file.seek(0)  # Reset position
            
            # Check magic signatures
            for signature, expected_type in cls.MAGIC_SIGNATURES.items():
                if header.startswith(signature):
                    # Verify it matches declared MIME type
                    if uploaded_file.content_type == expected_type:
                        return True
                    # Special case for Office documents (they're actually ZIP files)
                    elif (signature == b'PK\x03\x04' and 
                          'officedocument' in uploaded_file.content_type):
                        return True
            
            # If we have python-magic available, use it for more comprehensive checking
            try:
                import magic
                file_mime = magic.from_buffer(header, mime=True)
                return file_mime == uploaded_file.content_type
            except ImportError:
                # Fallback: allow if we can't determine
                return True
                
        except Exception as e:
            logger.error(f"Error validating file magic numbers: {str(e)}")
            return False
    
    @classmethod
    def _scan_for_malware_signatures(cls, uploaded_file: UploadedFile) -> bool:
        """Scan for basic malware signatures"""
        try:
            uploaded_file.seek(0)
            content = uploaded_file.read()
            uploaded_file.seek(0)
            
            # Convert to string for text-based scanning
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = str(content)
            
            # Malware signatures to look for
            malware_signatures = [
                b'eval(',                    # PHP eval
                b'exec(',                    # Command execution
                b'system(',                  # System calls
                b'shell_exec(',              # Shell execution
                b'passthru(',                # Pass through to shell
                b'file_get_contents(',       # Remote file inclusion
                b'fopen(',                   # File operations
                b'include(',                 # File inclusion
                b'require(',                 # File requirements
                b'<script',                  # JavaScript
                b'javascript:',              # JavaScript protocol
                b'vbscript:',                # VBScript protocol
                b'<?php',                    # PHP tags
                b'<%',                       # ASP tags
                b'#!/bin/sh',                # Shell script
                b'#!/bin/bash',              # Bash script
            ]
            
            # Check for signatures
            for signature in malware_signatures:
                if signature in content:
                    logger.warning(f"Malware signature found in uploaded file: {signature}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error scanning file for malware: {str(e)}")
            return False  # Err on the side of caution
    
    @classmethod
    def _validate_filename(cls, filename: str) -> bool:
        """Validate filename for security issues"""
        if not filename:
            return False
        
        # Check for path traversal in filename
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        # Check for null bytes
        if '\x00' in filename:
            return False
        
        # Check filename length
        if len(filename) > 255:
            return False
        
        # Check for reserved Windows filenames
        windows_reserved = {
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
            'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
            'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        }
        
        basename = os.path.splitext(filename)[0].upper()
        if basename in windows_reserved:
            return False
        
        return True


class ORMInjectionProtection:
    """Django ORM injection protection"""
    
    # Dangerous ORM operations
    DANGEROUS_ORM_PATTERNS = [
        # Raw SQL in ORM
        r'\.raw\s*\(',
        r'\.extra\s*\(',
        r'cursor\.execute\s*\(',
        
        # Dynamic field access
        r'__[a-zA-Z_]+__[a-zA-Z_]*',
        
        # Dangerous lookups
        r'__regex\b',
        r'__iregex\b',
        
        # SQL injection via ORM
        r'filter\s*\(\s*[\'"][^\'\"]*[;\|&`$(){}[\]<>]',
        r'exclude\s*\(\s*[\'"][^\'\"]*[;\|&`$(){}[\]<>]',
        r'get\s*\(\s*[\'"][^\'\"]*[;\|&`$(){}[\]<>]',
        
        # F() expression abuse
        r'F\s*\(\s*[\'"][^\'\"]*[;\|&`$(){}[\]<>]',
        
        # Q() object abuse  
        r'Q\s*\(\s*[^)]*[;\|&`${}[\]<>]',
    ]
    
    # Safe ORM patterns (whitelist)
    SAFE_LOOKUP_TYPES = {
        'exact', 'iexact', 'contains', 'icontains', 'in', 'gt', 'gte',
        'lt', 'lte', 'startswith', 'istartswith', 'endswith', 'iendswith',
        'range', 'date', 'year', 'month', 'day', 'week', 'week_day',
        'time', 'hour', 'minute', 'second', 'isnull', 'search', 'regex',
        'iregex'
    }
    
    @classmethod
    def validate_orm_query(cls, query_params: Dict[str, Any]) -> bool:
        """Validate ORM query parameters for injection attempts"""
        
        for field_name, value in query_params.items():
            # Validate field name
            if not cls._validate_field_name(field_name):
                logger.warning(f"Dangerous ORM field name: {field_name}")
                return False
            
            # Validate field value
            if not cls._validate_field_value(value):
                logger.warning(f"Dangerous ORM field value: {value}")
                return False
        
        return True
    
    @classmethod
    def _validate_field_name(cls, field_name: str) -> bool:
        """Validate ORM field name"""
        if not isinstance(field_name, str):
            return True  # Non-string field names are typically safe
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_ORM_PATTERNS:
            if re.search(pattern, field_name, re.IGNORECASE):
                return False
        
        # Validate lookup structure
        if '__' in field_name:
            parts = field_name.split('__')
            # Last part should be a safe lookup type
            lookup_type = parts[-1]
            if lookup_type not in cls.SAFE_LOOKUP_TYPES:
                # Allow numeric lookups for array/JSON fields
                if not lookup_type.isdigit():
                    return False
        
        return True
    
    @classmethod
    def _validate_field_value(cls, value: Any) -> bool:
        """Validate ORM field value"""
        if isinstance(value, str):
            # Check for SQL injection patterns in string values
            sql_patterns = [
                r'[;\'"]\s*(union|select|insert|update|delete|drop|create|alter)',
                r'--\s*',
                r'/\*.*?\*/',
                r'@@\w+',
                r'\bexec\s*\(',
                r'\beval\s*\(',
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return False
        
        return True


class TemplateInjectionProtection:
    """Server-Side Template Injection (SSTI) protection"""
    
    # Template injection patterns for various engines
    TEMPLATE_INJECTION_PATTERNS = [
        # Django template injection
        r'\{\{.*?[;|&`$()[\]<>].*?\}\}',
        r'\{%.*?[;|&`$()[\]<>].*?%\}',
        r'\{\{.*?(exec|eval|import|__import__|compile).*?\}\}',
        r'\{\{.*?request.*?\}\}',
        r'\{\{.*?config.*?\}\}',
        r'\{\{.*?self.*?\}\}',
        
        # Jinja2 template injection
        r'\{\{.*?__class__.*?\}\}',
        r'\{\{.*?__mro__.*?\}\}',
        r'\{\{.*?__globals__.*?\}\}',
        r'\{\{.*?__builtins__.*?\}\}',
        r'\{\{.*?__subclasses__.*?\}\}',
        r'\{\{.*?cycler.*?\}\}',
        r'\{\{.*?joiner.*?\}\}',
        r'\{\{.*?namespace.*?\}\}',
        
        # General template engines
        r'\$\{.*?[;|&`$()[\]<>].*?\}',  # Freemarker, Velocity
        r'<%.*?[;|&`$()[\]<>].*?%>',    # JSP, ASP
        r'#\{.*?[;|&`$()[\]<>].*?\}',   # Ruby ERB
        
        # Code execution attempts
        r'\{\{.*?(system|os\.|subprocess|popen).*?\}\}',
        r'\{\{.*?(\|safe|\|escape).*?\}\}',
        r'\{\{.*?range\(.*?\).*?\}\}',
        r'\{\{.*?lipsum.*?\}\}',
        r'\{\{.*?url_for.*?\}\}',
        
        # Python object access
        r'\{\{.*?\[.*?\].*?\}\}',
        r'\{\{.*?\.__.*?\}\}',
        r'\{\{.*?\.func_globals.*?\}\}',
        r'\{\{.*?\.gi_frame.*?\}\}',
    ]
    
    # Dangerous template tags/filters
    DANGEROUS_TEMPLATE_ELEMENTS = {
        'load', 'include', 'extends', 'ssi', 'url', 'static',
        'debug', 'settings', 'request', 'user', 'perms'
    }
    
    @classmethod
    def validate_template_content(cls, content: str) -> bool:
        """Validate template content for injection attempts"""
        if not isinstance(content, str):
            return True
        
        # Check for template injection patterns
        for pattern in cls.TEMPLATE_INJECTION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                logger.warning(f"Template injection pattern detected: {pattern}")
                return False
        
        # Check for dangerous Django template elements
        template_tags = re.findall(r'\{%\s*(\w+)', content)
        template_variables = re.findall(r'\{\{\s*(\w+)', content)
        
        for tag in template_tags:
            if tag.lower() in cls.DANGEROUS_TEMPLATE_ELEMENTS:
                logger.warning(f"Dangerous template tag detected: {tag}")
                return False
        
        for var in template_variables:
            if var.lower() in cls.DANGEROUS_TEMPLATE_ELEMENTS:
                logger.warning(f"Dangerous template variable detected: {var}")
                return False
        
        return True
    
    @classmethod
    def sanitize_template_input(cls, content: str) -> str:
        """Sanitize template input content"""
        if not isinstance(content, str):
            return content
        
        # Remove dangerous template constructs
        # Note: This is aggressive sanitization
        content = re.sub(r'\{\{.*?\}\}', '', content)  # Remove all template variables
        content = re.sub(r'\{%.*?%\}', '', content)    # Remove all template tags
        content = re.sub(r'\{#.*?#\}', '', content)    # Remove template comments
        
        # HTML escape the content
        content = escape(content)
        
        return content
    
    @classmethod
    def safe_template_render(cls, template_string: str, context_dict: Dict[str, Any]) -> str:
        """Safely render a template with restricted context"""
        
        # Validate template content first
        if not cls.validate_template_content(template_string):
            raise ValueError("Template contains dangerous content")
        
        # Create a restricted context
        safe_context = cls._create_safe_context(context_dict)
        
        try:
            template = Template(template_string)
            context = Context(safe_context)
            return template.render(context)
        except TemplateSyntaxError as e:
            logger.error(f"Template syntax error: {str(e)}")
            raise ValueError("Invalid template syntax")
        except Exception as e:
            logger.error(f"Template rendering error: {str(e)}")
            raise ValueError("Template rendering failed")
    
    @classmethod
    def _create_safe_context(cls, context_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Create a safe template context"""
        safe_context = {}
        
        for key, value in context_dict.items():
            # Only allow safe data types
            if isinstance(value, (str, int, float, bool, list, dict)):
                # Recursively sanitize nested structures
                if isinstance(value, str):
                    safe_context[key] = escape(value)
                elif isinstance(value, dict):
                    safe_context[key] = cls._sanitize_dict(value)
                elif isinstance(value, list):
                    safe_context[key] = cls._sanitize_list(value)
                else:
                    safe_context[key] = value
        
        return safe_context
    
    @classmethod
    def _sanitize_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary"""
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = escape(value)
            elif isinstance(value, dict):
                sanitized[key] = cls._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = cls._sanitize_list(value)
            elif isinstance(value, (int, float, bool)):
                sanitized[key] = value
        return sanitized
    
    @classmethod
    def _sanitize_list(cls, data: List[Any]) -> List[Any]:
        """Recursively sanitize list"""
        sanitized = []
        for item in data:
            if isinstance(item, str):
                sanitized.append(escape(item))
            elif isinstance(item, dict):
                sanitized.append(cls._sanitize_dict(item))
            elif isinstance(item, list):
                sanitized.append(cls._sanitize_list(item))
            elif isinstance(item, (int, float, bool)):
                sanitized.append(item)
        return sanitized


class ExtendedSecurityMiddleware(MiddlewareMixin):
    """Extended security middleware for additional attack vectors"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Process incoming request for extended security threats"""
        
        # Skip security checks for certain paths
        skip_paths = ['/health/api/status/', '/static/', '/media/', '/favicon.ico']
        if any(skip_path in request.path for skip_path in skip_paths):
            return None
        
        try:
            # 1. SQLMap detection
            is_sqlmap, sqlmap_details = SQLMapProtection.detect_sqlmap_attack(request)
            if is_sqlmap:
                self._log_security_event(request, 'SQLMAP_ATTACK', sqlmap_details)
                raise SuspiciousOperation("SQLMap attack detected")
            
            # 2. Brute force detection
            view_name = self._get_view_name(request.path)
            is_brute_force, attack_type, details = BruteForceProtection.detect_brute_force(request, view_name)
            if is_brute_force:
                self._log_security_event(request, f'BRUTE_FORCE_{attack_type.upper()}', details)
                raise SuspiciousOperation("Brute force attack detected")
            
            # 3. ORM injection validation for query parameters
            if not ORMInjectionProtection.validate_orm_query(request.GET.dict()):
                self._log_security_event(request, 'ORM_INJECTION', 'Dangerous ORM query detected')
                raise SuspiciousOperation("ORM injection attempt detected")
            
            # 4. Template injection validation for POST data
            if request.method == 'POST' and hasattr(request, 'POST'):
                for field_name, field_value in request.POST.items():
                    if isinstance(field_value, str) and field_value:
                        if not TemplateInjectionProtection.validate_template_content(field_value):
                            self._log_security_event(request, 'TEMPLATE_INJECTION', f'Template injection in field: {field_name}')
                            raise SuspiciousOperation("Template injection attempt detected")
        
        except SuspiciousOperation:
            raise
        except Exception as e:
            logger.error(f"Error in extended security validation: {str(e)}")
        
        return None
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        """Process view for file upload validation"""
        
        # Check for file uploads
        if request.method == 'POST' and hasattr(request, 'FILES'):
            for field_name, uploaded_file in request.FILES.items():
                is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
                if not is_valid:
                    self._log_security_event(request, 'MALICIOUS_FILE_UPLOAD', f'File: {uploaded_file.name}, Reason: {message}')
                    raise SuspiciousOperation(f"File upload rejected: {message}")
        
        return None
    
    def _get_view_name(self, path: str) -> str:
        """Get view name from path for rate limiting"""
        if '/login' in path.lower() or '/signin' in path.lower():
            return 'login'
        elif '/admin' in path.lower():
            return 'admin'
        elif '/api/' in path.lower():
            return 'api'
        else:
            return 'default'
    
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