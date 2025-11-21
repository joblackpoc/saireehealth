"""
OWASP Database Security and SQL Injection Prevention
Comprehensive database security implementation
"""

import logging
from typing import Any, Dict, List, Optional, Union
from django.db import models, connection
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils.html import escape
from django.contrib.auth.models import AbstractUser
import re
import hashlib
from datetime import datetime, timedelta
from django.utils import timezone

logger = logging.getLogger('security_enhancements')

class SecureQuerySet(models.QuerySet):
    """
    Secure QuerySet with SQL injection prevention
    """
    
    def safe_filter(self, **kwargs):
        """Safe filtering with input validation"""
        validated_kwargs = {}
        
        for key, value in kwargs.items():
            # Validate field names
            if not self._validate_field_name(key):
                logger.warning(f"Invalid field name in query: {key}")
                raise ValidationError(f"Invalid field name: {key}")
            
            # Validate values
            if isinstance(value, str):
                validated_value = self._validate_string_value(value)
                if validated_value is None:
                    logger.warning(f"Potentially malicious value in query: {value}")
                    raise ValidationError("Invalid query value")
                validated_kwargs[key] = validated_value
            else:
                validated_kwargs[key] = value
        
        return self.filter(**validated_kwargs)
    
    def safe_search(self, search_term: str, search_fields: List[str]):
        """Safe search with validation"""
        if not search_term or not search_fields:
            return self.none()
        
        # Validate search term
        validated_term = self._validate_search_term(search_term)
        if not validated_term:
            return self.none()
        
        # Validate search fields
        validated_fields = []
        for field in search_fields:
            if self._validate_field_name(field):
                validated_fields.append(field)
        
        if not validated_fields:
            return self.none()
        
        # Build safe search query
        query = Q()
        for field in validated_fields:
            query |= Q(**{f"{field}__icontains": validated_term})
        
        return self.filter(query)
    
    def _validate_field_name(self, field_name: str) -> bool:
        """Validate database field names"""
        # Only allow alphanumeric characters, underscores, and double underscores for lookups
        pattern = r'^[a-zA-Z][a-zA-Z0-9_]*(__[a-zA-Z]+)*$'
        if not re.match(pattern, field_name):
            return False
        
        # Check against model fields
        try:
            # Get the base field name (before any lookup)
            base_field = field_name.split('__')[0]
            model_fields = [f.name for f in self.model._meta.get_fields()]
            return base_field in model_fields
        except Exception:
            return False
    
    def _validate_string_value(self, value: str) -> Optional[str]:
        """Validate string values for SQL injection patterns"""
        if not isinstance(value, str):
            return value
        
        # Check for SQL injection patterns
        sql_patterns = [
            r"[';\"\\]",  # Quote characters
            r"(--)|(#)",  # Comment patterns
            r"(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+",
            r"or\s+1\s*=\s*1",
            r"and\s+1\s*=\s*1",
            r"'\\s*or\\s*'",
            r"\\b(script|javascript|vbscript)\\b",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return None
        
        # Limit length
        if len(value) > 1000:
            return value[:1000]
        
        return value
    
    def _validate_search_term(self, search_term: str) -> Optional[str]:
        """Validate search terms"""
        if not search_term or len(search_term) < 2:
            return None
        
        # Remove potentially dangerous characters
        cleaned_term = re.sub(r'[<>\"\'%;()&+]', '', search_term)
        
        # Validate length
        if len(cleaned_term) > 100:
            cleaned_term = cleaned_term[:100]
        
        return cleaned_term.strip() if cleaned_term.strip() else None


class SecureManager(models.Manager):
    """Secure model manager with built-in protections"""
    
    def get_queryset(self):
        return SecureQuerySet(self.model, using=self._db)
    
    def safe_filter(self, **kwargs):
        return self.get_queryset().safe_filter(**kwargs)
    
    def safe_search(self, search_term: str, search_fields: List[str]):
        return self.get_queryset().safe_search(search_term, search_fields)


class AuditMixin(models.Model):
    """
    Mixin for adding audit fields to models
    """
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True


class SecurityLog(models.Model):
    """
    Model for logging security events
    """
    
    EVENT_TYPES = [
        ('login_success', 'Login Success'),
        ('login_failure', 'Login Failure'),
        ('logout', 'Logout'),
        ('password_change', 'Password Change'),
        ('mfa_setup', 'MFA Setup'),
        ('mfa_verify', 'MFA Verification'),
        ('account_locked', 'Account Locked'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('data_access', 'Data Access'),
        ('data_modification', 'Data Modification'),
        ('file_upload', 'File Upload'),
        ('api_access', 'API Access'),
        ('injection_attempt', 'Injection Attempt'),
        ('xss_attempt', 'XSS Attempt'),
        ('csrf_failure', 'CSRF Failure'),
        ('unauthorized_access', 'Unauthorized Access'),
        ('session_anomaly', 'Session Anomaly'),
    ]
    
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    user = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict, blank=True)
    risk_level = models.CharField(
        max_length=10,
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')],
        default='low'
    )
    
    objects = SecureManager()
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.user} - {self.timestamp}"


class DatabaseSecurityMonitor:
    """
    Monitor database queries for security issues
    """
    
    @staticmethod
    def log_query_execution(sql: str, params: tuple = None):
        """Log database query execution"""
        # Check for suspicious patterns in raw SQL
        if DatabaseSecurityMonitor._is_suspicious_query(sql):
            logger.warning(
                f"Suspicious database query detected: {sql[:200]}...",
                extra={'sql': sql, 'params': params}
            )
    
    @staticmethod
    def _is_suspicious_query(sql: str) -> bool:
        """Check if query contains suspicious patterns"""
        suspicious_patterns = [
            r"union\\s+select",
            r"information_schema",
            r"pg_catalog",
            r"sys\\.",
            r"mysql\\.",
            r"--\\s*",
            r"/\\*.*\\*/",
            r"xp_cmdshell",
            r"sp_configure",
            r"openrowset",
            r"load_file",
            r"into\\s+outfile",
            r"into\\s+dumpfile"
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, sql, re.IGNORECASE):
                return True
        
        return False


class SecureDatabaseConnection:
    """
    Secure database connection wrapper
    """
    
    @staticmethod
    def execute_safe_query(query: str, params: tuple = None):
        """Execute query with security monitoring"""
        # Log query execution
        DatabaseSecurityMonitor.log_query_execution(query, params)
        
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Database query error: {str(e)}", extra={'query': query})
            raise
    
    @staticmethod
    def validate_table_name(table_name: str) -> bool:
        """Validate table name to prevent injection"""
        # Only allow alphanumeric characters and underscores
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', table_name):
            return False
        
        # Check against known table names
        try:
            tables = connection.introspection.table_names()
            return table_name in tables
        except Exception:
            return False
    
    @staticmethod
    def validate_column_name(table_name: str, column_name: str) -> bool:
        """Validate column name to prevent injection"""
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', column_name):
            return False
        
        try:
            table_description = connection.introspection.get_table_description(connection.cursor(), table_name)
            column_names = [row[0] for row in table_description]
            return column_name in column_names
        except Exception:
            return False


class DataEncryption:
    """
    Utilities for data encryption at rest
    """
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: str = None) -> str:
        """Hash sensitive data for storage"""
        if salt is None:
            import secrets
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 for hashing
        hashed = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)
        return f"{salt}:{hashed.hex()}"
    
    @staticmethod
    def verify_hashed_data(data: str, hashed_data: str) -> bool:
        """Verify hashed data"""
        try:
            salt, hash_hex = hashed_data.split(':', 1)
            expected_hash = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)
            return hash_hex == expected_hash.hex()
        except Exception:
            return False