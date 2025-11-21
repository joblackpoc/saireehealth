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
        
        return value\n    \n    def _validate_search_term(self, search_term: str) -> Optional[str]:\n        """Validate search terms"""\n        if not search_term or len(search_term) < 2:\n            return None\n        \n        # Remove potentially dangerous characters\n        cleaned_term = re.sub(r'[<>\"\'%;()&+]', '', search_term)\n        \n        # Validate length\n        if len(cleaned_term) > 100:\n            cleaned_term = cleaned_term[:100]\n        \n        return cleaned_term.strip() if cleaned_term.strip() else None\n\n\nclass SecureManager(models.Manager):\n    """Secure model manager with built-in protections"""\n    \n    def get_queryset(self):\n        return SecureQuerySet(self.model, using=self._db)\n    \n    def safe_filter(self, **kwargs):\n        return self.get_queryset().safe_filter(**kwargs)\n    \n    def safe_search(self, search_term: str, search_fields: List[str]):\n        return self.get_queryset().safe_search(search_term, search_fields)\n    \n    def safe_get_or_create(self, defaults=None, **kwargs):\n        """Secure get_or_create with validation"""\n        # Validate input data\n        validated_kwargs = self._validate_lookup_kwargs(kwargs)\n        validated_defaults = self._validate_defaults(defaults or {})\n        \n        return super().get_or_create(defaults=validated_defaults, **validated_kwargs)\n    \n    def _validate_lookup_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:\n        """Validate lookup kwargs"""\n        validated = {}\n        \n        for key, value in kwargs.items():\n            # Validate field name\n            if not self._is_valid_field_name(key):\n                raise ValidationError(f"Invalid field name: {key}")\n            \n            # Sanitize value\n            if isinstance(value, str):\n                sanitized_value = self._sanitize_string_value(value)\n                if sanitized_value is None:\n                    raise ValidationError(f"Invalid value for field {key}")\n                validated[key] = sanitized_value\n            else:\n                validated[key] = value\n        \n        return validated\n    \n    def _validate_defaults(self, defaults: Dict[str, Any]) -> Dict[str, Any]:\n        """Validate default values"""\n        return self._validate_lookup_kwargs(defaults)\n    \n    def _is_valid_field_name(self, field_name: str) -> bool:\n        """Check if field name is valid"""\n        try:\n            model_fields = [f.name for f in self.model._meta.get_fields()]\n            base_field = field_name.split('__')[0]\n            return base_field in model_fields\n        except Exception:\n            return False\n    \n    def _sanitize_string_value(self, value: str) -> Optional[str]:\n        """Sanitize string values"""\n        if not isinstance(value, str):\n            return value\n        \n        # Remove dangerous patterns\n        dangerous_patterns = [\n            r"<script[^>]*>.*?</script>",\n            r"javascript:",\n            r"vbscript:",\n            r"on\\w+\\s*=",\n            r"['\";\\\\]"\n        ]\n        \n        for pattern in dangerous_patterns:\n            if re.search(pattern, value, re.IGNORECASE):\n                logger.warning(f"Dangerous pattern detected in value: {value[:50]}...")\n                return None\n        \n        # HTML escape\n        value = escape(value)\n        \n        return value\n\n\nclass AuditMixin(models.Model):\n    """\n    Mixin for adding audit fields to models\n    """\n    \n    created_at = models.DateTimeField(auto_now_add=True)\n    updated_at = models.DateTimeField(auto_now=True)\n    created_by = models.ForeignKey(\n        'auth.User',\n        on_delete=models.SET_NULL,\n        null=True,\n        related_name='%(class)s_created'\n    )\n    updated_by = models.ForeignKey(\n        'auth.User',\n        on_delete=models.SET_NULL,\n        null=True,\n        related_name='%(class)s_updated'\n    )\n    \n    class Meta:\n        abstract = True\n\n\nclass SecurityLog(models.Model):\n    """\n    Model for logging security events\n    """\n    \n    EVENT_TYPES = [\n        ('login_success', 'Login Success'),\n        ('login_failure', 'Login Failure'),\n        ('logout', 'Logout'),\n        ('password_change', 'Password Change'),\n        ('mfa_setup', 'MFA Setup'),\n        ('mfa_verify', 'MFA Verification'),\n        ('account_locked', 'Account Locked'),\n        ('suspicious_activity', 'Suspicious Activity'),\n        ('data_access', 'Data Access'),\n        ('data_modification', 'Data Modification'),\n        ('file_upload', 'File Upload'),\n        ('api_access', 'API Access'),\n    ]\n    \n    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)\n    user = models.ForeignKey(\n        'auth.User',\n        on_delete=models.SET_NULL,\n        null=True,\n        blank=True\n    )\n    ip_address = models.GenericIPAddressField()\n    user_agent = models.TextField(blank=True)\n    timestamp = models.DateTimeField(auto_now_add=True)\n    details = models.JSONField(default=dict, blank=True)\n    risk_level = models.CharField(\n        max_length=10,\n        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')],\n        default='low'\n    )\n    \n    objects = SecureManager()\n    \n    class Meta:\n        ordering = ['-timestamp']\n        indexes = [\n            models.Index(fields=['event_type', 'timestamp']),\n            models.Index(fields=['user', 'timestamp']),\n            models.Index(fields=['ip_address', 'timestamp']),\n        ]\n    \n    def __str__(self):\n        return f"{self.event_type} - {self.user} - {self.timestamp}"\n\n\nclass DatabaseSecurityMonitor:\n    """\n    Monitor database queries for security issues\n    """\n    \n    @staticmethod\n    def log_query_execution(sql: str, params: tuple = None):\n        """Log database query execution"""\n        # Check for suspicious patterns in raw SQL\n        if DatabaseSecurityMonitor._is_suspicious_query(sql):\n            logger.warning(\n                f"Suspicious database query detected: {sql[:200]}...",\n                extra={'sql': sql, 'params': params}\n            )\n    \n    @staticmethod\n    def _is_suspicious_query(sql: str) -> bool:\n        """Check if query contains suspicious patterns"""\n        suspicious_patterns = [\n            r"union\\s+select",\n            r"information_schema",\n            r"pg_catalog",\n            r"sys\\.",\n            r"mysql\\.",\n            r"--\\s*",\n            r"/\\*.*\\*/",\n            r"xp_cmdshell",\n            r"sp_configure",\n            r"openrowset",\n            r"load_file",\n            r"into\\s+outfile",\n            r"into\\s+dumpfile"\n        ]\n        \n        for pattern in suspicious_patterns:\n            if re.search(pattern, sql, re.IGNORECASE):\n                return True\n        \n        return False\n\n\nclass SecureDatabaseConnection:\n    """\n    Secure database connection wrapper\n    """\n    \n    @staticmethod\n    def execute_safe_query(query: str, params: tuple = None):\n        """Execute query with security monitoring"""\n        # Log query execution\n        DatabaseSecurityMonitor.log_query_execution(query, params)\n        \n        try:\n            with connection.cursor() as cursor:\n                cursor.execute(query, params)\n                return cursor.fetchall()\n        except Exception as e:\n            logger.error(f"Database query error: {str(e)}", extra={'query': query})\n            raise\n    \n    @staticmethod\n    def validate_table_name(table_name: str) -> bool:\n        """Validate table name to prevent injection"""\n        # Only allow alphanumeric characters and underscores\n        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', table_name):\n            return False\n        \n        # Check against known table names\n        try:\n            tables = connection.introspection.table_names()\n            return table_name in tables\n        except Exception:\n            return False\n    \n    @staticmethod\n    def validate_column_name(table_name: str, column_name: str) -> bool:\n        """Validate column name to prevent injection"""\n        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', column_name):\n            return False\n        \n        try:\n            table_description = connection.introspection.get_table_description(connection.cursor(), table_name)\n            column_names = [row[0] for row in table_description]\n            return column_name in column_names\n        except Exception:\n            return False\n\n\nclass DataEncryption:\n    """\n    Utilities for data encryption at rest\n    """\n    \n    @staticmethod\n    def hash_sensitive_data(data: str, salt: str = None) -> str:\n        \"\"\"Hash sensitive data for storage\"\"\"\n        if salt is None:\n            import secrets\n            salt = secrets.token_hex(16)\n        \n        # Use PBKDF2 for hashing\n        hashed = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)\n        return f"{salt}:{hashed.hex()}"\n    \n    @staticmethod\n    def verify_hashed_data(data: str, hashed_data: str) -> bool:\n        \"\"\"Verify hashed data\"\"\"\n        try:\n            salt, hash_hex = hashed_data.split(':', 1)\n            expected_hash = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)\n            return hash_hex == expected_hash.hex()\n        except Exception:\n            return False\n\n\n# Custom field for storing encrypted data\nclass EncryptedTextField(models.TextField):\n    \"\"\"Text field that automatically encrypts data\"\"\"\n    \n    def __init__(self, *args, **kwargs):\n        self.encrypt_key = kwargs.pop('encrypt_key', None)\n        super().__init__(*args, **kwargs)\n    \n    def to_python(self, value):\n        \"\"\"Decrypt when loading from database\"\"\"\n        if value is None:\n            return value\n        \n        # In a real implementation, you'd decrypt here\n        # This is a placeholder for demonstration\n        return value\n    \n    def get_prep_value(self, value):\n        \"\"\"Encrypt when saving to database\"\"\"\n        if value is None:\n            return value\n        \n        # In a real implementation, you'd encrypt here\n        # This is a placeholder for demonstration\n        return super().get_prep_value(value)\n\n\n# Example secure model\nclass SecureHealthRecord(AuditMixin):\n    \"\"\"Example of a secure health record model\"\"\"\n    \n    patient_id = models.CharField(max_length=100, db_index=True)\n    diagnosis = EncryptedTextField()\n    treatment_notes = EncryptedTextField(blank=True)\n    doctor_notes = models.TextField(blank=True)\n    \n    # Use secure manager\n    objects = SecureManager()\n    \n    class Meta:\n        permissions = [\n            ('view_sensitive_data', 'Can view sensitive health data'),\n            ('modify_sensitive_data', 'Can modify sensitive health data'),\n        ]\n    \n    def save(self, *args, **kwargs):\n        \"\"\"Override save to add security logging\"\"\"\n        is_new = self.pk is None\n        \n        # Log data modification\n        if not is_new:\n            SecurityLog.objects.create(\n                event_type='data_modification',\n                user=getattr(self, '_current_user', None),\n                ip_address=getattr(self, '_current_ip', '127.0.0.1'),\n                details={\n                    'model': self.__class__.__name__,\n                    'record_id': str(self.pk),\n                    'action': 'update'\n                }\n            )\n        \n        super().save(*args, **kwargs)\n        \n        if is_new:\n            SecurityLog.objects.create(\n                event_type='data_modification',\n                user=getattr(self, '_current_user', None),\n                ip_address=getattr(self, '_current_ip', '127.0.0.1'),\n                details={\n                    'model': self.__class__.__name__,\n                    'record_id': str(self.pk),\n                    'action': 'create'\n                }\n            )\n    \n    def delete(self, *args, **kwargs):\n        \"\"\"Override delete to add security logging\"\"\"\n        SecurityLog.objects.create(\n            event_type='data_modification',\n            user=getattr(self, '_current_user', None),\n            ip_address=getattr(self, '_current_ip', '127.0.0.1'),\n            details={\n                'model': self.__class__.__name__,\n                'record_id': str(self.pk),\n                'action': 'delete'\n            },\n            risk_level='medium'\n        )\n        \n        super().delete(*args, **kwargs)