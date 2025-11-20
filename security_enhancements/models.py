"""
Security Enhancements Models
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json


class SecurityEvent(models.Model):
    """Track security events and threats"""
    EVENT_TYPES = [
        ('SQL_INJECTION', 'SQL Injection Attempt'),
        ('XSS_ATTACK', 'Cross-Site Scripting'),
        ('CSRF_ATTACK', 'CSRF Attack'),
        ('BRUTE_FORCE', 'Brute Force Attack'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity'),
        ('ACCESS_DENIED', 'Access Denied'),
        ('MALICIOUS_FILE', 'Malicious File Upload'),
        ('RATE_LIMIT', 'Rate Limit Exceeded'),
        ('DATA_BREACH', 'Data Breach Attempt'),
        ('AUTHENTICATION_FAILURE', 'Authentication Failure'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='MEDIUM')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10)
    payload = models.TextField(blank=True)
    headers = models.JSONField(default=dict)
    timestamp = models.DateTimeField(default=timezone.now)
    resolved = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['severity', 'resolved']),
        ]
    
    def __str__(self):
        return f"{self.event_type} - {self.ip_address} - {self.timestamp}"


class BlockedIP(models.Model):
    """Track blocked IP addresses"""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=200)
    blocked_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_permanent = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['-blocked_at']
    
    def __str__(self):
        return f"Blocked: {self.ip_address} - {self.reason}"
    
    @property
    def is_expired(self):
        if self.is_permanent:
            return False
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False


class SecurityConfiguration(models.Model):
    """Security configuration settings"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
    description = models.CharField(max_length=500, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        ordering = ['key']
    
    def __str__(self):
        return f"{self.key}: {self.value[:50]}..."


class AuditLog(models.Model):
    """Audit log for tracking user actions"""
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('READ', 'Read'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('EXPORT', 'Export'),
        ('IMPORT', 'Import'),
        ('ADMIN_ACTION', 'Admin Action'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_TYPES)
    model_name = models.CharField(max_length=100, blank=True)
    object_id = models.CharField(max_length=100, blank=True)
    changes = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['model_name', 'object_id']),
        ]
    
    def __str__(self):
        user_name = self.user.username if self.user else 'Anonymous'
        return f"{user_name} - {self.action} - {self.timestamp}"