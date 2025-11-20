"""
Security Audit System
Real-time security event tracking and logging for enhanced monitoring
"""

import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth.models import User
import json
import hashlib

security_logger = logging.getLogger('security_audit')

class SecurityAuditTracker:
    """Real-time security event tracking and analysis"""
    
    @staticmethod
    def log_security_event(event_type, description, user=None, ip_address=None, severity='medium', additional_data=None):
        """Log a security event with real-time tracking"""
        try:
            # Create security event record
            event = {
                'timestamp': timezone.now().isoformat(),
                'event_type': event_type,
                'description': description,
                'user': user.username if user else 'anonymous',
                'ip_address': ip_address or 'unknown',
                'severity': severity,
                'additional_data': additional_data or {},
                'event_id': hashlib.md5(f"{timezone.now().isoformat()}{event_type}{ip_address}".encode()).hexdigest()[:12]
            }
            
            # Store in cache for real-time access
            current_events = cache.get('security_events_realtime', [])
            current_events.insert(0, event)  # Most recent first
            
            # Keep only last 1000 events in cache
            if len(current_events) > 1000:
                current_events = current_events[:1000]
            
            cache.set('security_events_realtime', current_events, 3600 * 24)  # 24 hours
            
            # Log to file for permanent record
            security_logger.info(f"SECURITY_EVENT: {json.dumps(event)}")
            
            # Update real-time statistics
            SecurityAuditTracker._update_realtime_stats(event_type, severity)
            
            return event['event_id']
            
        except Exception as e:
            security_logger.error(f"Error logging security event: {str(e)}")
            return None
    
    @staticmethod
    def _update_realtime_stats(event_type, severity):
        """Update real-time security statistics"""
        try:
            # Get current stats
            stats = cache.get('security_stats_realtime', {
                'total_events': 0,
                'events_by_type': {},
                'events_by_severity': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'last_updated': timezone.now().isoformat()
            })
            
            # Update counters
            stats['total_events'] += 1
            stats['events_by_type'][event_type] = stats['events_by_type'].get(event_type, 0) + 1
            stats['events_by_severity'][severity] += 1
            stats['last_updated'] = timezone.now().isoformat()
            
            # Cache updated stats
            cache.set('security_stats_realtime', stats, 3600 * 24)
            
        except Exception as e:
            security_logger.error(f"Error updating security stats: {str(e)}")
    
    @staticmethod
    def get_security_events(limit=50, event_type=None, severity=None, hours=24):
        """Get recent security events with filtering"""
        try:
            events = cache.get('security_events_realtime', [])
            
            # Filter by time
            cutoff_time = timezone.now() - timedelta(hours=hours)
            events = [e for e in events if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) > cutoff_time]
            
            # Filter by event type
            if event_type:
                events = [e for e in events if e['event_type'] == event_type]
            
            # Filter by severity
            if severity:
                events = [e for e in events if e['severity'] == severity]
            
            return events[:limit]
            
        except Exception as e:
            security_logger.error(f"Error getting security events: {str(e)}")
            return []
    
    @staticmethod
    def get_security_summary():
        """Get comprehensive security summary"""
        try:
            stats = cache.get('security_stats_realtime', {})
            events = SecurityAuditTracker.get_security_events(limit=100)
            
            # Calculate threat level
            high_severity_events = len([e for e in events if e['severity'] in ['high', 'critical']])
            
            if high_severity_events > 10:
                threat_level = 'critical'
            elif high_severity_events > 5:
                threat_level = 'high'
            elif high_severity_events > 0:
                threat_level = 'medium'
            else:
                threat_level = 'low'
            
            return {
                'total_events_24h': len(events),
                'threat_level': threat_level,
                'high_severity_events': high_severity_events,
                'events_by_type': stats.get('events_by_type', {}),
                'events_by_severity': stats.get('events_by_severity', {}),
                'recent_events': events[:10],  # Last 10 events
                'last_updated': timezone.now().isoformat()
            }
            
        except Exception as e:
            security_logger.error(f"Error getting security summary: {str(e)}")
            return {}

class SecurityEventTypes:
    """Standardized security event types"""
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILED = 'login_failed'
    LOGOUT = 'logout'
    PASSWORD_RESET = 'password_reset'
    PROFILE_UPDATE = 'profile_update'
    ADMIN_ACCESS = 'admin_access'
    DATA_ACCESS = 'data_access'
    PERMISSION_DENIED = 'permission_denied'
    SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    SYSTEM_ERROR = 'system_error'

class SecurityEventSeverity:
    """Standardized security event severity levels"""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'