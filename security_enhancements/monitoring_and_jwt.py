"""
Security Monitoring, Alerting, and JWT Security for HealthProgress
"""
# JWT functionality temporarily disabled for testing
# import PyJWT as jwt
jwt = None
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from django.conf import settings
from django.core.mail import send_mail
from django.core.cache import cache
from .security_core import SecurityLogger, CryptoUtils


class SecurityMonitor:
    """Real-time Security Monitoring and Metrics"""
    
    @staticmethod
    def get_security_dashboard() -> Dict[str, Any]:
        """Get comprehensive security dashboard data"""
        from .security_core import SecurityCore
        
        # Get recent events
        recent_events = SecurityLogger.get_recent_events(hours=24)
        
        # Get metrics
        metrics = SecurityCore.get_security_metrics(days=7)
        
        # Calculate statistics
        total_events = len(recent_events)
        critical_events = sum(1 for e in recent_events if e.get('severity') == 'critical')
        high_events = sum(1 for e in recent_events if e.get('severity') == 'high')
        
        # Get top attack types
        attack_types = {}
        for event in recent_events:
            event_type = event.get('event_type', 'unknown')
            attack_types[event_type] = attack_types.get(event_type, 0) + 1
        
        top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Get top attacking IPs
        attacking_ips = {}
        for event in recent_events:
            if 'ip' in event:
                ip = event['ip']
                attacking_ips[ip] = attacking_ips.get(ip, 0) + 1
        
        top_ips = sorted(attacking_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Get blocked IPs count
        blocked_ips = cache.get('blocked_ips_list', [])
        
        return {
            'summary': {
                'total_events_24h': total_events,
                'critical_events': critical_events,
                'high_events': high_events,
                'blocked_ips': len(blocked_ips),
            },
            'metrics_7d': metrics,
            'top_attacks': top_attacks,
            'top_attacking_ips': top_ips,
            'recent_events': recent_events[:50],  # Last 50 events
        }
    
    @staticmethod
    def detect_anomalies() -> List[Dict[str, Any]]:
        """Detect anomalous security behavior"""
        anomalies = []
        
        # Get recent events
        events = SecurityLogger.get_recent_events(hours=1)
        
        # Detect rate anomalies (sudden spike in attacks)
        event_rate = len(events)
        avg_rate = cache.get('avg_event_rate', 0)
        
        if event_rate > avg_rate * 3:  # 3x normal rate
            anomalies.append({
                'type': 'rate_spike',
                'severity': 'high',
                'message': f'Attack rate spike detected: {event_rate} events in last hour (avg: {avg_rate})',
                'timestamp': datetime.now().isoformat()
            })
        
        # Update average rate
        cache.set('avg_event_rate', (avg_rate * 0.9 + event_rate * 0.1), timeout=86400)
        
        # Detect distributed attacks (multiple IPs targeting same endpoint)
        endpoints = {}
        for event in events:
            if 'path' in event:
                path = event['path']
                endpoints[path] = endpoints.get(path, set())
                if 'ip' in event:
                    endpoints[path].add(event['ip'])
        
        for path, ips in endpoints.items():
            if len(ips) > 10:  # 10+ different IPs
                anomalies.append({
                    'type': 'distributed_attack',
                    'severity': 'critical',
                    'message': f'Distributed attack detected on {path}: {len(ips)} unique IPs',
                    'timestamp': datetime.now().isoformat()
                })
        
        # Detect user account enumeration
        failed_logins = {}
        for event in events:
            if event.get('event_type') == 'login_failed':
                ip = event.get('ip', 'unknown')
                failed_logins[ip] = failed_logins.get(ip, 0) + 1
        
        for ip, count in failed_logins.items():
            if count > 20:  # 20+ failed logins
                anomalies.append({
                    'type': 'account_enumeration',
                    'severity': 'high',
                    'message': f'Possible account enumeration from {ip}: {count} failed logins',
                    'timestamp': datetime.now().isoformat()
                })
        
        return anomalies
    
    @staticmethod
    def generate_security_report(days: int = 7) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        from .security_core import SecurityCore
        
        # Get all events for period
        all_events = []
        for i in range(days):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            cache_key = f"security_events:{date}"
            all_events.extend(cache.get(cache_key, []))
        
        # Calculate statistics
        total_events = len(all_events)
        
        # Events by severity
        severity_counts = {
            'critical': sum(1 for e in all_events if e.get('severity') == 'critical'),
            'high': sum(1 for e in all_events if e.get('severity') == 'high'),
            'medium': sum(1 for e in all_events if e.get('severity') == 'medium'),
            'low': sum(1 for e in all_events if e.get('severity') == 'low'),
        }
        
        # Events by type
        type_counts = {}
        for event in all_events:
            event_type = event.get('event_type', 'unknown')
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
        
        # Events by day
        daily_counts = {}
        for event in all_events:
            date = event.get('timestamp', '')[:10]  # YYYY-MM-DD
            daily_counts[date] = daily_counts.get(date, 0) + 1
        
        return {
            'period': f'{days} days',
            'total_events': total_events,
            'severity_breakdown': severity_counts,
            'event_types': type_counts,
            'daily_counts': daily_counts,
            'generated_at': datetime.now().isoformat()
        }


class SecurityAlerting:
    """Security Alert System"""
    
    @staticmethod
    def send_alert(alert_type: str, severity: str, details: Dict[str, Any]):
        """Send security alert via configured channels"""
        
        # Format alert message
        alert_message = SecurityAlerting._format_alert(alert_type, severity, details)
        
        # Send email alert
        if getattr(settings, 'SECURITY_ALERT_EMAIL', None):
            SecurityAlerting._send_email_alert(alert_message, severity)
        
        # Send webhook alert (Slack, Discord, etc.)
        webhook_url = getattr(settings, 'SECURITY_ALERT_WEBHOOK', None)
        if webhook_url:
            SecurityAlerting._send_webhook_alert(webhook_url, alert_message, severity)
        
        # Log alert
        SecurityLogger.log_security_event(
            'security_alert_sent',
            severity,
            {
                'alert_type': alert_type,
                'details': details
            }
        )
    
    @staticmethod
    def _format_alert(alert_type: str, severity: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Format alert message"""
        return {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,
            'severity': severity.upper(),
            'application': 'HealthProgress',
            'details': details
        }
    
    @staticmethod
    def _send_email_alert(alert: Dict[str, Any], severity: str):
        """Send email alert"""
        subject = f"[{severity.upper()}] Security Alert - {alert['alert_type']}"
        
        message = f"""
Security Alert from HealthProgress

Timestamp: {alert['timestamp']}
Severity: {alert['severity']}
Alert Type: {alert['alert_type']}

Details:
{json.dumps(alert['details'], indent=2)}

---
This is an automated security alert.
        """
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [settings.SECURITY_ALERT_EMAIL],
                fail_silently=False,
            )
        except Exception as e:
            SecurityLogger.log_security_event(
                'alert_email_failed',
                'medium',
                {'error': str(e)}
            )
    
    @staticmethod
    def _send_webhook_alert(webhook_url: str, alert: Dict[str, Any], severity: str):
        """Send webhook alert (Slack/Discord compatible)"""
        
        # Color coding by severity
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745'
        }
        
        # Format for Slack/Discord
        payload = {
            'embeds': [{
                'title': f"🚨 Security Alert: {alert['alert_type']}",
                'description': f"**Severity:** {alert['severity']}",
                'color': int(colors.get(severity, '#6c757d').replace('#', ''), 16),
                'fields': [
                    {'name': 'Timestamp', 'value': alert['timestamp'], 'inline': True},
                    {'name': 'Application', 'value': 'HealthProgress', 'inline': True},
                ],
                'footer': {'text': 'HealthProgress Security System'}
            }]
        }
        
        # Add details
        for key, value in alert['details'].items():
            payload['embeds'][0]['fields'].append({
                'name': key,
                'value': str(value)[:100],  # Limit length
                'inline': False
            })
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=5
            )
            response.raise_for_status()
        except Exception as e:
            SecurityLogger.log_security_event(
                'alert_webhook_failed',
                'medium',
                {'error': str(e)}
            )
    
    @staticmethod
    def check_and_alert():
        """Check for conditions that require alerting"""
        
        # Check for anomalies
        anomalies = SecurityMonitor.detect_anomalies()
        for anomaly in anomalies:
            SecurityAlerting.send_alert(
                anomaly['type'],
                anomaly['severity'],
                {'message': anomaly['message']}
            )
        
        # Check for high-frequency attacks
        recent_events = SecurityLogger.get_recent_events(hours=1)
        critical_count = sum(1 for e in recent_events if e.get('severity') == 'critical')
        
        if critical_count > 10:
            SecurityAlerting.send_alert(
                'high_frequency_attack',
                'critical',
                {
                    'count': critical_count,
                    'period': '1 hour',
                    'message': f'{critical_count} critical security events in the last hour'
                }
            )


class JWTSecurity:
    """JWT Token Security Management"""
    
    SECRET_KEY = getattr(settings, 'JWT_SECRET_KEY', CryptoUtils.generate_secure_token())
    ALGORITHM = 'HS256'
    ACCESS_TOKEN_EXPIRE = 15  # minutes
    REFRESH_TOKEN_EXPIRE = 7  # days
    
    @classmethod
    def create_access_token(cls, user_id: int, additional_claims: Dict = None) -> str:
        """Create JWT access token"""
        payload = {
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE),
            'iat': datetime.utcnow(),
            'jti': CryptoUtils.generate_secure_token(16)  # Unique token ID
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
        
        # Store token JTI in cache for revocation checking
        cache.set(f"jwt_jti:{payload['jti']}", True, timeout=cls.ACCESS_TOKEN_EXPIRE * 60)
        
        return token
    
    @classmethod
    def create_refresh_token(cls, user_id: int) -> str:
        """Create JWT refresh token"""
        payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + timedelta(days=cls.REFRESH_TOKEN_EXPIRE),
            'iat': datetime.utcnow(),
            'jti': CryptoUtils.generate_secure_token(16)
        }
        
        token = jwt.encode(payload, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
        
        # Store token JTI
        cache.set(f"jwt_jti:{payload['jti']}", True, timeout=cls.REFRESH_TOKEN_EXPIRE * 86400)
        
        return token
    
    @classmethod
    def verify_token(cls, token: str, token_type: str = 'access') -> Optional[Dict]:
        """Verify and decode JWT token"""
        try:
            # Decode token
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            
            # Verify token type
            if payload.get('type') != token_type:
                SecurityLogger.log_security_event(
                    'jwt_type_mismatch',
                    'medium',
                    {'expected': token_type, 'got': payload.get('type')}
                )
                return None
            
            # Check if token is revoked
            jti = payload.get('jti')
            if jti and not cache.get(f"jwt_jti:{jti}"):
                SecurityLogger.log_security_event(
                    'jwt_revoked_token_used',
                    'high',
                    {'jti': jti}
                )
                return None
            
            return payload
        
        except jwt.ExpiredSignatureError:
            SecurityLogger.log_security_event(
                'jwt_expired',
                'low',
                {'message': 'Token has expired'}
            )
            return None
        
        except jwt.InvalidTokenError as e:
            SecurityLogger.log_security_event(
                'jwt_invalid',
                'medium',
                {'error': str(e)}
            )
            return None
    
    @classmethod
    def revoke_token(cls, token: str):
        """Revoke a JWT token"""
        try:
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            jti = payload.get('jti')
            
            if jti:
                cache.delete(f"jwt_jti:{jti}")
                SecurityLogger.log_security_event(
                    'jwt_revoked',
                    'low',
                    {'jti': jti}
                )
        except Exception as e:
            SecurityLogger.log_security_event(
                'jwt_revoke_failed',
                'medium',
                {'error': str(e)}
            )
    
    @classmethod
    def refresh_access_token(cls, refresh_token: str) -> Optional[str]:
        """Generate new access token using refresh token"""
        payload = cls.verify_token(refresh_token, token_type='refresh')
        
        if payload:
            user_id = payload['user_id']
            return cls.create_access_token(user_id)
        
        return None
    
    @classmethod
    def validate_token_signature(cls, token: str) -> bool:
        """Validate token signature without decoding"""
        try:
            jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            return True
        except:
            return False