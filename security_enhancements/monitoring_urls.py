"""
Phase 8: Security Monitoring API URLs
URL patterns for advanced monitoring and response system APIs

Author: ETH Blue Team Engineer  
Created: 2025-11-15
Security Level: CRITICAL
Component: API Endpoints & Management
"""

from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt

from . import monitoring_middleware

app_name = 'security_monitoring'

# Phase 8: Advanced Monitoring & Response API Endpoints
urlpatterns = [
    # Main monitoring management API
    path('api/monitoring/', monitoring_middleware.SecurityMonitoringAPIView.as_view(), name='monitoring_api'),
    
    # Event streaming status and control
    path('api/streaming/status/', monitoring_middleware.event_stream_status, name='streaming_status'),
    
    # Security events API
    path('api/events/', monitoring_middleware.security_events_api, name='security_events'),
    
    # Threat intelligence API
    path('api/threat-intelligence/', monitoring_middleware.threat_intelligence_api, name='threat_intelligence'),
    
    # Security metrics API
    path('api/metrics/', monitoring_middleware.security_metrics_api, name='security_metrics'),
    
    # Security dashboard data
    path('api/dashboard/', monitoring_middleware.security_dashboard_view, name='security_dashboard'),
    
    # WebSocket endpoint info (actual WebSocket server runs separately)
    path('api/websocket/info/', csrf_exempt(lambda request: monitoring_middleware.JsonResponse({
        'websocket_url': f'ws://{request.get_host()}:8765',
        'status': 'available',
        'protocols': ['event_streaming', 'real_time_alerts']
    })), name='websocket_info'),
]