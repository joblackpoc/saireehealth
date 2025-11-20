"""
Security Enhancements URL Configuration
Phase 7: Advanced Security Monitoring & Intelligence

This module provides URL routing for all security enhancement endpoints
including the advanced security intelligence dashboard and APIs.

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
"""

from django.urls import path, include
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache

from .security_dashboard_api import SecurityDashboardAPI

app_name = 'security_enhancements'

# ============================================================================
# Phase 7: Security Intelligence API URLs
# ============================================================================

# Security dashboard API endpoints (requires authentication and staff privileges)
security_api_patterns = [
    # Real-time security overview
    path('overview/', 
         staff_member_required(SecurityDashboardAPI.get_security_overview), 
         name='security_overview'),
    
    # Threat timeline and analysis
    path('timeline/', 
         staff_member_required(SecurityDashboardAPI.get_threat_timeline), 
         name='threat_timeline'),
    
    # Top threats analysis
    path('threats/', 
         staff_member_required(SecurityDashboardAPI.get_top_threats), 
         name='top_threats'),
    
    # Security incidents management
    path('incidents/<str:incident_id>/', 
         staff_member_required(SecurityDashboardAPI.get_incident_details), 
         name='incident_details'),
    
    # Security metrics
    path('metrics/', 
         staff_member_required(SecurityDashboardAPI.get_security_metrics), 
         name='security_metrics'),
]

# ============================================================================
# Security Management URLs
# ============================================================================

# Security management endpoints for current and future phases
security_management_patterns = [
    # Phase 8: Advanced Monitoring and Response
    path('monitoring/', include('security_enhancements.monitoring_urls')),
    
    # Phase 9: Compliance and Governance (Future)
    # path('compliance/', include('security_enhancements.compliance.urls')),
    
    # Phase 10: Advanced Security Operations Center (SOC) (Future)
    # path('soc/', include('security_enhancements.soc.urls')),
]

# ============================================================================
# Main URL Patterns
# ============================================================================

urlpatterns = [
    # Phase 7: Security Intelligence Dashboard (HTML view)
    path('dashboard/', SecurityDashboardAPI.realtime_dashboard_view, name='realtime_dashboard'),
    
    # Phase 7: Security Intelligence API
    path('api/', include((security_api_patterns, 'security_api'))),
    
    # Security Management (Future Phases)
    path('management/', include((security_management_patterns, 'security_management'))),
    
    # Health check endpoint (public)
    path('health/', SecurityDashboardAPI.health_check, name='health_check'),
]

# ============================================================================
# API Documentation and Development URLs
# ============================================================================

if hasattr(SecurityDashboardAPI, 'get_api_documentation'):
    urlpatterns.extend([
        path('api/docs/', 
             staff_member_required(SecurityDashboardAPI.get_api_documentation), 
             name='api_documentation'),
        
        path('api/schema/', 
             staff_member_required(SecurityDashboardAPI.get_api_schema), 
             name='api_schema'),
    ])

# ============================================================================
# Security Headers for API Endpoints
# ============================================================================

# All security API endpoints should include additional security headers
# This is handled by the SecurityHeadersMiddleware and SecurityDashboardAPI
# but can be enhanced here for specific endpoints if needed