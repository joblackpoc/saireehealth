"""
Phase 9: Compliance Dashboard & Data Governance Controls
Real-time compliance monitoring and comprehensive data governance

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Compliance Dashboard & Data Governance
"""

import os
import json
import uuid
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import asyncio
from collections import defaultdict, deque
import re
from pathlib import Path

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from django.db import models, transaction
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.admin.views.decorators import staff_member_required
from django.views import View

from .compliance_framework import (
    ComplianceFramework, ComplianceStatus, AuditLevel, 
    get_compliance_manager, ComplianceControl
)
from .policy_management import (
    PolicyType, PolicyStatus, WorkflowStatus,
    get_policy_manager, get_audit_system
)

# Dashboard Logger
dashboard_logger = logging.getLogger('compliance_dashboard')

class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"

class DataLifecycleStage(Enum):
    """Data lifecycle stages"""
    CREATION = "creation"
    STORAGE = "storage"
    PROCESSING = "processing"
    SHARING = "sharing"
    ARCHIVAL = "archival"
    DELETION = "deletion"

class GovernanceStatus(Enum):
    """Data governance status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNDER_REVIEW = "under_review"
    REMEDIATION_REQUIRED = "remediation_required"
    EXCEPTION_GRANTED = "exception_granted"

@dataclass
class DataAsset:
    """Data asset for governance tracking"""
    asset_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    classification: DataClassification = DataClassification.INTERNAL
    owner: str = ""
    steward: str = ""
    location: str = ""
    format: str = ""
    size_mb: float = 0.0
    record_count: int = 0
    created_date: datetime = field(default_factory=timezone.now)
    last_accessed: Optional[datetime] = None
    retention_period_days: int = 2555  # 7 years default
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    data_categories: List[str] = field(default_factory=list)
    access_controls: Dict[str, Any] = field(default_factory=dict)
    encryption_status: str = "encrypted"
    backup_status: str = "backed_up"
    governance_status: GovernanceStatus = GovernanceStatus.UNDER_REVIEW

@dataclass
class DataProcessingActivity:
    """GDPR Article 30 processing activity record"""
    activity_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    controller_name: str = ""
    controller_contact: str = ""
    dpo_contact: str = ""
    purposes: List[str] = field(default_factory=list)
    lawful_basis: List[str] = field(default_factory=list)
    categories_of_data_subjects: List[str] = field(default_factory=list)
    categories_of_personal_data: List[str] = field(default_factory=list)
    recipients: List[str] = field(default_factory=list)
    third_country_transfers: List[str] = field(default_factory=list)
    retention_schedule: str = ""
    technical_measures: List[str] = field(default_factory=list)
    organizational_measures: List[str] = field(default_factory=list)
    created_date: datetime = field(default_factory=timezone.now)
    last_reviewed: Optional[datetime] = None

@dataclass
class ComplianceAlert:
    """Compliance monitoring alert"""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str = ""
    severity: str = "medium"  # low, medium, high, critical
    title: str = ""
    description: str = ""
    framework: ComplianceFramework = ComplianceFramework.GDPR
    control_id: str = ""
    triggered_date: datetime = field(default_factory=timezone.now)
    status: str = "active"  # active, acknowledged, resolved, false_positive
    assigned_to: str = ""
    due_date: Optional[datetime] = None
    remediation_steps: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)

class ComplianceDashboardManager:
    """
    Comprehensive Compliance Dashboard Manager
    
    Provides real-time compliance monitoring, risk assessment,
    and executive reporting capabilities.
    """
    
    def __init__(self):
        self.alerts = {}
        self.risk_assessments = {}
        self.dashboard_cache = {}
        
        # Configuration
        self.config = getattr(settings, 'COMPLIANCE_DASHBOARD_CONFIG', {
            'REAL_TIME_UPDATES': True,
            'ALERT_THRESHOLDS': {
                'non_compliance_percentage': 10,
                'overdue_assessments': 5,
                'policy_violations_per_day': 10,
                'high_risk_events_per_hour': 3
            },
            'EXECUTIVE_DASHBOARD_ENABLED': True,
            'AUTOMATED_REPORTING': True,
            'RISK_SCORING_ENABLED': True,
            'TREND_ANALYSIS_ENABLED': True,
            'EXPORT_FORMATS': ['pdf', 'excel', 'json'],
        })
        
        # Dashboard metrics
        self.metrics = {
            'last_updated': None,
            'total_compliance_score': 0.0,
            'active_alerts': 0,
            'high_risk_alerts': 0,
            'overdue_assessments': 0,
            'policy_violations_24h': 0,
            'frameworks_monitored': 0,
            'data_assets_tracked': 0,
        }
        
        # Initialize dashboard components
        self._initialize_dashboard()
        
        dashboard_logger.info("Compliance Dashboard Manager initialized")
    
    def _initialize_dashboard(self):
        """Initialize dashboard components"""
        try:
            # Load existing alerts from cache
            self._load_cached_alerts()
            
            # Initialize risk scoring
            self._initialize_risk_scoring()
            
            # Start background monitoring if enabled
            if self.config.get('REAL_TIME_UPDATES', True):
                self._start_background_monitoring()
            
            dashboard_logger.info("Dashboard components initialized")
            
        except Exception as e:
            dashboard_logger.error(f"Failed to initialize dashboard: {str(e)}")
    
    def _load_cached_alerts(self):
        """Load alerts from cache"""
        try:
            cached_alerts = cache.get('compliance_alerts', {})
            self.alerts.update(cached_alerts)
            dashboard_logger.info(f"Loaded {len(cached_alerts)} cached alerts")
        except Exception as e:
            dashboard_logger.error(f"Failed to load cached alerts: {str(e)}")
    
    def _initialize_risk_scoring(self):
        """Initialize risk scoring algorithms"""
        try:
            # Risk scoring weights for different factors
            self.risk_weights = {
                'compliance_score': 0.3,
                'alert_severity': 0.25,
                'overdue_assessments': 0.2,
                'policy_violations': 0.15,
                'trend_analysis': 0.1
            }
            
            dashboard_logger.info("Risk scoring initialized")
            
        except Exception as e:
            dashboard_logger.error(f"Failed to initialize risk scoring: {str(e)}")
    
    def _start_background_monitoring(self):
        """Start background monitoring thread"""
        try:
            monitor_thread = threading.Thread(
                target=self._background_monitoring_loop,
                name="ComplianceMonitor",
                daemon=True
            )
            monitor_thread.start()
            dashboard_logger.info("Background monitoring started")
        except Exception as e:
            dashboard_logger.error(f"Failed to start background monitoring: {str(e)}")
    
    def _background_monitoring_loop(self):
        """Background monitoring loop"""
        while True:
            try:
                # Update dashboard metrics
                self._update_dashboard_metrics()
                
                # Check for new alerts
                self._check_compliance_alerts()
                
                # Update risk assessments
                self._update_risk_assessments()
                
                # Cache dashboard data
                self._cache_dashboard_data()
                
                # Sleep for update interval
                import time
                time.sleep(60)  # Update every minute
                
            except Exception as e:
                dashboard_logger.error(f"Background monitoring error: {str(e)}")
                import time
                time.sleep(60)
    
    def _update_dashboard_metrics(self):
        """Update real-time dashboard metrics"""
        try:
            compliance_manager = get_compliance_manager()
            policy_manager = get_policy_manager()
            
            # Get compliance scores for all frameworks
            total_score = 0
            framework_count = 0
            
            for framework in compliance_manager.frameworks.keys():
                assessment = compliance_manager.assess_compliance(framework)
                if 'compliance_score' in assessment:
                    total_score += assessment['compliance_score']
                    framework_count += 1
            
            # Update metrics
            self.metrics.update({
                'last_updated': timezone.now().isoformat(),
                'total_compliance_score': total_score / framework_count if framework_count > 0 else 0,
                'active_alerts': len([a for a in self.alerts.values() if a.status == 'active']),
                'high_risk_alerts': len([a for a in self.alerts.values() 
                                       if a.severity in ['high', 'critical'] and a.status == 'active']),
                'frameworks_monitored': framework_count,
                'policy_violations_24h': self._get_violations_24h(),
                'overdue_assessments': self._get_overdue_assessments_count()
            })
            
        except Exception as e:
            dashboard_logger.error(f"Failed to update dashboard metrics: {str(e)}")
    
    def _get_violations_24h(self) -> int:
        """Get policy violations in last 24 hours"""
        try:
            # This would query actual audit logs
            # For now, return from cache
            return cache.get('policy_violations_24h', 0)
        except Exception as e:
            dashboard_logger.error(f"Failed to get violations count: {str(e)}")
            return 0
    
    def _get_overdue_assessments_count(self) -> int:
        """Get count of overdue compliance assessments"""
        try:
            compliance_manager = get_compliance_manager()
            overdue_count = 0
            
            for controls in compliance_manager.frameworks.values():
                for control in controls:
                    if (control.next_assessment and 
                        control.next_assessment < timezone.now()):
                        overdue_count += 1
            
            return overdue_count
            
        except Exception as e:
            dashboard_logger.error(f"Failed to get overdue assessments: {str(e)}")
            return 0
    
    def _check_compliance_alerts(self):
        """Check for new compliance alerts"""
        try:
            # Check compliance score thresholds
            threshold = self.config['ALERT_THRESHOLDS'].get('non_compliance_percentage', 10)
            if 100 - self.metrics['total_compliance_score'] > threshold:
                self._create_alert(
                    alert_type="compliance_score_low",
                    severity="high",
                    title="Low Compliance Score",
                    description=f"Overall compliance score below threshold: {self.metrics['total_compliance_score']:.1f}%"
                )
            
            # Check overdue assessments
            overdue_threshold = self.config['ALERT_THRESHOLDS'].get('overdue_assessments', 5)
            if self.metrics['overdue_assessments'] > overdue_threshold:
                self._create_alert(
                    alert_type="overdue_assessments",
                    severity="medium",
                    title="Overdue Compliance Assessments",
                    description=f"{self.metrics['overdue_assessments']} assessments are overdue"
                )
            
            # Check policy violations
            violations_threshold = self.config['ALERT_THRESHOLDS'].get('policy_violations_per_day', 10)
            if self.metrics['policy_violations_24h'] > violations_threshold:
                self._create_alert(
                    alert_type="high_policy_violations",
                    severity="high",
                    title="High Policy Violation Rate",
                    description=f"{self.metrics['policy_violations_24h']} violations in last 24 hours"
                )
            
        except Exception as e:
            dashboard_logger.error(f"Failed to check compliance alerts: {str(e)}")
    
    def _create_alert(self, alert_type: str, severity: str, title: str, 
                     description: str, framework: ComplianceFramework = ComplianceFramework.GDPR):
        """Create new compliance alert"""
        try:
            # Check if similar alert already exists
            existing_alert = None
            for alert in self.alerts.values():
                if (alert.alert_type == alert_type and 
                    alert.status == 'active' and
                    alert.framework == framework):
                    existing_alert = alert
                    break
            
            if existing_alert:
                # Update existing alert
                existing_alert.description = description
                existing_alert.triggered_date = timezone.now()
            else:
                # Create new alert
                alert = ComplianceAlert(
                    alert_type=alert_type,
                    severity=severity,
                    title=title,
                    description=description,
                    framework=framework
                )
                
                # Set due date based on severity
                if severity == 'critical':
                    alert.due_date = timezone.now() + timedelta(hours=4)
                elif severity == 'high':
                    alert.due_date = timezone.now() + timedelta(hours=24)
                elif severity == 'medium':
                    alert.due_date = timezone.now() + timedelta(days=3)
                else:
                    alert.due_date = timezone.now() + timedelta(days=7)
                
                self.alerts[alert.alert_id] = alert
                
                dashboard_logger.warning(f"Compliance alert created: {alert.alert_id} - {title}")
        
        except Exception as e:
            dashboard_logger.error(f"Failed to create alert: {str(e)}")
    
    def _update_risk_assessments(self):
        """Update risk assessments for frameworks"""
        try:
            compliance_manager = get_compliance_manager()
            
            for framework in compliance_manager.frameworks.keys():
                risk_score = self._calculate_framework_risk(framework)
                
                self.risk_assessments[framework.value] = {
                    'framework': framework.value,
                    'risk_score': risk_score,
                    'risk_level': self._get_risk_level(risk_score),
                    'last_calculated': timezone.now().isoformat(),
                    'contributing_factors': self._get_risk_factors(framework)
                }
            
        except Exception as e:
            dashboard_logger.error(f"Failed to update risk assessments: {str(e)}")
    
    def _calculate_framework_risk(self, framework: ComplianceFramework) -> float:
        """Calculate risk score for framework"""
        try:
            compliance_manager = get_compliance_manager()
            assessment = compliance_manager.assess_compliance(framework)
            
            # Base risk from compliance score (inverted)
            compliance_score = assessment.get('compliance_score', 0)
            compliance_risk = (100 - compliance_score) / 100 * self.risk_weights['compliance_score']
            
            # Risk from active alerts
            framework_alerts = [a for a in self.alerts.values() 
                              if a.framework == framework and a.status == 'active']
            alert_risk = 0
            for alert in framework_alerts:
                if alert.severity == 'critical':
                    alert_risk += 0.8
                elif alert.severity == 'high':
                    alert_risk += 0.6
                elif alert.severity == 'medium':
                    alert_risk += 0.4
                else:
                    alert_risk += 0.2
            
            alert_risk = min(alert_risk, 1.0) * self.risk_weights['alert_severity']
            
            # Risk from overdue assessments
            overdue_risk = min(self.metrics['overdue_assessments'] / 10, 1.0) * self.risk_weights['overdue_assessments']
            
            # Risk from policy violations
            violation_risk = min(self.metrics['policy_violations_24h'] / 20, 1.0) * self.risk_weights['policy_violations']
            
            # Total risk score (0-1 scale)
            total_risk = compliance_risk + alert_risk + overdue_risk + violation_risk
            
            return min(total_risk, 1.0)
            
        except Exception as e:
            dashboard_logger.error(f"Failed to calculate framework risk: {str(e)}")
            return 0.5  # Medium risk as fallback
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "minimal"
    
    def _get_risk_factors(self, framework: ComplianceFramework) -> List[str]:
        """Get contributing risk factors for framework"""
        factors = []
        
        compliance_manager = get_compliance_manager()
        assessment = compliance_manager.assess_compliance(framework)
        
        if assessment.get('compliance_score', 0) < 80:
            factors.append("Low compliance score")
        
        if assessment.get('non_compliant_controls', 0) > 5:
            factors.append("Multiple non-compliant controls")
        
        framework_alerts = [a for a in self.alerts.values() 
                          if a.framework == framework and a.status == 'active']
        if len(framework_alerts) > 3:
            factors.append("Multiple active alerts")
        
        if any(a.severity in ['critical', 'high'] for a in framework_alerts):
            factors.append("High severity alerts")
        
        return factors
    
    def _cache_dashboard_data(self):
        """Cache dashboard data for performance"""
        try:
            dashboard_data = {
                'metrics': self.metrics,
                'alerts': {aid: asdict(alert) for aid, alert in self.alerts.items()},
                'risk_assessments': self.risk_assessments,
                'timestamp': timezone.now().isoformat()
            }
            
            cache.set('compliance_dashboard_data', dashboard_data, 300)  # 5 minutes
            cache.set('compliance_alerts', self.alerts, 86400)  # 24 hours
            
        except Exception as e:
            dashboard_logger.error(f"Failed to cache dashboard data: {str(e)}")
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive dashboard data"""
        try:
            # Check cache first
            cached_data = cache.get('compliance_dashboard_data')
            if cached_data:
                cache_age = (timezone.now() - datetime.fromisoformat(cached_data['timestamp'])).seconds
                if cache_age < 60:  # Use cache if less than 1 minute old
                    return cached_data
            
            # Generate fresh dashboard data
            compliance_manager = get_compliance_manager()
            policy_manager = get_policy_manager()
            
            dashboard_data = {
                'overview': {
                    'total_compliance_score': self.metrics['total_compliance_score'],
                    'frameworks_monitored': self.metrics['frameworks_monitored'],
                    'active_alerts': self.metrics['active_alerts'],
                    'high_risk_alerts': self.metrics['high_risk_alerts'],
                    'overdue_assessments': self.metrics['overdue_assessments'],
                    'last_updated': self.metrics['last_updated']
                },
                'framework_status': {},
                'alerts': [asdict(alert) for alert in self.alerts.values() if alert.status == 'active'],
                'risk_assessments': self.risk_assessments,
                'policy_status': policy_manager.get_policy_metrics(),
                'recent_audit_events': [],
                'compliance_trends': self._get_compliance_trends(),
                'recommendations': self._get_dashboard_recommendations()
            }
            
            # Get framework status
            for framework in compliance_manager.frameworks.keys():
                assessment = compliance_manager.assess_compliance(framework)
                dashboard_data['framework_status'][framework.value] = assessment
            
            # Get recent audit events
            audit_system = get_audit_system()
            recent_events = audit_system.search_audit_events({
                'start_date': timezone.now() - timedelta(hours=24),
                'limit': 20
            })
            dashboard_data['recent_audit_events'] = recent_events
            
            return dashboard_data
            
        except Exception as e:
            dashboard_logger.error(f"Failed to get dashboard data: {str(e)}")
            return {'error': str(e)}
    
    def _get_compliance_trends(self) -> Dict[str, Any]:
        """Get compliance trends over time"""
        # This would analyze historical compliance data
        # For now, return mock trending data
        return {
            'period_days': 30,
            'overall_trend': 'stable',
            'score_change': 2.3,
            'framework_trends': {
                'gdpr': {'score': 85.2, 'trend': 'improving', 'change': 3.1},
                'hipaa': {'score': 92.1, 'trend': 'stable', 'change': 0.8},
                'soc2': {'score': 88.7, 'trend': 'improving', 'change': 4.2},
                'iso27001': {'score': 90.3, 'trend': 'stable', 'change': -0.5}
            },
            'alert_trends': {
                'total_alerts': 15,
                'new_alerts': 3,
                'resolved_alerts': 8,
                'trend': 'improving'
            }
        }
    
    def _get_dashboard_recommendations(self) -> List[str]:
        """Get dashboard recommendations based on current status"""
        recommendations = []
        
        # Check compliance scores
        if self.metrics['total_compliance_score'] < 85:
            recommendations.append("Focus on improving compliance controls with scores below 85%")
        
        # Check alerts
        if self.metrics['high_risk_alerts'] > 0:
            recommendations.append(f"Address {self.metrics['high_risk_alerts']} high-risk compliance alerts")
        
        # Check overdue assessments
        if self.metrics['overdue_assessments'] > 0:
            recommendations.append(f"Complete {self.metrics['overdue_assessments']} overdue compliance assessments")
        
        # Check policy violations
        if self.metrics['policy_violations_24h'] > 5:
            recommendations.append("Investigate recent increase in policy violations")
        
        # Framework-specific recommendations
        for framework_name, assessment in self.risk_assessments.items():
            if assessment['risk_level'] in ['high', 'critical']:
                recommendations.append(f"Prioritize risk reduction for {framework_name.upper()} framework")
        
        return recommendations[:5]  # Return top 5 recommendations


class DataGovernanceController:
    """
    Data Governance Controller
    
    Manages data assets, processing activities, and governance controls
    to ensure compliance with data protection regulations.
    """
    
    def __init__(self):
        self.data_assets = {}
        self.processing_activities = {}
        self.governance_rules = {}
        
        # Configuration
        self.config = getattr(settings, 'DATA_GOVERNANCE_CONFIG', {
            'AUTO_CLASSIFICATION_ENABLED': True,
            'DATA_DISCOVERY_ENABLED': True,
            'RETENTION_ENFORCEMENT': True,
            'ACCESS_MONITORING': True,
            'DATA_LINEAGE_TRACKING': True,
            'PRIVACY_BY_DESIGN': True,
            'DATA_MINIMIZATION': True,
            'CONSENT_MANAGEMENT': True,
        })
        
        # Governance metrics
        self.metrics = {
            'total_data_assets': 0,
            'classified_assets': 0,
            'compliant_assets': 0,
            'processing_activities': 0,
            'active_consents': 0,
            'data_subject_requests': 0,
            'retention_violations': 0,
        }
        
        # Initialize governance framework
        self._initialize_governance_framework()
        
        dashboard_logger.info("Data Governance Controller initialized")
    
    def _initialize_governance_framework(self):
        """Initialize data governance framework"""
        try:
            # Initialize data classification rules
            self._initialize_classification_rules()
            
            # Initialize retention policies
            self._initialize_retention_policies()
            
            # Initialize processing activities templates
            self._initialize_processing_templates()
            
            dashboard_logger.info("Data governance framework initialized")
            
        except Exception as e:
            dashboard_logger.error(f"Failed to initialize governance framework: {str(e)}")
    
    def _initialize_classification_rules(self):
        """Initialize automatic data classification rules"""
        self.classification_rules = {
            'patterns': {
                'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
                'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            },
            'keywords': {
                DataClassification.RESTRICTED: [
                    'password', 'secret', 'private_key', 'token', 'api_key',
                    'medical_record', 'health_data', 'diagnosis', 'treatment'
                ],
                DataClassification.CONFIDENTIAL: [
                    'personal', 'pii', 'customer_data', 'financial', 'salary',
                    'employee_id', 'social_security', 'tax_id'
                ],
                DataClassification.INTERNAL: [
                    'internal', 'company', 'employee', 'department', 'project'
                ]
            }
        }
    
    def _initialize_retention_policies(self):
        """Initialize data retention policies"""
        self.retention_policies = {
            DataClassification.PUBLIC: 365,  # 1 year
            DataClassification.INTERNAL: 1095,  # 3 years  
            DataClassification.CONFIDENTIAL: 2190,  # 6 years
            DataClassification.RESTRICTED: 2555,  # 7 years
            DataClassification.TOP_SECRET: 3650,  # 10 years
        }
    
    def _initialize_processing_templates(self):
        """Initialize GDPR processing activity templates"""
        self.processing_templates = {
            'customer_management': {
                'name': 'Customer Data Management',
                'purposes': ['Customer relationship management', 'Service delivery', 'Support'],
                'lawful_basis': ['Contract performance', 'Legitimate interest'],
                'categories_of_data_subjects': ['Customers', 'Prospects'],
                'categories_of_personal_data': ['Contact details', 'Transaction history', 'Preferences'],
                'retention_schedule': '7 years after contract termination',
                'technical_measures': ['Encryption', 'Access controls', 'Audit logging'],
                'organizational_measures': ['Staff training', 'Data protection policies', 'Regular reviews']
            },
            'employee_management': {
                'name': 'Employee Data Management',
                'purposes': ['HR management', 'Payroll', 'Performance management'],
                'lawful_basis': ['Contract performance', 'Legal obligation'],
                'categories_of_data_subjects': ['Employees', 'Job applicants'],
                'categories_of_personal_data': ['Personal details', 'Employment history', 'Performance data'],
                'retention_schedule': '7 years after employment termination',
                'technical_measures': ['Encryption', 'Role-based access', 'Secure transmission'],
                'organizational_measures': ['HR policies', 'Confidentiality agreements', 'Access reviews']
            }
        }
    
    def register_data_asset(self, name: str, location: str, 
                          classification: Optional[DataClassification] = None,
                          owner: str = "", steward: str = "",
                          data_categories: List[str] = None) -> str:
        """Register new data asset"""
        try:
            asset = DataAsset(
                name=name,
                location=location,
                owner=owner,
                steward=steward,
                data_categories=data_categories or []
            )
            
            # Auto-classify if not provided
            if classification is None:
                asset.classification = self._auto_classify_data(name, data_categories or [])
            else:
                asset.classification = classification
            
            # Set retention period based on classification
            asset.retention_period_days = self.retention_policies.get(
                asset.classification, 2555
            )
            
            # Determine applicable compliance frameworks
            asset.compliance_frameworks = self._determine_applicable_frameworks(asset)
            
            # Store asset
            self.data_assets[asset.asset_id] = asset
            
            # Update metrics
            self.metrics['total_data_assets'] += 1
            self.metrics['classified_assets'] += 1
            
            dashboard_logger.info(f"Data asset registered: {asset.asset_id} - {name}")
            
            # Record governance event
            self._record_governance_event(
                event_type="data_asset_registered",
                asset_id=asset.asset_id,
                details={
                    'name': name,
                    'classification': asset.classification.value,
                    'location': location
                }
            )
            
            return asset.asset_id
            
        except Exception as e:
            dashboard_logger.error(f"Failed to register data asset: {str(e)}")
            return ""
    
    def _auto_classify_data(self, name: str, categories: List[str]) -> DataClassification:
        """Automatically classify data based on name and categories"""
        try:
            name_lower = name.lower()
            categories_lower = [c.lower() for c in categories]
            
            # Check for restricted classification keywords
            for keyword in self.classification_rules['keywords'][DataClassification.RESTRICTED]:
                if keyword in name_lower or any(keyword in cat for cat in categories_lower):
                    return DataClassification.RESTRICTED
            
            # Check for confidential classification keywords
            for keyword in self.classification_rules['keywords'][DataClassification.CONFIDENTIAL]:
                if keyword in name_lower or any(keyword in cat for cat in categories_lower):
                    return DataClassification.CONFIDENTIAL
            
            # Check for internal classification keywords
            for keyword in self.classification_rules['keywords'][DataClassification.INTERNAL]:
                if keyword in name_lower or any(keyword in cat for cat in categories_lower):
                    return DataClassification.INTERNAL
            
            # Default to internal
            return DataClassification.INTERNAL
            
        except Exception as e:
            dashboard_logger.error(f"Auto-classification failed: {str(e)}")
            return DataClassification.INTERNAL
    
    def _determine_applicable_frameworks(self, asset: DataAsset) -> List[ComplianceFramework]:
        """Determine applicable compliance frameworks for data asset"""
        frameworks = []
        
        # GDPR for personal data
        personal_indicators = ['personal', 'customer', 'employee', 'user', 'contact']
        if any(indicator in asset.name.lower() for indicator in personal_indicators):
            frameworks.append(ComplianceFramework.GDPR)
        
        # HIPAA for health data
        health_indicators = ['health', 'medical', 'patient', 'diagnosis', 'treatment']
        if any(indicator in asset.name.lower() for indicator in health_indicators):
            frameworks.append(ComplianceFramework.HIPAA)
        
        # PCI DSS for payment data
        payment_indicators = ['payment', 'card', 'transaction', 'financial']
        if any(indicator in asset.name.lower() for indicator in payment_indicators):
            frameworks.append(ComplianceFramework.PCI_DSS)
        
        # SOC 2 for system data
        if asset.classification in [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED]:
            frameworks.append(ComplianceFramework.SOC2)
        
        return frameworks
    
    def create_processing_activity(self, template_id: Optional[str] = None,
                                 custom_data: Dict[str, Any] = None) -> str:
        """Create GDPR Article 30 processing activity record"""
        try:
            activity = DataProcessingActivity()
            
            # Use template if specified
            if template_id and template_id in self.processing_templates:
                template = self.processing_templates[template_id]
                activity.name = template['name']
                activity.purposes = template['purposes']
                activity.lawful_basis = template['lawful_basis']
                activity.categories_of_data_subjects = template['categories_of_data_subjects']
                activity.categories_of_personal_data = template['categories_of_personal_data']
                activity.retention_schedule = template['retention_schedule']
                activity.technical_measures = template['technical_measures']
                activity.organizational_measures = template['organizational_measures']
            
            # Apply custom data
            if custom_data:
                for key, value in custom_data.items():
                    if hasattr(activity, key):
                        setattr(activity, key, value)
            
            # Store activity
            self.processing_activities[activity.activity_id] = activity
            
            # Update metrics
            self.metrics['processing_activities'] += 1
            
            dashboard_logger.info(f"Processing activity created: {activity.activity_id}")
            
            # Record governance event
            self._record_governance_event(
                event_type="processing_activity_created",
                activity_id=activity.activity_id,
                details={
                    'name': activity.name,
                    'template_used': template_id
                }
            )
            
            return activity.activity_id
            
        except Exception as e:
            dashboard_logger.error(f"Failed to create processing activity: {str(e)}")
            return ""
    
    def assess_data_governance_compliance(self) -> Dict[str, Any]:
        """Assess data governance compliance status"""
        try:
            assessment = {
                'assessment_date': timezone.now().isoformat(),
                'overall_score': 0.0,
                'asset_compliance': {
                    'total_assets': len(self.data_assets),
                    'compliant_assets': 0,
                    'non_compliant_assets': 0,
                    'classification_coverage': 0.0
                },
                'processing_compliance': {
                    'total_activities': len(self.processing_activities),
                    'documented_activities': 0,
                    'reviewed_activities': 0
                },
                'governance_gaps': [],
                'recommendations': []
            }
            
            # Assess data asset compliance
            compliant_assets = 0
            classified_assets = 0
            
            for asset in self.data_assets.values():
                if asset.classification != DataClassification.INTERNAL:  # Has been classified
                    classified_assets += 1
                
                # Check compliance criteria
                asset_compliant = True
                
                # Check if asset has owner
                if not asset.owner:
                    asset_compliant = False
                
                # Check if asset has appropriate controls
                if asset.classification in [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED]:
                    if not asset.access_controls:
                        asset_compliant = False
                
                # Check encryption for sensitive data
                if (asset.classification in [DataClassification.RESTRICTED] and 
                    asset.encryption_status != 'encrypted'):
                    asset_compliant = False
                
                if asset_compliant:
                    compliant_assets += 1
                    asset.governance_status = GovernanceStatus.COMPLIANT
                else:
                    asset.governance_status = GovernanceStatus.NON_COMPLIANT
            
            assessment['asset_compliance']['compliant_assets'] = compliant_assets
            assessment['asset_compliance']['non_compliant_assets'] = len(self.data_assets) - compliant_assets
            
            if len(self.data_assets) > 0:
                assessment['asset_compliance']['classification_coverage'] = classified_assets / len(self.data_assets) * 100
            
            # Assess processing activity compliance
            documented_activities = 0
            reviewed_activities = 0
            
            for activity in self.processing_activities.values():
                if activity.name and activity.purposes and activity.lawful_basis:
                    documented_activities += 1
                
                if activity.last_reviewed and activity.last_reviewed > timezone.now() - timedelta(days=365):
                    reviewed_activities += 1
            
            assessment['processing_compliance']['documented_activities'] = documented_activities
            assessment['processing_compliance']['reviewed_activities'] = reviewed_activities
            
            # Calculate overall score
            if len(self.data_assets) > 0 and len(self.processing_activities) > 0:
                asset_score = (compliant_assets / len(self.data_assets)) * 50
                processing_score = (documented_activities / len(self.processing_activities)) * 30
                classification_score = (classified_assets / len(self.data_assets)) * 20
                assessment['overall_score'] = asset_score + processing_score + classification_score
            
            # Identify governance gaps
            if assessment['asset_compliance']['classification_coverage'] < 90:
                assessment['governance_gaps'].append("Incomplete data asset classification")
            
            if compliant_assets / len(self.data_assets) < 0.8:
                assessment['governance_gaps'].append("Low data asset compliance rate")
            
            if documented_activities / len(self.processing_activities) < 0.9:
                assessment['governance_gaps'].append("Incomplete processing activity documentation")
            
            # Generate recommendations
            assessment['recommendations'] = self._generate_governance_recommendations(assessment)
            
            return assessment
            
        except Exception as e:
            dashboard_logger.error(f"Failed to assess data governance compliance: {str(e)}")
            return {'error': str(e)}
    
    def _generate_governance_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """Generate data governance recommendations"""
        recommendations = []
        
        # Asset-related recommendations
        if assessment['asset_compliance']['classification_coverage'] < 90:
            recommendations.append("Complete classification for all data assets")
        
        non_compliant_ratio = assessment['asset_compliance']['non_compliant_assets'] / assessment['asset_compliance']['total_assets']
        if non_compliant_ratio > 0.2:
            recommendations.append("Address compliance issues for data assets")
        
        # Processing activity recommendations
        if assessment['processing_compliance']['documented_activities'] < assessment['processing_compliance']['total_activities']:
            recommendations.append("Complete documentation for all processing activities")
        
        if assessment['processing_compliance']['reviewed_activities'] < assessment['processing_compliance']['total_activities']:
            recommendations.append("Conduct annual reviews of processing activities")
        
        # Overall score recommendations
        if assessment['overall_score'] < 80:
            recommendations.append("Implement comprehensive data governance improvements")
        
        return recommendations
    
    def _record_governance_event(self, event_type: str, asset_id: str = "", 
                               activity_id: str = "", details: Dict[str, Any] = None):
        """Record data governance audit event"""
        try:
            audit_system = get_audit_system()
            
            enhanced_details = details or {}
            enhanced_details.update({
                'governance_event': True,
                'asset_id': asset_id,
                'activity_id': activity_id
            })
            
            audit_system.create_enhanced_audit_event(
                event_type=event_type,
                resource_type="data_governance",
                action="governance_action",
                details=enhanced_details,
                data_classification="internal",
                business_context="Data governance and compliance"
            )
            
        except Exception as e:
            dashboard_logger.error(f"Failed to record governance event: {str(e)}")
    
    def get_governance_metrics(self) -> Dict[str, Any]:
        """Get data governance metrics"""
        try:
            # Update metrics
            self.metrics['total_data_assets'] = len(self.data_assets)
            self.metrics['processing_activities'] = len(self.processing_activities)
            
            classified_count = sum(1 for asset in self.data_assets.values() 
                                 if asset.classification != DataClassification.INTERNAL)
            self.metrics['classified_assets'] = classified_count
            
            compliant_count = sum(1 for asset in self.data_assets.values() 
                                if asset.governance_status == GovernanceStatus.COMPLIANT)
            self.metrics['compliant_assets'] = compliant_count
            
            return self.metrics.copy()
            
        except Exception as e:
            dashboard_logger.error(f"Failed to get governance metrics: {str(e)}")
            return {'error': str(e)}


# API Views for Compliance Dashboard

@csrf_exempt
@staff_member_required
def compliance_dashboard_api(request):
    """API endpoint for compliance dashboard data"""
    if request.method == 'GET':
        try:
            dashboard_manager = ComplianceDashboardManager()
            dashboard_data = dashboard_manager.get_dashboard_data()
            return JsonResponse(dashboard_data)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@staff_member_required
def compliance_alerts_api(request):
    """API endpoint for compliance alerts"""
    if request.method == 'GET':
        try:
            dashboard_manager = ComplianceDashboardManager()
            
            # Filter parameters
            severity = request.GET.get('severity')
            status = request.GET.get('status', 'active')
            framework = request.GET.get('framework')
            
            alerts = []
            for alert in dashboard_manager.alerts.values():
                if status and alert.status != status:
                    continue
                if severity and alert.severity != severity:
                    continue
                if framework and alert.framework.value != framework:
                    continue
                
                alerts.append(asdict(alert))
            
            return JsonResponse({'alerts': alerts})
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@staff_member_required  
def data_governance_api(request):
    """API endpoint for data governance"""
    if request.method == 'GET':
        try:
            governance_controller = DataGovernanceController()
            
            # Get governance assessment
            assessment = governance_controller.assess_data_governance_compliance()
            
            # Get governance metrics
            metrics = governance_controller.get_governance_metrics()
            
            return JsonResponse({
                'assessment': assessment,
                'metrics': metrics,
                'timestamp': timezone.now().isoformat()
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            
            governance_controller = DataGovernanceController()
            
            if action == 'register_asset':
                asset_id = governance_controller.register_data_asset(
                    name=data.get('name', ''),
                    location=data.get('location', ''),
                    owner=data.get('owner', ''),
                    data_categories=data.get('categories', [])
                )
                return JsonResponse({'asset_id': asset_id})
            
            elif action == 'create_processing_activity':
                activity_id = governance_controller.create_processing_activity(
                    template_id=data.get('template_id'),
                    custom_data=data.get('custom_data', {})
                )
                return JsonResponse({'activity_id': activity_id})
            
            else:
                return JsonResponse({'error': 'Unknown action'}, status=400)
                
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

# Global instances
_global_dashboard_manager = None
_global_governance_controller = None

def get_dashboard_manager() -> ComplianceDashboardManager:
    """Get global dashboard manager instance"""
    global _global_dashboard_manager
    if _global_dashboard_manager is None:
        _global_dashboard_manager = ComplianceDashboardManager()
    return _global_dashboard_manager

def get_governance_controller() -> DataGovernanceController:
    """Get global data governance controller instance"""
    global _global_governance_controller
    if _global_governance_controller is None:
        _global_governance_controller = DataGovernanceController()
    return _global_governance_controller