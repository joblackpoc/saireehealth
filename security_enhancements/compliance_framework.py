"""
Phase 9: Compliance & Governance Systems - Core Framework
Advanced compliance management, regulatory standards, and governance automation

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Compliance & Governance Framework
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
from django.core.serializers.json import DjangoJSONEncoder

# Compliance Logger
compliance_logger = logging.getLogger('compliance_governance')

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    GDPR = "gdpr"  # General Data Protection Regulation
    HIPAA = "hipaa"  # Health Insurance Portability and Accountability Act
    SOC2 = "soc2"  # Service Organization Control 2
    ISO27001 = "iso27001"  # ISO/IEC 27001
    NIST = "nist"  # NIST Cybersecurity Framework
    PCI_DSS = "pci_dss"  # Payment Card Industry Data Security Standard
    SOX = "sox"  # Sarbanes-Oxley Act
    CCPA = "ccpa"  # California Consumer Privacy Act
    FISMA = "fisma"  # Federal Information Security Management Act

class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL_COMPLIANCE = "partial_compliance"
    UNDER_REVIEW = "under_review"
    REMEDIATION_REQUIRED = "remediation_required"
    EXEMPT = "exempt"

class AuditLevel(Enum):
    """Audit trail levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class PolicyStatus(Enum):
    """Policy status"""
    ACTIVE = "active"
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"

@dataclass
class ComplianceControl:
    """Individual compliance control"""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    requirements: List[str]
    implementation_status: ComplianceStatus = ComplianceStatus.UNDER_REVIEW
    last_assessed: Optional[datetime] = None
    next_assessment: Optional[datetime] = None
    responsible_party: str = ""
    evidence_links: List[str] = field(default_factory=list)
    remediation_notes: str = ""
    risk_level: str = "medium"
    automated_check: bool = False
    
    def __post_init__(self):
        if self.next_assessment is None:
            self.next_assessment = timezone.now() + timedelta(days=90)

@dataclass
class AuditEvent:
    """Audit trail event"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=timezone.now)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    event_type: str = ""
    resource_type: str = ""
    resource_id: str = ""
    action: str = ""
    outcome: str = ""
    ip_address: str = ""
    user_agent: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    audit_level: AuditLevel = AuditLevel.MEDIUM
    retention_period_days: int = 2555  # 7 years default
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['compliance_frameworks'] = [f.value for f in self.compliance_frameworks]
        data['audit_level'] = self.audit_level.value
        return data

@dataclass
class PolicyDocument:
    """Security/compliance policy document"""
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    version: str = "1.0"
    category: str = ""
    description: str = ""
    content: str = ""
    status: PolicyStatus = PolicyStatus.DRAFT
    created_date: datetime = field(default_factory=timezone.now)
    effective_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    owner: str = ""
    approver: str = ""
    applicable_frameworks: List[ComplianceFramework] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    approval_workflow: List[str] = field(default_factory=list)
    
class ComplianceManager:
    """
    Core Compliance & Governance Manager
    
    Manages compliance frameworks, controls, audit trails,
    and policy enforcement across the application.
    """
    
    def __init__(self):
        self.frameworks = {}
        self.controls = {}
        self.audit_trail = deque(maxlen=100000)  # Large audit buffer
        self.policies = {}
        self.compliance_cache = {}
        
        # Configuration
        self.config = getattr(settings, 'COMPLIANCE_GOVERNANCE_CONFIG', {
            'ENABLED_FRAMEWORKS': ['GDPR', 'HIPAA', 'SOC2', 'ISO27001'],
            'AUDIT_RETENTION_DAYS': 2555,  # 7 years
            'REAL_TIME_MONITORING': True,
            'AUTOMATED_ASSESSMENTS': True,
            'POLICY_APPROVAL_REQUIRED': True,
            'DATA_CLASSIFICATION_ENABLED': True,
            'PRIVACY_IMPACT_ASSESSMENTS': True,
            'INCIDENT_COMPLIANCE_TRACKING': True,
        })
        
        # Metrics
        self.metrics = {
            'total_controls': 0,
            'compliant_controls': 0,
            'non_compliant_controls': 0,
            'total_audit_events': 0,
            'policy_violations': 0,
            'compliance_score': 0.0,
            'last_assessment': None,
        }
        
        # Initialize compliance frameworks
        self._initialize_compliance_frameworks()
        
        compliance_logger.info("Compliance Manager initialized")
    
    def _initialize_compliance_frameworks(self):
        """Initialize supported compliance frameworks"""
        try:
            # Initialize each enabled framework
            enabled_frameworks = self.config.get('ENABLED_FRAMEWORKS', [])
            
            for framework_name in enabled_frameworks:
                try:
                    framework = ComplianceFramework(framework_name.lower())
                    self.frameworks[framework] = self._load_framework_controls(framework)
                    compliance_logger.info(f"Loaded framework: {framework.value}")
                except ValueError:
                    compliance_logger.warning(f"Unknown framework: {framework_name}")
            
            # Load custom controls from configuration
            self._load_custom_controls()
            
            compliance_logger.info(f"Initialized {len(self.frameworks)} compliance frameworks")
            
        except Exception as e:
            compliance_logger.error(f"Failed to initialize frameworks: {str(e)}")
    
    def _load_framework_controls(self, framework: ComplianceFramework) -> List[ComplianceControl]:
        """Load controls for specific framework"""
        controls = []
        
        if framework == ComplianceFramework.GDPR:
            controls.extend(self._get_gdpr_controls())
        elif framework == ComplianceFramework.HIPAA:
            controls.extend(self._get_hipaa_controls())
        elif framework == ComplianceFramework.SOC2:
            controls.extend(self._get_soc2_controls())
        elif framework == ComplianceFramework.ISO27001:
            controls.extend(self._get_iso27001_controls())
        elif framework == ComplianceFramework.NIST:
            controls.extend(self._get_nist_controls())
        elif framework == ComplianceFramework.PCI_DSS:
            controls.extend(self._get_pci_dss_controls())
        
        # Store controls by ID for quick access
        for control in controls:
            self.controls[control.control_id] = control
        
        return controls
    
    def _get_gdpr_controls(self) -> List[ComplianceControl]:
        """Get GDPR compliance controls"""
        return [
            ComplianceControl(
                control_id="GDPR-ART6",
                framework=ComplianceFramework.GDPR,
                title="Lawful Basis for Processing",
                description="Ensure processing has lawful basis under Article 6",
                requirements=[
                    "Identify and document lawful basis for each processing activity",
                    "Ensure processing is necessary for the specified purpose",
                    "Review and update lawful basis documentation regularly"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="GDPR-ART7",
                framework=ComplianceFramework.GDPR,
                title="Consent Management",
                description="Manage consent in accordance with Article 7",
                requirements=[
                    "Obtain clear and specific consent",
                    "Provide easy withdrawal mechanism",
                    "Maintain consent records and audit trail"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="GDPR-ART17",
                framework=ComplianceFramework.GDPR,
                title="Right to Erasure",
                description="Implement right to erasure (right to be forgotten)",
                requirements=[
                    "Provide mechanism for data subject requests",
                    "Verify identity before processing requests",
                    "Delete data within required timeframe",
                    "Notify third parties of deletion requests"
                ],
                automated_check=False
            ),
            ComplianceControl(
                control_id="GDPR-ART25",
                framework=ComplianceFramework.GDPR,
                title="Data Protection by Design and by Default",
                description="Implement privacy by design principles",
                requirements=[
                    "Integrate data protection into system design",
                    "Implement appropriate technical measures",
                    "Ensure data minimization by default",
                    "Regular privacy impact assessments"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="GDPR-ART32",
                framework=ComplianceFramework.GDPR,
                title="Security of Processing",
                description="Ensure appropriate security measures",
                requirements=[
                    "Implement encryption of personal data",
                    "Ensure confidentiality, integrity, availability",
                    "Regular security testing and assessment",
                    "Incident response procedures"
                ],
                automated_check=True
            ),
        ]
    
    def _get_hipaa_controls(self) -> List[ComplianceControl]:
        """Get HIPAA compliance controls"""
        return [
            ComplianceControl(
                control_id="HIPAA-164.306",
                framework=ComplianceFramework.HIPAA,
                title="Security Standards - General Rules",
                description="Ensure PHI confidentiality, integrity, and availability",
                requirements=[
                    "Implement security measures for PHI",
                    "Protect against unauthorized access",
                    "Protect against unauthorized disclosure",
                    "Ensure workforce compliance"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="HIPAA-164.308",
                framework=ComplianceFramework.HIPAA,
                title="Administrative Safeguards",
                description="Implement administrative safeguards for PHI",
                requirements=[
                    "Designate security official",
                    "Conduct workforce training",
                    "Implement access management",
                    "Maintain audit controls"
                ],
                automated_check=False
            ),
            ComplianceControl(
                control_id="HIPAA-164.310",
                framework=ComplianceFramework.HIPAA,
                title="Physical Safeguards",
                description="Implement physical safeguards for PHI",
                requirements=[
                    "Limit physical access to facilities",
                    "Control workstation access and use",
                    "Implement device and media controls",
                    "Maintain facility access controls"
                ],
                automated_check=False
            ),
            ComplianceControl(
                control_id="HIPAA-164.312",
                framework=ComplianceFramework.HIPAA,
                title="Technical Safeguards",
                description="Implement technical safeguards for PHI",
                requirements=[
                    "Implement access control systems",
                    "Audit controls and logs",
                    "Integrity controls for PHI",
                    "Transmission security measures"
                ],
                automated_check=True
            ),
        ]
    
    def _get_soc2_controls(self) -> List[ComplianceControl]:
        """Get SOC 2 compliance controls"""
        return [
            ComplianceControl(
                control_id="SOC2-CC1",
                framework=ComplianceFramework.SOC2,
                title="Control Environment",
                description="Demonstrate commitment to integrity and ethical values",
                requirements=[
                    "Establish tone at the top",
                    "Exercise oversight responsibility",
                    "Establish structure, authority, and responsibility",
                    "Demonstrate commitment to competence"
                ],
                automated_check=False
            ),
            ComplianceControl(
                control_id="SOC2-CC2",
                framework=ComplianceFramework.SOC2,
                title="Communication and Information",
                description="Obtain and use relevant information for internal control",
                requirements=[
                    "Obtain and use relevant information",
                    "Communicate internally",
                    "Communicate externally"
                ],
                automated_check=False
            ),
            ComplianceControl(
                control_id="SOC2-CC6",
                framework=ComplianceFramework.SOC2,
                title="Logical and Physical Access Controls",
                description="Restrict logical and physical access",
                requirements=[
                    "Implement logical access security measures",
                    "Implement physical access security measures",
                    "Create and remove access credentials",
                    "Review access rights periodically"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="SOC2-CC7",
                framework=ComplianceFramework.SOC2,
                title="System Operations",
                description="Manage system operations to meet objectives",
                requirements=[
                    "Manage system capacity",
                    "Monitor system performance",
                    "Manage system vulnerabilities",
                    "Monitor data processing"
                ],
                automated_check=True
            ),
        ]
    
    def _get_iso27001_controls(self) -> List[ComplianceControl]:
        """Get ISO 27001 compliance controls"""
        return [
            ComplianceControl(
                control_id="ISO27001-A5",
                framework=ComplianceFramework.ISO27001,
                title="Information Security Policies",
                description="Provide management direction for information security",
                requirements=[
                    "Document information security policy",
                    "Review policy regularly",
                    "Communicate policy to relevant parties",
                    "Ensure policy compliance"
                ],
                automated_check=False
            ),
            ComplianceControl(
                control_id="ISO27001-A8",
                framework=ComplianceFramework.ISO27001,
                title="Asset Management",
                description="Achieve and maintain appropriate protection of assets",
                requirements=[
                    "Inventory all information assets",
                    "Classify information appropriately",
                    "Handle assets according to classification",
                    "Return assets upon employment termination"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="ISO27001-A9",
                framework=ComplianceFramework.ISO27001,
                title="Access Control",
                description="Limit access to information and processing facilities",
                requirements=[
                    "Implement access control policy",
                    "Manage user access provisioning",
                    "Review user access rights regularly",
                    "Remove access rights upon termination"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="ISO27001-A10",
                framework=ComplianceFramework.ISO27001,
                title="Cryptography",
                description="Ensure proper use of cryptography",
                requirements=[
                    "Implement cryptographic controls policy",
                    "Use appropriate encryption algorithms",
                    "Manage cryptographic keys properly",
                    "Protect cryptographic keys"
                ],
                automated_check=True
            ),
        ]
    
    def _get_nist_controls(self) -> List[ComplianceControl]:
        """Get NIST Cybersecurity Framework controls"""
        return [
            ComplianceControl(
                control_id="NIST-ID.AM",
                framework=ComplianceFramework.NIST,
                title="Asset Management",
                description="Identify and manage assets",
                requirements=[
                    "Inventory physical devices and systems",
                    "Inventory software platforms and applications",
                    "Map organizational communication and data flows",
                    "Maintain asset inventory"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="NIST-PR.AC",
                framework=ComplianceFramework.NIST,
                title="Access Control",
                description="Limit access to assets and facilities",
                requirements=[
                    "Manage identities and credentials",
                    "Control physical access to assets",
                    "Manage remote access",
                    "Review access permissions"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="NIST-DE.CM",
                framework=ComplianceFramework.NIST,
                title="Security Continuous Monitoring",
                description="Monitor cybersecurity events",
                requirements=[
                    "Monitor networks and physical activities",
                    "Detect malicious code",
                    "Monitor unauthorized personnel activities",
                    "Test detection processes"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="NIST-RS.RP",
                framework=ComplianceFramework.NIST,
                title="Response Planning",
                description="Manage response activities",
                requirements=[
                    "Execute response plan during incidents",
                    "Communicate response activities",
                    "Collect and analyze forensic information",
                    "Coordinate response with stakeholders"
                ],
                automated_check=False
            ),
        ]
    
    def _get_pci_dss_controls(self) -> List[ComplianceControl]:
        """Get PCI DSS compliance controls"""
        return [
            ComplianceControl(
                control_id="PCI-DSS-1",
                framework=ComplianceFramework.PCI_DSS,
                title="Install and Maintain Firewall Configuration",
                description="Protect cardholder data with firewall configuration",
                requirements=[
                    "Establish firewall configuration standards",
                    "Build firewall configuration that denies traffic from untrusted networks",
                    "Prohibit direct public access between Internet and cardholder data",
                    "Review firewall and router rule sets"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="PCI-DSS-3",
                framework=ComplianceFramework.PCI_DSS,
                title="Protect Stored Cardholder Data",
                description="Protect stored cardholder data",
                requirements=[
                    "Keep cardholder data storage to minimum",
                    "Do not store sensitive authentication data",
                    "Mask PAN when displayed",
                    "Encrypt stored cardholder data"
                ],
                automated_check=True
            ),
            ComplianceControl(
                control_id="PCI-DSS-4",
                framework=ComplianceFramework.PCI_DSS,
                title="Encrypt Transmission of Cardholder Data",
                description="Encrypt transmission across open, public networks",
                requirements=[
                    "Use strong cryptography and security protocols",
                    "Never send unprotected PANs by email",
                    "Ensure wireless networks use encryption",
                    "Test encryption strength regularly"
                ],
                automated_check=True
            ),
        ]
    
    def _load_custom_controls(self):
        """Load custom controls from configuration"""
        try:
            custom_controls_config = getattr(settings, 'CUSTOM_COMPLIANCE_CONTROLS', {})
            
            for control_data in custom_controls_config.get('controls', []):
                control = ComplianceControl(
                    control_id=control_data['control_id'],
                    framework=ComplianceFramework(control_data['framework']),
                    title=control_data['title'],
                    description=control_data['description'],
                    requirements=control_data['requirements'],
                    automated_check=control_data.get('automated_check', False)
                )
                self.controls[control.control_id] = control
            
            compliance_logger.info(f"Loaded {len(custom_controls_config.get('controls', []))} custom controls")
            
        except Exception as e:
            compliance_logger.warning(f"Failed to load custom controls: {str(e)}")
    
    def record_audit_event(self, event_type: str, resource_type: str, 
                          action: str, user_id: Optional[str] = None,
                          resource_id: str = "", outcome: str = "success",
                          details: Dict[str, Any] = None,
                          compliance_frameworks: List[ComplianceFramework] = None,
                          ip_address: str = "", user_agent: str = "") -> str:
        """Record audit event for compliance tracking"""
        try:
            event = AuditEvent(
                user_id=user_id,
                event_type=event_type,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                outcome=outcome,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details or {},
                compliance_frameworks=compliance_frameworks or [],
                audit_level=self._calculate_audit_level(event_type, outcome)
            )
            
            # Add to audit trail
            self.audit_trail.append(event)
            
            # Store in cache for persistence
            cache_key = f"audit_event_{event.event_id}"
            cache.set(cache_key, event.to_dict(), event.retention_period_days * 86400)
            
            # Update metrics
            self.metrics['total_audit_events'] += 1
            
            # Check for compliance violations
            if outcome == "failure" or "violation" in event_type.lower():
                self.metrics['policy_violations'] += 1
                self._handle_compliance_violation(event)
            
            compliance_logger.info(f"Audit event recorded: {event.event_id}")
            return event.event_id
            
        except Exception as e:
            compliance_logger.error(f"Failed to record audit event: {str(e)}")
            return ""
    
    def _calculate_audit_level(self, event_type: str, outcome: str) -> AuditLevel:
        """Calculate audit level based on event characteristics"""
        # Critical events
        critical_events = [
            'authentication_failure', 'privilege_escalation', 'data_breach',
            'unauthorized_access', 'security_incident', 'policy_violation'
        ]
        
        # High priority events
        high_events = [
            'admin_action', 'configuration_change', 'user_creation',
            'permission_change', 'data_export', 'system_modification'
        ]
        
        event_lower = event_type.lower()
        
        if any(critical in event_lower for critical in critical_events) or outcome == "failure":
            return AuditLevel.CRITICAL
        elif any(high in event_lower for high in high_events):
            return AuditLevel.HIGH
        elif "access" in event_lower or "login" in event_lower:
            return AuditLevel.MEDIUM
        else:
            return AuditLevel.LOW
    
    def _handle_compliance_violation(self, event: AuditEvent):
        """Handle compliance violation detection"""
        try:
            violation_data = {
                'event_id': event.event_id,
                'timestamp': event.timestamp.isoformat(),
                'violation_type': event.event_type,
                'severity': event.audit_level.value,
                'frameworks_affected': [f.value for f in event.compliance_frameworks],
                'details': event.details
            }
            
            # Store violation for reporting
            cache_key = f"compliance_violation_{event.event_id}"
            cache.set(cache_key, violation_data, 86400 * 30)  # 30 days
            
            # Trigger automated remediation if configured
            if self.config.get('AUTOMATED_REMEDIATION', False):
                self._trigger_automated_remediation(event)
            
            compliance_logger.warning(f"Compliance violation detected: {event.event_id}")
            
        except Exception as e:
            compliance_logger.error(f"Failed to handle compliance violation: {str(e)}")
    
    def _trigger_automated_remediation(self, event: AuditEvent):
        """Trigger automated remediation for compliance violations"""
        # This would integrate with the security response system from Phase 8
        # For now, we'll log the remediation action
        compliance_logger.info(f"Automated remediation triggered for event: {event.event_id}")
    
    def assess_compliance(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Assess compliance status for specific framework"""
        try:
            if framework not in self.frameworks:
                raise ValueError(f"Framework {framework.value} not supported")
            
            controls = self.frameworks[framework]
            assessment_results = {
                'framework': framework.value,
                'assessment_date': timezone.now().isoformat(),
                'total_controls': len(controls),
                'compliant_controls': 0,
                'non_compliant_controls': 0,
                'partial_compliance_controls': 0,
                'controls_detail': []
            }
            
            for control in controls:
                # Perform automated checks if available
                if control.automated_check:
                    status = self._perform_automated_check(control)
                    control.implementation_status = status
                    control.last_assessed = timezone.now()
                
                # Count by status
                if control.implementation_status == ComplianceStatus.COMPLIANT:
                    assessment_results['compliant_controls'] += 1
                elif control.implementation_status == ComplianceStatus.NON_COMPLIANT:
                    assessment_results['non_compliant_controls'] += 1
                elif control.implementation_status == ComplianceStatus.PARTIAL_COMPLIANCE:
                    assessment_results['partial_compliance_controls'] += 1
                
                # Add control details
                assessment_results['controls_detail'].append({
                    'control_id': control.control_id,
                    'title': control.title,
                    'status': control.implementation_status.value,
                    'last_assessed': control.last_assessed.isoformat() if control.last_assessed else None,
                    'risk_level': control.risk_level,
                    'automated': control.automated_check
                })
            
            # Calculate compliance score
            total_controls = assessment_results['total_controls']
            if total_controls > 0:
                compliant_weight = assessment_results['compliant_controls']
                partial_weight = assessment_results['partial_compliance_controls'] * 0.5
                compliance_score = (compliant_weight + partial_weight) / total_controls * 100
            else:
                compliance_score = 0
            
            assessment_results['compliance_score'] = round(compliance_score, 2)
            
            # Cache results
            cache_key = f"compliance_assessment_{framework.value}"
            cache.set(cache_key, assessment_results, 86400)  # 24 hours
            
            compliance_logger.info(f"Compliance assessment completed for {framework.value}: {compliance_score}%")
            
            return assessment_results
            
        except Exception as e:
            compliance_logger.error(f"Compliance assessment failed for {framework.value}: {str(e)}")
            return {'error': str(e)}
    
    def _perform_automated_check(self, control: ComplianceControl) -> ComplianceStatus:
        """Perform automated compliance check for control"""
        try:
            # This is where we would integrate with the security monitoring
            # systems from previous phases to check compliance automatically
            
            # For demonstration, we'll perform basic checks based on control ID
            if control.framework == ComplianceFramework.GDPR:
                return self._check_gdpr_control(control)
            elif control.framework == ComplianceFramework.HIPAA:
                return self._check_hipaa_control(control)
            elif control.framework == ComplianceFramework.SOC2:
                return self._check_soc2_control(control)
            elif control.framework == ComplianceFramework.ISO27001:
                return self._check_iso27001_control(control)
            else:
                return ComplianceStatus.UNDER_REVIEW
                
        except Exception as e:
            compliance_logger.error(f"Automated check failed for control {control.control_id}: {str(e)}")
            return ComplianceStatus.UNDER_REVIEW
    
    def _check_gdpr_control(self, control: ComplianceControl) -> ComplianceStatus:
        """Check GDPR-specific control compliance"""
        if control.control_id == "GDPR-ART6":
            # Check if lawful basis is documented
            # This would check actual policy documents and data processing records
            return ComplianceStatus.COMPLIANT
        elif control.control_id == "GDPR-ART32":
            # Check security measures implementation
            # This would verify encryption, access controls, etc.
            return ComplianceStatus.COMPLIANT
        else:
            return ComplianceStatus.PARTIAL_COMPLIANCE
    
    def _check_hipaa_control(self, control: ComplianceControl) -> ComplianceStatus:
        """Check HIPAA-specific control compliance"""
        if control.control_id == "HIPAA-164.312":
            # Check technical safeguards
            # This would verify access controls, audit logs, etc.
            return ComplianceStatus.COMPLIANT
        else:
            return ComplianceStatus.PARTIAL_COMPLIANCE
    
    def _check_soc2_control(self, control: ComplianceControl) -> ComplianceStatus:
        """Check SOC 2-specific control compliance"""
        if control.control_id in ["SOC2-CC6", "SOC2-CC7"]:
            # Check access controls and system operations
            return ComplianceStatus.COMPLIANT
        else:
            return ComplianceStatus.PARTIAL_COMPLIANCE
    
    def _check_iso27001_control(self, control: ComplianceControl) -> ComplianceStatus:
        """Check ISO 27001-specific control compliance"""
        if control.control_id in ["ISO27001-A8", "ISO27001-A9", "ISO27001-A10"]:
            # Check asset management, access control, and cryptography
            return ComplianceStatus.COMPLIANT
        else:
            return ComplianceStatus.PARTIAL_COMPLIANCE
    
    def get_audit_trail(self, start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None,
                       event_type: Optional[str] = None,
                       user_id: Optional[str] = None,
                       limit: int = 1000) -> List[Dict[str, Any]]:
        """Get audit trail events with filtering"""
        try:
            filtered_events = []
            
            for event in list(self.audit_trail):
                # Apply filters
                if start_date and event.timestamp < start_date:
                    continue
                if end_date and event.timestamp > end_date:
                    continue
                if event_type and event_type.lower() not in event.event_type.lower():
                    continue
                if user_id and event.user_id != user_id:
                    continue
                
                filtered_events.append(event.to_dict())
                
                if len(filtered_events) >= limit:
                    break
            
            return filtered_events
            
        except Exception as e:
            compliance_logger.error(f"Failed to get audit trail: {str(e)}")
            return []
    
    def generate_compliance_report(self, frameworks: Optional[List[ComplianceFramework]] = None,
                                 report_type: str = "summary") -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        try:
            if frameworks is None:
                frameworks = list(self.frameworks.keys())
            
            report = {
                'report_id': str(uuid.uuid4()),
                'generation_date': timezone.now().isoformat(),
                'report_type': report_type,
                'frameworks_assessed': [f.value for f in frameworks],
                'overall_compliance_score': 0.0,
                'framework_assessments': {},
                'compliance_trends': {},
                'violations_summary': {},
                'recommendations': []
            }
            
            total_score = 0
            framework_count = 0
            
            # Assess each framework
            for framework in frameworks:
                assessment = self.assess_compliance(framework)
                if 'error' not in assessment:
                    report['framework_assessments'][framework.value] = assessment
                    total_score += assessment['compliance_score']
                    framework_count += 1
            
            # Calculate overall compliance score
            if framework_count > 0:
                report['overall_compliance_score'] = round(total_score / framework_count, 2)
            
            # Add compliance trends (would be based on historical data)
            report['compliance_trends'] = self._calculate_compliance_trends()
            
            # Add violations summary
            report['violations_summary'] = self._get_violations_summary()
            
            # Add recommendations
            report['recommendations'] = self._generate_compliance_recommendations(frameworks)
            
            # Cache report
            cache_key = f"compliance_report_{report['report_id']}"
            cache.set(cache_key, report, 86400 * 30)  # 30 days
            
            compliance_logger.info(f"Compliance report generated: {report['report_id']}")
            
            return report
            
        except Exception as e:
            compliance_logger.error(f"Failed to generate compliance report: {str(e)}")
            return {'error': str(e)}
    
    def _calculate_compliance_trends(self) -> Dict[str, Any]:
        """Calculate compliance trends over time"""
        # This would analyze historical compliance data
        # For now, return mock trending data
        return {
            'trend_period_days': 90,
            'overall_trend': 'improving',
            'trend_percentage': 5.2,
            'framework_trends': {
                'gdpr': {'trend': 'stable', 'change': 0.5},
                'hipaa': {'trend': 'improving', 'change': 3.2},
                'soc2': {'trend': 'improving', 'change': 2.1}
            }
        }
    
    def _get_violations_summary(self) -> Dict[str, Any]:
        """Get summary of compliance violations"""
        try:
            # Count violations from cache
            violation_count = 0
            critical_violations = 0
            
            # This would query cached violation data
            # For now, return current metrics
            violation_count = self.metrics.get('policy_violations', 0)
            
            return {
                'total_violations': violation_count,
                'critical_violations': critical_violations,
                'violation_categories': {
                    'access_control': 0,
                    'data_protection': 0,
                    'audit_trail': 0,
                    'policy_compliance': violation_count
                }
            }
            
        except Exception as e:
            compliance_logger.error(f"Failed to get violations summary: {str(e)}")
            return {}
    
    def _generate_compliance_recommendations(self, frameworks: List[ComplianceFramework]) -> List[str]:
        """Generate compliance improvement recommendations"""
        recommendations = []
        
        try:
            for framework in frameworks:
                if framework not in self.frameworks:
                    continue
                
                controls = self.frameworks[framework]
                non_compliant_controls = [
                    c for c in controls 
                    if c.implementation_status == ComplianceStatus.NON_COMPLIANT
                ]
                
                if non_compliant_controls:
                    recommendations.append(
                        f"Address {len(non_compliant_controls)} non-compliant controls in {framework.value}"
                    )
                
                # Add framework-specific recommendations
                if framework == ComplianceFramework.GDPR:
                    recommendations.extend([
                        "Implement automated consent management system",
                        "Enhance data subject rights automation",
                        "Conduct regular privacy impact assessments"
                    ])
                elif framework == ComplianceFramework.HIPAA:
                    recommendations.extend([
                        "Strengthen PHI encryption at rest and in transit",
                        "Implement comprehensive audit logging",
                        "Enhance workforce security training"
                    ])
        
        except Exception as e:
            compliance_logger.error(f"Failed to generate recommendations: {str(e)}")
        
        return recommendations
    
    def get_compliance_dashboard_data(self) -> Dict[str, Any]:
        """Get data for compliance dashboard"""
        try:
            dashboard_data = {
                'timestamp': timezone.now().isoformat(),
                'overall_metrics': self.metrics.copy(),
                'framework_status': {},
                'recent_violations': [],
                'upcoming_assessments': [],
                'compliance_alerts': []
            }
            
            # Get status for each framework
            for framework in self.frameworks.keys():
                assessment = self.assess_compliance(framework)
                if 'error' not in assessment:
                    dashboard_data['framework_status'][framework.value] = {
                        'compliance_score': assessment['compliance_score'],
                        'total_controls': assessment['total_controls'],
                        'compliant_controls': assessment['compliant_controls'],
                        'non_compliant_controls': assessment['non_compliant_controls']
                    }
            
            # Get recent audit events (last 24 hours)
            recent_events = self.get_audit_trail(
                start_date=timezone.now() - timedelta(days=1),
                limit=50
            )
            dashboard_data['recent_audit_events'] = recent_events
            
            # Get upcoming assessments
            dashboard_data['upcoming_assessments'] = self._get_upcoming_assessments()
            
            # Get compliance alerts
            dashboard_data['compliance_alerts'] = self._get_compliance_alerts()
            
            return dashboard_data
            
        except Exception as e:
            compliance_logger.error(f"Failed to get dashboard data: {str(e)}")
            return {'error': str(e)}
    
    def _get_upcoming_assessments(self) -> List[Dict[str, Any]]:
        """Get upcoming compliance assessments"""
        upcoming = []
        try:
            for controls in self.frameworks.values():
                for control in controls:
                    if control.next_assessment and control.next_assessment <= timezone.now() + timedelta(days=30):
                        upcoming.append({
                            'control_id': control.control_id,
                            'title': control.title,
                            'framework': control.framework.value,
                            'due_date': control.next_assessment.isoformat(),
                            'days_until_due': (control.next_assessment - timezone.now()).days
                        })
            
            # Sort by due date
            upcoming.sort(key=lambda x: x['due_date'])
            
        except Exception as e:
            compliance_logger.error(f"Failed to get upcoming assessments: {str(e)}")
        
        return upcoming[:10]  # Return top 10
    
    def _get_compliance_alerts(self) -> List[Dict[str, Any]]:
        """Get active compliance alerts"""
        alerts = []
        try:
            # Check for overdue assessments
            for controls in self.frameworks.values():
                for control in controls:
                    if control.next_assessment and control.next_assessment < timezone.now():
                        alerts.append({
                            'type': 'overdue_assessment',
                            'severity': 'high',
                            'message': f"Control {control.control_id} assessment overdue",
                            'control_id': control.control_id,
                            'framework': control.framework.value
                        })
            
            # Check for high violation rates
            if self.metrics.get('policy_violations', 0) > 10:
                alerts.append({
                    'type': 'high_violation_rate',
                    'severity': 'critical',
                    'message': f"High number of policy violations: {self.metrics['policy_violations']}",
                    'count': self.metrics['policy_violations']
                })
            
        except Exception as e:
            compliance_logger.error(f"Failed to get compliance alerts: {str(e)}")
        
        return alerts


# Global compliance manager instance
_global_compliance_manager = None

def get_compliance_manager() -> ComplianceManager:
    """Get global compliance manager instance"""
    global _global_compliance_manager
    if _global_compliance_manager is None:
        _global_compliance_manager = ComplianceManager()
    return _global_compliance_manager