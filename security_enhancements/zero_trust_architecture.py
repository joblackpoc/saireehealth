"""
Phase 10: Zero-Trust Architecture Implementation
Comprehensive zero-trust security model with continuous verification

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Zero-Trust Architecture
"""

import os
import json
import uuid
import logging
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import re
import ipaddress
from collections import defaultdict, deque
import secrets
import base64

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.mail import send_mail
from django.http import HttpRequest
from django.contrib.gis.geoip2 import GeoIP2

from .advanced_monitoring import get_security_monitor
from .threat_intelligence import get_threat_intelligence_engine
from .predictive_analytics import get_predictive_analytics_engine

# Zero-Trust Logger
zt_logger = logging.getLogger('zero_trust')

class ZeroTrustPrinciple(Enum):
    """Core zero-trust security principles"""
    VERIFY_EXPLICITLY = "verify_explicitly"
    LEAST_PRIVILEGE = "least_privilege"
    ASSUME_BREACH = "assume_breach"
    CONTINUOUS_VALIDATION = "continuous_validation"
    MICRO_SEGMENTATION = "micro_segmentation"
    ENCRYPT_EVERYWHERE = "encrypt_everywhere"

class VerificationMethod(Enum):
    """Identity verification methods"""
    PASSWORD = "password"
    MFA_TOTP = "mfa_totp"
    MFA_SMS = "mfa_sms"
    MFA_EMAIL = "mfa_email"
    BIOMETRIC = "biometric"
    DEVICE_CERTIFICATE = "device_certificate"
    HARDWARE_TOKEN = "hardware_token"
    BEHAVIORAL_BIOMETRIC = "behavioral_biometric"
    LOCATION_VERIFICATION = "location_verification"
    RISK_BASED_ASSESSMENT = "risk_based_assessment"

class AccessDecision(Enum):
    """Access control decisions"""
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL_ALLOW = "conditional_allow"
    STEP_UP_AUTH = "step_up_auth"
    CHALLENGE = "challenge"
    QUARANTINE = "quarantine"

class TrustLevel(Enum):
    """Zero-trust verification levels"""
    NO_TRUST = "no_trust"
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"

@dataclass
class TrustScore:
    """Zero-trust score for entity"""
    entity_id: str = ""
    entity_type: str = ""  # user, device, application, network
    trust_level: TrustLevel = TrustLevel.NO_TRUST
    score: float = 0.0  # 0.0 to 1.0
    factors: Dict[str, float] = field(default_factory=dict)
    verification_methods: List[str] = field(default_factory=list)
    last_verification: datetime = field(default_factory=timezone.now)
    verification_valid_until: datetime = field(default_factory=lambda: timezone.now() + timedelta(hours=1))
    risk_indicators: List[str] = field(default_factory=list)
    access_permissions: List[str] = field(default_factory=list)

class NetworkSegment(Enum):
    """Network micro-segmentation zones"""
    PUBLIC = "public"
    DMZ = "dmz"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    ADMIN = "admin"
    ISOLATED = "isolated"

class ResourceClassification(Enum):
    """Resource security classifications"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"

@dataclass
class VerificationEvent:
    """Identity verification event"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    verification_method: VerificationMethod = VerificationMethod.PASSWORD
    success: bool = False
    confidence_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    device_id: str = ""
    source_ip: str = ""
    location: Optional[Dict[str, str]] = None
    timestamp: datetime = field(default_factory=timezone.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AccessRequest:
    """Zero-trust access request"""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    resource: str = ""
    action: str = ""
    requested_permissions: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    device_fingerprint: str = ""
    source_ip: str = ""
    user_agent: str = ""
    timestamp: datetime = field(default_factory=timezone.now)
    trust_score: float = 0.0
    decision: Optional[AccessDecision] = None
    decision_factors: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)
    session_id: str = ""

@dataclass
class DeviceProfile:
    """Device trust profile"""
    device_id: str = ""
    device_fingerprint: str = ""
    device_type: str = ""  # mobile, desktop, tablet, server
    operating_system: str = ""
    browser: str = ""
    is_managed: bool = False
    is_compliant: bool = True
    last_seen: datetime = field(default_factory=timezone.now)
    trust_score: float = 0.0
    security_posture: Dict[str, Any] = field(default_factory=dict)
    certificates: List[str] = field(default_factory=list)
    encryption_status: bool = False
    patch_level: str = ""
    antivirus_status: bool = False
    firewall_enabled: bool = False

@dataclass
class NetworkZone:
    """Network micro-segmentation zone"""
    zone_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    segment: NetworkSegment = NetworkSegment.INTERNAL
    ip_ranges: List[str] = field(default_factory=list)
    allowed_protocols: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    security_level: int = 3  # 1-5, higher = more secure
    encryption_required: bool = True
    monitoring_enabled: bool = True
    access_policies: List[str] = field(default_factory=list)
    ingress_rules: List[Dict[str, Any]] = field(default_factory=list)
    egress_rules: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class ZeroTrustPolicy:
    """Comprehensive zero-trust access policy"""
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    resource_pattern: str = ""
    resource_classification: ResourceClassification = ResourceClassification.INTERNAL
    required_trust_level: TrustLevel = TrustLevel.MEDIUM
    required_verifications: List[VerificationMethod] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)
    time_restrictions: Dict[str, Any] = field(default_factory=dict)
    location_restrictions: List[str] = field(default_factory=list)
    network_restrictions: List[str] = field(default_factory=list)
    device_requirements: Dict[str, Any] = field(default_factory=dict)
    session_controls: Dict[str, Any] = field(default_factory=dict)
    monitoring_level: int = 3  # 1-5
    audit_required: bool = True
    encryption_required: bool = True
    created_date: datetime = field(default_factory=timezone.now)
    enabled: bool = True

@dataclass
class ContinuousVerification:
    """Continuous verification session"""
    session_id: str = ""
    user_id: str = ""
    device_id: str = ""
    start_time: datetime = field(default_factory=timezone.now)
    last_verification: datetime = field(default_factory=timezone.now)
    verification_interval: timedelta = field(default_factory=lambda: timedelta(minutes=30))
    risk_threshold: float = 0.7
    current_trust_score: float = 0.0
    verification_history: List[VerificationEvent] = field(default_factory=list)
    anomaly_count: int = 0
    last_activity: datetime = field(default_factory=timezone.now)
    is_active: bool = True

class ZeroTrustArchitecture:
    """
    Comprehensive Zero-Trust Security Architecture
    
    Implements complete zero-trust security model with:
    - Explicit verification for every access request
    - Least privilege access controls
    - Continuous validation and monitoring
    - Micro-segmentation and encryption
    - Adaptive trust scoring
    """
    
    def __init__(self):
        self.verification_events = deque(maxlen=10000)
        self.access_requests = deque(maxlen=5000)
        self.device_profiles = {}
        self.network_zones = {}
        self.zero_trust_policies = {}
        self.active_sessions = {}
        self.continuous_verifications = {}
        
        # Configuration
        self.config = getattr(settings, 'ZERO_TRUST_CONFIG', {
            'STRICT_MODE': True,
            'DEFAULT_DENY': True,
            'REQUIRE_EXPLICIT_ALLOW': True,
            'CONTINUOUS_VERIFICATION': True,
            'VERIFICATION_INTERVAL_MINUTES': 30,
            'DEVICE_TRUST_REQUIRED': True,
            'LOCATION_TRACKING': True,
            'BEHAVIORAL_ANALYSIS': True,
            'MICRO_SEGMENTATION': True,
            'ENCRYPTION_EVERYWHERE': True,
            'AUDIT_ALL_ACCESS': True,
            'ADAPTIVE_TRUST': True,
            'RISK_BASED_DECISIONS': True,
            'MAX_TRUST_SCORE_AGE_MINUTES': 60,
            'MIN_TRUST_SCORE_FOR_ACCESS': 0.5,
            'STEP_UP_AUTH_THRESHOLD': 0.7,
            'NETWORK_SEGMENTATION_LEVELS': 5
        })
        
        # Initialize zero-trust architecture
        self._initialize_zero_trust_architecture()
        
        zt_logger.info("Zero-Trust Architecture initialized")
    
    def _initialize_zero_trust_architecture(self):
        """Initialize zero-trust architecture components"""
        try:
            # Load existing data
            self._load_zero_trust_data()
            
            # Initialize network zones
            self._initialize_network_zones()
            
            # Initialize default policies
            self._initialize_default_policies()
            
            # Setup continuous verification
            self._setup_continuous_verification()
            
            zt_logger.info("Zero-trust architecture components initialized")
            
        except Exception as e:
            zt_logger.error(f"Failed to initialize zero-trust architecture: {str(e)}")
    
    def _load_zero_trust_data(self):
        """Load zero-trust data from cache"""
        try:
            # Load device profiles
            cached_devices = cache.get('zero_trust_devices', {})
            self.device_profiles.update(cached_devices)
            
            # Load network zones
            cached_zones = cache.get('zero_trust_zones', {})
            self.network_zones.update(cached_zones)
            
            # Load policies
            cached_policies = cache.get('zero_trust_policies', {})
            self.zero_trust_policies.update(cached_policies)
            
            zt_logger.info("Loaded zero-trust data from cache")
            
        except Exception as e:
            zt_logger.error(f"Failed to load zero-trust data: {str(e)}")
    
    def _initialize_network_zones(self):
        """Initialize network micro-segmentation zones"""
        try:
            if not self.network_zones:
                # Public zone
                public_zone = NetworkZone(
                    name="Public Zone",
                    segment=NetworkSegment.PUBLIC,
                    ip_ranges=["0.0.0.0/0"],
                    allowed_protocols=["HTTPS", "HTTP"],
                    allowed_ports=[80, 443],
                    security_level=1,
                    encryption_required=True,
                    monitoring_enabled=True
                )
                self.network_zones[public_zone.zone_id] = public_zone
                
                # DMZ zone
                dmz_zone = NetworkZone(
                    name="DMZ Zone",
                    segment=NetworkSegment.DMZ,
                    ip_ranges=["10.0.1.0/24"],
                    allowed_protocols=["HTTPS", "SSH"],
                    allowed_ports=[22, 443, 8080],
                    security_level=2,
                    encryption_required=True,
                    monitoring_enabled=True
                )
                self.network_zones[dmz_zone.zone_id] = dmz_zone
                
                # Internal zone
                internal_zone = NetworkZone(
                    name="Internal Zone",
                    segment=NetworkSegment.INTERNAL,
                    ip_ranges=["10.0.2.0/24", "192.168.1.0/24"],
                    allowed_protocols=["HTTPS", "HTTP", "SSH", "RDP"],
                    allowed_ports=[22, 80, 443, 3389, 5432],
                    security_level=3,
                    encryption_required=True,
                    monitoring_enabled=True
                )
                self.network_zones[internal_zone.zone_id] = internal_zone
                
                # Restricted zone
                restricted_zone = NetworkZone(
                    name="Restricted Zone",
                    segment=NetworkSegment.RESTRICTED,
                    ip_ranges=["10.0.3.0/24"],
                    allowed_protocols=["HTTPS"],
                    allowed_ports=[443],
                    security_level=4,
                    encryption_required=True,
                    monitoring_enabled=True
                )
                self.network_zones[restricted_zone.zone_id] = restricted_zone
                
                # Admin zone
                admin_zone = NetworkZone(
                    name="Admin Zone",
                    segment=NetworkSegment.ADMIN,
                    ip_ranges=["10.0.4.0/24"],
                    allowed_protocols=["HTTPS", "SSH"],
                    allowed_ports=[22, 443],
                    security_level=5,
                    encryption_required=True,
                    monitoring_enabled=True
                )
                self.network_zones[admin_zone.zone_id] = admin_zone
            
            zt_logger.info(f"Initialized {len(self.network_zones)} network zones")
            
        except Exception as e:
            zt_logger.error(f"Failed to initialize network zones: {str(e)}")
    
    def _initialize_default_policies(self):
        """Initialize default zero-trust policies"""
        try:
            if not self.zero_trust_policies:
                # Admin access policy
                admin_policy = ZeroTrustPolicy(
                    name="Admin Access Policy",
                    description="Strict access controls for administrative functions",
                    resource_pattern="/admin/*",
                    resource_classification=ResourceClassification.RESTRICTED,
                    required_trust_level=TrustLevel.VERIFIED,
                    required_verifications=[
                        VerificationMethod.PASSWORD,
                        VerificationMethod.MFA_TOTP,
                        VerificationMethod.DEVICE_CERTIFICATE
                    ],
                    conditions={
                        'max_concurrent_sessions': 1,
                        'business_hours_only': True,
                        'vpn_required': True
                    },
                    time_restrictions={
                        'allowed_hours': '08:00-18:00',
                        'weekdays_only': True,
                        'timezone': 'UTC'
                    },
                    location_restrictions=['US', 'CA'],
                    device_requirements={
                        'managed_device': True,
                        'encryption_enabled': True,
                        'patch_level_current': True,
                        'antivirus_active': True
                    },
                    session_controls={
                        'timeout_minutes': 30,
                        'idle_timeout_minutes': 15,
                        'concurrent_limit': 1,
                        'step_up_auth_required': True
                    },
                    monitoring_level=5,
                    audit_required=True,
                    encryption_required=True
                )
                self.zero_trust_policies[admin_policy.policy_id] = admin_policy
                
                # Sensitive data policy
                data_policy = ZeroTrustPolicy(
                    name="Sensitive Data Access Policy",
                    description="Controls for accessing sensitive health data",
                    resource_pattern="/health_data/*",
                    resource_classification=ResourceClassification.CONFIDENTIAL,
                    required_trust_level=TrustLevel.HIGH,
                    required_verifications=[
                        VerificationMethod.PASSWORD,
                        VerificationMethod.MFA_TOTP
                    ],
                    conditions={
                        'data_classification_clearance': True,
                        'need_to_know_basis': True,
                        'purpose_limitation': True
                    },
                    device_requirements={
                        'encryption_enabled': True,
                        'screen_lock_enabled': True
                    },
                    session_controls={
                        'timeout_minutes': 60,
                        'idle_timeout_minutes': 30,
                        'watermarking': True,
                        'screenshot_protection': True
                    },
                    monitoring_level=4,
                    audit_required=True,
                    encryption_required=True
                )
                self.zero_trust_policies[data_policy.policy_id] = data_policy
                
                # Standard user policy
                user_policy = ZeroTrustPolicy(
                    name="Standard User Access Policy",
                    description="Standard access controls for regular users",
                    resource_pattern="/app/*",
                    resource_classification=ResourceClassification.INTERNAL,
                    required_trust_level=TrustLevel.MEDIUM,
                    required_verifications=[
                        VerificationMethod.PASSWORD
                    ],
                    conditions={
                        'basic_authentication': True
                    },
                    session_controls={
                        'timeout_minutes': 480,  # 8 hours
                        'idle_timeout_minutes': 120,  # 2 hours
                        'concurrent_limit': 3
                    },
                    monitoring_level=2,
                    audit_required=False,
                    encryption_required=True
                )
                self.zero_trust_policies[user_policy.policy_id] = user_policy
            
            zt_logger.info(f"Initialized {len(self.zero_trust_policies)} zero-trust policies")
            
        except Exception as e:
            zt_logger.error(f"Failed to initialize default policies: {str(e)}")
    
    def _setup_continuous_verification(self):
        """Setup continuous verification system"""
        try:
            # Load existing continuous verification sessions
            cached_verifications = cache.get('continuous_verifications', {})
            self.continuous_verifications.update(cached_verifications)
            
            zt_logger.info("Continuous verification system setup complete")
            
        except Exception as e:
            zt_logger.error(f"Failed to setup continuous verification: {str(e)}")
    
    def process_access_request(self, request: HttpRequest, resource: str, action: str = "read") -> AccessDecision:
        """
        Process zero-trust access request
        
        Args:
            request: Django HTTP request
            resource: Resource being accessed
            action: Action being performed
            
        Returns:
            Access decision
        """
        try:
            # Create access request record
            access_request = AccessRequest(
                user_id=str(request.user.id) if request.user.is_authenticated else "anonymous",
                resource=resource,
                action=action,
                source_ip=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                device_fingerprint=self._generate_device_fingerprint(request),
                session_id=request.session.session_key or ""
            )
            
            # Verify identity explicitly
            verification_result = self._verify_identity_explicitly(request, access_request)
            if not verification_result['success']:
                access_request.decision = AccessDecision.DENY
                access_request.decision_factors.append("Identity verification failed")
                self.access_requests.append(access_request)
                return AccessDecision.DENY
            
            # Get current trust score
            trust_score = self._get_current_trust_score(access_request.user_id, access_request.device_fingerprint)
            access_request.trust_score = trust_score
            
            # Find applicable policies
            applicable_policies = self._find_applicable_policies(resource)
            if not applicable_policies:
                if self.config.get('DEFAULT_DENY', True):
                    access_request.decision = AccessDecision.DENY
                    access_request.decision_factors.append("No applicable policy found - default deny")
                    self.access_requests.append(access_request)
                    return AccessDecision.DENY
            
            # Evaluate access decision
            decision = self._evaluate_access_decision(access_request, applicable_policies, verification_result)
            access_request.decision = decision
            
            # Setup continuous verification if access granted
            if decision in [AccessDecision.ALLOW, AccessDecision.CONDITIONAL_ALLOW]:
                self._setup_session_monitoring(access_request)
            
            # Log access request
            self.access_requests.append(access_request)
            
            zt_logger.info(f"Access decision: {decision.value} for user {access_request.user_id} accessing {resource}")
            
            return decision
            
        except Exception as e:
            zt_logger.error(f"Failed to process access request: {str(e)}")
            return AccessDecision.DENY
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address from request"""
        try:
            # Check for forwarded IP
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                return x_forwarded_for.split(',')[0].strip()
            
            # Check for real IP
            x_real_ip = request.META.get('HTTP_X_REAL_IP')
            if x_real_ip:
                return x_real_ip
            
            # Default to remote address
            return request.META.get('REMOTE_ADDR', '127.0.0.1')
            
        except Exception as e:
            zt_logger.error(f"Failed to get client IP: {str(e)}")
            return '127.0.0.1'
    
    def _generate_device_fingerprint(self, request: HttpRequest) -> str:
        """Generate device fingerprint"""
        try:
            # Collect device characteristics
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
            accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')
            
            # Create fingerprint
            fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
            fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            
            return fingerprint_hash[:32]
            
        except Exception as e:
            zt_logger.error(f"Failed to generate device fingerprint: {str(e)}")
            return "unknown"
    
    def _verify_identity_explicitly(self, request: HttpRequest, access_request: AccessRequest) -> Dict[str, Any]:
        """Verify identity explicitly according to zero-trust principles"""
        try:
            verification_results = []
            
            # Password verification
            if request.user.is_authenticated:
                verification_event = VerificationEvent(
                    user_id=access_request.user_id,
                    verification_method=VerificationMethod.PASSWORD,
                    success=True,
                    confidence_score=0.6,
                    device_id=access_request.device_fingerprint,
                    source_ip=access_request.source_ip
                )
                verification_results.append(verification_event)
                self.verification_events.append(verification_event)
            
            # Device verification
            device_trust = self._verify_device_trust(access_request.device_fingerprint, request)
            if device_trust['verified']:
                verification_event = VerificationEvent(
                    user_id=access_request.user_id,
                    verification_method=VerificationMethod.DEVICE_CERTIFICATE,
                    success=True,
                    confidence_score=device_trust['confidence'],
                    device_id=access_request.device_fingerprint,
                    source_ip=access_request.source_ip,
                    metadata=device_trust
                )
                verification_results.append(verification_event)
                self.verification_events.append(verification_event)
            
            # Location verification
            location_trust = self._verify_location_trust(access_request.source_ip, access_request.user_id)
            if location_trust['verified']:
                verification_event = VerificationEvent(
                    user_id=access_request.user_id,
                    verification_method=VerificationMethod.LOCATION_VERIFICATION,
                    success=True,
                    confidence_score=location_trust['confidence'],
                    device_id=access_request.device_fingerprint,
                    source_ip=access_request.source_ip,
                    location=location_trust.get('location'),
                    metadata=location_trust
                )
                verification_results.append(verification_event)
                self.verification_events.append(verification_event)
            
            # Risk-based assessment
            risk_assessment = self._perform_risk_assessment(access_request)
            verification_event = VerificationEvent(
                user_id=access_request.user_id,
                verification_method=VerificationMethod.RISK_BASED_ASSESSMENT,
                success=risk_assessment['low_risk'],
                confidence_score=risk_assessment['confidence'],
                device_id=access_request.device_fingerprint,
                source_ip=access_request.source_ip,
                risk_factors=risk_assessment['risk_factors'],
                metadata=risk_assessment
            )
            verification_results.append(verification_event)
            self.verification_events.append(verification_event)
            
            # Calculate overall verification success
            successful_verifications = [v for v in verification_results if v.success]
            overall_confidence = sum(v.confidence_score for v in successful_verifications) / len(successful_verifications) if successful_verifications else 0.0
            
            return {
                'success': len(successful_verifications) > 0,
                'confidence': overall_confidence,
                'verifications': verification_results,
                'required_additional_auth': overall_confidence < 0.7
            }
            
        except Exception as e:
            zt_logger.error(f"Failed to verify identity explicitly: {str(e)}")
            return {'success': False, 'confidence': 0.0, 'verifications': []}
    
    def _verify_device_trust(self, device_fingerprint: str, request: HttpRequest) -> Dict[str, Any]:
        """Verify device trust and compliance"""
        try:
            # Get or create device profile
            if device_fingerprint not in self.device_profiles:
                self.device_profiles[device_fingerprint] = DeviceProfile(
                    device_id=device_fingerprint,
                    device_fingerprint=device_fingerprint,
                    device_type=self._detect_device_type(request),
                    operating_system=self._detect_os(request),
                    browser=self._detect_browser(request)
                )
            
            device = self.device_profiles[device_fingerprint]
            device.last_seen = timezone.now()
            
            # Calculate device trust score
            trust_factors = {
                'known_device': 0.4 if device_fingerprint in self.device_profiles else 0.0,
                'managed_device': 0.3 if device.is_managed else 0.0,
                'compliant_device': 0.2 if device.is_compliant else 0.0,
                'recent_activity': 0.1 if (timezone.now() - device.last_seen).days < 7 else 0.0
            }
            
            device.trust_score = sum(trust_factors.values())
            
            return {
                'verified': device.trust_score > 0.3,
                'confidence': device.trust_score,
                'trust_factors': trust_factors,
                'device_profile': device
            }
            
        except Exception as e:
            zt_logger.error(f"Failed to verify device trust: {str(e)}")
            return {'verified': False, 'confidence': 0.0}
    
    def _verify_location_trust(self, ip_address: str, user_id: str) -> Dict[str, Any]:
        """Verify location trust based on IP geolocation"""
        try:
            # Get geolocation
            try:
                g = GeoIP2()
                location = g.city(ip_address)
                country = location.get('country_code', 'Unknown')
                city = location.get('city', 'Unknown')
                
                # Check if location is in allowed regions
                # This would be configured per user/policy
                allowed_countries = ['US', 'CA', 'GB', 'DE', 'AU']  # Example
                location_trusted = country in allowed_countries
                
                # Check for location consistency
                # In real implementation, this would check user's location history
                location_consistent = True  # Placeholder
                
                confidence = 0.0
                if location_trusted:
                    confidence += 0.5
                if location_consistent:
                    confidence += 0.3
                
                return {
                    'verified': confidence > 0.4,
                    'confidence': confidence,
                    'location': {
                        'country': country,
                        'city': city,
                        'ip': ip_address
                    },
                    'trusted_location': location_trusted,
                    'consistent_location': location_consistent
                }
                
            except Exception:
                # Fallback for local/private IPs
                if self._is_private_ip(ip_address):
                    return {
                        'verified': True,
                        'confidence': 0.8,
                        'location': {'type': 'private_network', 'ip': ip_address},
                        'trusted_location': True,
                        'consistent_location': True
                    }
                else:
                    return {
                        'verified': False,
                        'confidence': 0.0,
                        'location': {'ip': ip_address},
                        'error': 'Could not verify location'
                    }
            
        except Exception as e:
            zt_logger.error(f"Failed to verify location trust: {str(e)}")
            return {'verified': False, 'confidence': 0.0}
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is private/internal"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except:
            return False
    
    def _perform_risk_assessment(self, access_request: AccessRequest) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        try:
            risk_factors = []
            risk_score = 0.0
            
            # Get threat intelligence
            threat_engine = get_threat_intelligence_engine()
            
            # Check IP reputation
            ip_intel = threat_engine.check_ip_reputation(access_request.source_ip)
            if ip_intel and ip_intel.threat_level.value in ['high', 'critical']:
                risk_factors.append(f"Malicious IP: {ip_intel.threat_level.value}")
                risk_score += 0.3
            
            # Check user risk profile
            analytics_engine = get_predictive_analytics_engine()
            user_profile = analytics_engine.get_user_risk_profile(access_request.user_id)
            if user_profile and user_profile.risk_score > 0.7:
                risk_factors.append(f"High user risk score: {user_profile.risk_score}")
                risk_score += user_profile.risk_score * 0.2
            
            # Check for anomalous timing
            current_hour = timezone.now().hour
            if current_hour < 6 or current_hour > 22:
                risk_factors.append("Access outside business hours")
                risk_score += 0.1
            
            # Check for rapid successive requests
            recent_requests = [
                req for req in self.access_requests
                if (req.user_id == access_request.user_id and
                    (timezone.now() - req.timestamp).seconds < 60)
            ]
            if len(recent_requests) > 5:
                risk_factors.append("Rapid successive access requests")
                risk_score += 0.15
            
            # Normalize risk score
            risk_score = min(risk_score, 1.0)
            
            return {
                'low_risk': risk_score < 0.3,
                'confidence': 1.0 - risk_score,
                'risk_score': risk_score,
                'risk_factors': risk_factors
            }
            
        except Exception as e:
            zt_logger.error(f"Failed to perform risk assessment: {str(e)}")
            return {'low_risk': False, 'confidence': 0.0, 'risk_score': 1.0, 'risk_factors': ['Risk assessment failed']}
    
    def _detect_device_type(self, request: HttpRequest) -> str:
        """Detect device type from user agent"""
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        
        if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
            return 'mobile'
        elif 'tablet' in user_agent or 'ipad' in user_agent:
            return 'tablet'
        elif 'bot' in user_agent or 'crawler' in user_agent:
            return 'bot'
        else:
            return 'desktop'
    
    def _detect_os(self, request: HttpRequest) -> str:
        """Detect operating system from user agent"""
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        
        if 'windows' in user_agent:
            return 'Windows'
        elif 'mac os' in user_agent or 'macos' in user_agent:
            return 'macOS'
        elif 'linux' in user_agent:
            return 'Linux'
        elif 'android' in user_agent:
            return 'Android'
        elif 'ios' in user_agent or 'iphone' in user_agent:
            return 'iOS'
        else:
            return 'Unknown'
    
    def _detect_browser(self, request: HttpRequest) -> str:
        """Detect browser from user agent"""
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        
        if 'chrome' in user_agent and 'edg' not in user_agent:
            return 'Chrome'
        elif 'firefox' in user_agent:
            return 'Firefox'
        elif 'safari' in user_agent and 'chrome' not in user_agent:
            return 'Safari'
        elif 'edg' in user_agent:
            return 'Edge'
        elif 'opera' in user_agent:
            return 'Opera'
        else:
            return 'Unknown'
    
    def _get_current_trust_score(self, user_id: str, device_fingerprint: str) -> float:
        """Get current trust score for user/device combination"""
        try:
            # Get trust score from automation engine
            from .ai_security_automation import get_security_automation_engine
            automation_engine = get_security_automation_engine()
            
            if user_id in automation_engine.trust_scores:
                trust_score = automation_engine.trust_scores[user_id]
                
                # Check if trust score is still valid
                if trust_score.verification_valid_until > timezone.now():
                    return trust_score.score
            
            # Default to low trust if no valid score
            return 0.2
            
        except Exception as e:
            zt_logger.error(f"Failed to get current trust score: {str(e)}")
            return 0.0
    
    def _find_applicable_policies(self, resource: str) -> List[ZeroTrustPolicy]:
        """Find policies applicable to resource"""
        try:
            applicable_policies = []
            
            for policy in self.zero_trust_policies.values():
                if not policy.enabled:
                    continue
                
                # Check if resource matches policy pattern
                if self._resource_matches_pattern(resource, policy.resource_pattern):
                    applicable_policies.append(policy)
            
            # Sort by specificity (more specific patterns first)
            applicable_policies.sort(key=lambda p: len(p.resource_pattern), reverse=True)
            
            return applicable_policies
            
        except Exception as e:
            zt_logger.error(f"Failed to find applicable policies: {str(e)}")
            return []
    
    def _resource_matches_pattern(self, resource: str, pattern: str) -> bool:
        """Check if resource matches policy pattern"""
        try:
            # Convert pattern to regex
            regex_pattern = pattern.replace('*', '.*')
            return re.match(f"^{regex_pattern}$", resource) is not None
            
        except Exception as e:
            zt_logger.error(f"Failed to match resource pattern: {str(e)}")
            return False
    
    def _evaluate_access_decision(self, access_request: AccessRequest, policies: List[ZeroTrustPolicy], verification_result: Dict[str, Any]) -> AccessDecision:
        """Evaluate access decision based on policies and verification"""
        try:
            if not policies:
                return AccessDecision.DENY
            
            # Use the most specific policy (first in sorted list)
            primary_policy = policies[0]
            
            # Check trust level requirement
            required_trust = primary_policy.required_trust_level
            current_trust_score = access_request.trust_score
            
            trust_levels = {
                TrustLevel.NO_TRUST: 0.0,
                TrustLevel.MINIMAL: 0.2,
                TrustLevel.LOW: 0.4,
                TrustLevel.MEDIUM: 0.6,
                TrustLevel.HIGH: 0.8,
                TrustLevel.VERIFIED: 0.9
            }
            
            required_score = trust_levels.get(required_trust, 0.6)
            
            if current_trust_score < required_score:
                access_request.decision_factors.append(f"Trust score {current_trust_score} below required {required_score}")
                
                # Check if step-up authentication can help
                if current_trust_score >= self.config.get('STEP_UP_AUTH_THRESHOLD', 0.5):
                    return AccessDecision.STEP_UP_AUTH
                else:
                    return AccessDecision.DENY
            
            # Check verification requirements
            verification_success = verification_result.get('success', False)
            verification_confidence = verification_result.get('confidence', 0.0)
            
            if not verification_success or verification_confidence < 0.5:
                access_request.decision_factors.append("Insufficient verification")
                return AccessDecision.CHALLENGE
            
            # Check time restrictions
            if not self._check_time_restrictions(primary_policy.time_restrictions):
                access_request.decision_factors.append("Outside allowed time window")
                return AccessDecision.DENY
            
            # Check location restrictions
            if not self._check_location_restrictions(access_request.source_ip, primary_policy.location_restrictions):
                access_request.decision_factors.append("Location not allowed")
                return AccessDecision.DENY
            
            # Check device requirements
            device_profile = self.device_profiles.get(access_request.device_fingerprint)
            if not self._check_device_requirements(device_profile, primary_policy.device_requirements):
                access_request.decision_factors.append("Device does not meet requirements")
                return AccessDecision.CONDITIONAL_ALLOW
            
            # All checks passed
            access_request.decision_factors.append("All policy requirements met")
            return AccessDecision.ALLOW
            
        except Exception as e:
            zt_logger.error(f"Failed to evaluate access decision: {str(e)}")
            return AccessDecision.DENY
    
    def _check_time_restrictions(self, time_restrictions: Dict[str, Any]) -> bool:
        """Check if current time is within allowed restrictions"""
        try:
            if not time_restrictions:
                return True
            
            current_time = timezone.now()
            
            # Check weekdays only
            if time_restrictions.get('weekdays_only', False):
                if current_time.weekday() >= 5:  # Saturday = 5, Sunday = 6
                    return False
            
            # Check allowed hours
            allowed_hours = time_restrictions.get('allowed_hours')
            if allowed_hours:
                start_hour, end_hour = allowed_hours.split('-')
                start_time = int(start_hour.split(':')[0])
                end_time = int(end_hour.split(':')[0])
                
                current_hour = current_time.hour
                if not (start_time <= current_hour <= end_time):
                    return False
            
            return True
            
        except Exception as e:
            zt_logger.error(f"Failed to check time restrictions: {str(e)}")
            return False
    
    def _check_location_restrictions(self, ip_address: str, location_restrictions: List[str]) -> bool:
        """Check if location is within allowed restrictions"""
        try:
            if not location_restrictions:
                return True
            
            # For private IPs, allow access
            if self._is_private_ip(ip_address):
                return True
            
            # Check geolocation
            try:
                g = GeoIP2()
                location = g.city(ip_address)
                country = location.get('country_code', '')
                
                return country in location_restrictions
                
            except Exception:
                # If geolocation fails, deny access for safety
                return False
            
        except Exception as e:
            zt_logger.error(f"Failed to check location restrictions: {str(e)}")
            return False
    
    def _check_device_requirements(self, device_profile: Optional[DeviceProfile], device_requirements: Dict[str, Any]) -> bool:
        """Check if device meets requirements"""
        try:
            if not device_requirements or not device_profile:
                return True
            
            # Check managed device requirement
            if device_requirements.get('managed_device', False):
                if not device_profile.is_managed:
                    return False
            
            # Check encryption requirement
            if device_requirements.get('encryption_enabled', False):
                if not device_profile.encryption_status:
                    return False
            
            # Check patch level requirement
            if device_requirements.get('patch_level_current', False):
                # This would check actual patch level in real implementation
                pass
            
            # Check antivirus requirement
            if device_requirements.get('antivirus_active', False):
                if not device_profile.antivirus_status:
                    return False
            
            return True
            
        except Exception as e:
            zt_logger.error(f"Failed to check device requirements: {str(e)}")
            return False
    
    def _setup_session_monitoring(self, access_request: AccessRequest):
        """Setup continuous monitoring for granted access"""
        try:
            # Create or update continuous verification session
            verification_session = ContinuousVerification(
                session_id=access_request.session_id,
                user_id=access_request.user_id,
                device_id=access_request.device_fingerprint,
                current_trust_score=access_request.trust_score,
                verification_interval=timedelta(
                    minutes=self.config.get('VERIFICATION_INTERVAL_MINUTES', 30)
                )
            )
            
            self.continuous_verifications[access_request.session_id] = verification_session
            
            zt_logger.info(f"Setup continuous verification for session {access_request.session_id}")
            
        except Exception as e:
            zt_logger.error(f"Failed to setup session monitoring: {str(e)}")
    
    def validate_ongoing_access(self, session_id: str) -> bool:
        """Validate ongoing access for active session"""
        try:
            verification_session = self.continuous_verifications.get(session_id)
            if not verification_session or not verification_session.is_active:
                return False
            
            current_time = timezone.now()
            
            # Check if re-verification is needed
            time_since_verification = current_time - verification_session.last_verification
            if time_since_verification >= verification_session.verification_interval:
                
                # Perform re-verification
                reverification_success = self._perform_reverification(verification_session)
                
                if not reverification_success:
                    verification_session.is_active = False
                    zt_logger.warning(f"Re-verification failed for session {session_id}")
                    return False
                
                verification_session.last_verification = current_time
            
            # Check for anomalies
            if verification_session.anomaly_count > 3:
                verification_session.is_active = False
                zt_logger.warning(f"Too many anomalies detected for session {session_id}")
                return False
            
            # Update last activity
            verification_session.last_activity = current_time
            
            return True
            
        except Exception as e:
            zt_logger.error(f"Failed to validate ongoing access: {str(e)}")
            return False
    
    def _perform_reverification(self, verification_session: ContinuousVerification) -> bool:
        """Perform re-verification for continuous access"""
        try:
            # Get current trust score
            from .ai_security_automation import get_security_automation_engine
            automation_engine = get_security_automation_engine()
            
            if verification_session.user_id in automation_engine.trust_scores:
                trust_score = automation_engine.trust_scores[verification_session.user_id]
                verification_session.current_trust_score = trust_score.score
                
                # Check if trust score is still above threshold
                if trust_score.score < verification_session.risk_threshold:
                    return False
            
            # Additional verification checks would go here
            # For example: behavioral analysis, device posture check, etc.
            
            return True
            
        except Exception as e:
            zt_logger.error(f"Failed to perform re-verification: {str(e)}")
            return False
    
    def get_zero_trust_summary(self) -> Dict[str, Any]:
        """Get zero-trust architecture summary"""
        try:
            # Access statistics
            recent_requests = [
                req for req in self.access_requests
                if (timezone.now() - req.timestamp).days <= 7
            ]
            
            allowed_requests = [req for req in recent_requests if req.decision == AccessDecision.ALLOW]
            denied_requests = [req for req in recent_requests if req.decision == AccessDecision.DENY]
            
            # Trust score statistics
            trust_scores = [device.trust_score for device in self.device_profiles.values()]
            avg_device_trust = sum(trust_scores) / len(trust_scores) if trust_scores else 0.0
            
            # Verification statistics
            recent_verifications = [
                event for event in self.verification_events
                if (timezone.now() - event.timestamp).days <= 7
            ]
            
            successful_verifications = [event for event in recent_verifications if event.success]
            
            summary = {
                'last_updated': timezone.now().isoformat(),
                'zero_trust_enabled': self.config.get('STRICT_MODE', True),
                'default_deny_policy': self.config.get('DEFAULT_DENY', True),
                'continuous_verification_enabled': self.config.get('CONTINUOUS_VERIFICATION', True),
                'total_policies': len(self.zero_trust_policies),
                'total_network_zones': len(self.network_zones),
                'total_device_profiles': len(self.device_profiles),
                'average_device_trust_score': avg_device_trust,
                'recent_access_requests': len(recent_requests),
                'access_success_rate': len(allowed_requests) / len(recent_requests) if recent_requests else 0.0,
                'recent_verifications': len(recent_verifications),
                'verification_success_rate': len(successful_verifications) / len(recent_verifications) if recent_verifications else 0.0,
                'active_continuous_sessions': len([v for v in self.continuous_verifications.values() if v.is_active]),
                'micro_segmentation_enabled': self.config.get('MICRO_SEGMENTATION', True),
                'encryption_everywhere': self.config.get('ENCRYPTION_EVERYWHERE', True)
            }
            
            return summary
            
        except Exception as e:
            zt_logger.error(f"Failed to get zero-trust summary: {str(e)}")
            return {'error': str(e)}


# Global zero-trust architecture instance
_global_zero_trust_architecture = None

def get_zero_trust_architecture() -> ZeroTrustArchitecture:
    """Get global zero-trust architecture instance"""
    global _global_zero_trust_architecture
    if _global_zero_trust_architecture is None:
        _global_zero_trust_architecture = ZeroTrustArchitecture()
    return _global_zero_trust_architecture