"""
Phase 10: Advanced Threat Intelligence & AI-Powered Security
Cutting-edge threat intelligence, predictive analytics, and AI security automation

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Advanced Threat Intelligence System
"""

import os
import json
import uuid
import hashlib
import logging
import asyncio
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import re
import ipaddress
from pathlib import Path
import pickle
import numpy as np
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

# Machine Learning imports
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Network analysis imports
try:
    import requests
    import dns.resolver
    import whois
    NETWORK_ANALYSIS_AVAILABLE = True
except ImportError:
    NETWORK_ANALYSIS_AVAILABLE = False
    # Set variables to None to avoid NameError later
    dns = None
    whois = None
    requests = None

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from django.db import models, transaction
from django.contrib.auth.models import User

from .advanced_monitoring import get_security_monitor
from .compliance_framework import get_compliance_manager
from .policy_management import get_audit_system

# Threat Intelligence Logger
threat_logger = logging.getLogger('threat_intelligence')

class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatCategory(Enum):
    """Threat categories"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    APT = "advanced_persistent_threat"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"
    SOCIAL_ENGINEERING = "social_engineering"
    RANSOMWARE = "ransomware"

class IOCType(Enum):
    """Indicator of Compromise types"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"
    REGISTRY_KEY = "registry_key"
    PROCESS_NAME = "process_name"

class ThreatSource(Enum):
    """Threat intelligence sources"""
    INTERNAL = "internal"
    OSINT = "osint"
    COMMERCIAL_FEED = "commercial_feed"
    GOVERNMENT = "government"
    COMMUNITY = "community"
    HONEYPOT = "honeypot"
    SANDBOX = "sandbox"

@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    value: str = ""
    ioc_type: IOCType = IOCType.IP_ADDRESS
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    categories: List[ThreatCategory] = field(default_factory=list)
    source: ThreatSource = ThreatSource.INTERNAL
    confidence: float = 0.5  # 0.0 to 1.0
    first_seen: datetime = field(default_factory=timezone.now)
    last_seen: datetime = field(default_factory=timezone.now)
    hit_count: int = 0
    context: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    expiry_date: Optional[datetime] = None
    false_positive: bool = False

@dataclass
class ThreatActor:
    """Threat actor profile"""
    actor_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    actor_type: str = "unknown"  # nation_state, cybercriminal, hacktivist, insider
    sophistication: str = "medium"  # low, medium, high, expert
    motivation: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    procedures: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    geographic_focus: List[str] = field(default_factory=list)
    associated_iocs: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    first_observed: datetime = field(default_factory=timezone.now)
    last_activity: datetime = field(default_factory=timezone.now)

@dataclass
class ThreatIntelligence:
    """Comprehensive threat intelligence record"""
    intel_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    categories: List[ThreatCategory] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    threat_actors: List[ThreatActor] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    source: ThreatSource = ThreatSource.INTERNAL
    confidence: float = 0.5
    created_date: datetime = field(default_factory=timezone.now)
    updated_date: datetime = field(default_factory=timezone.now)
    expiry_date: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

@dataclass
class SecurityEvent:
    """Security event for analysis"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=timezone.now)
    event_type: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    user_id: str = ""
    resource: str = ""
    action: str = ""
    outcome: str = ""
    severity: ThreatLevel = ThreatLevel.INFO
    raw_data: Dict[str, Any] = field(default_factory=dict)
    processed: bool = False
    threat_indicators: List[str] = field(default_factory=list)

class ThreatIntelligenceEngine:
    """
    Advanced Threat Intelligence Engine
    
    Collects, analyzes, and correlates threat intelligence from multiple sources
    to provide actionable security insights and automated threat detection.
    """
    
    def __init__(self):
        self.iocs = {}
        self.threat_actors = {}
        self.threat_intelligence = {}
        self.security_events = deque(maxlen=10000)
        self.ml_models = {}
        
        # Configuration
        self.config = getattr(settings, 'THREAT_INTELLIGENCE_CONFIG', {
            'IOC_RETENTION_DAYS': 365,
            'THREAT_INTEL_RETENTION_DAYS': 730,
            'AUTO_IOC_ENRICHMENT': True,
            'ML_ANOMALY_DETECTION': True,
            'REAL_TIME_CORRELATION': True,
            'THREAT_HUNTING_ENABLED': True,
            'EXTERNAL_FEEDS_ENABLED': True,
            'HONEYPOT_INTEGRATION': True,
            'YARA_RULES_ENABLED': True,
            'MITRE_ATT&CK_MAPPING': True,
        })
        
        # Threat intelligence feeds
        self.threat_feeds = {
            'abuse_ch': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            'malware_bazaar': 'https://mb-api.abuse.ch/api/v1/',
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1/',
        }
        
        # MITRE ATT&CK framework mapping
        self.mitre_tactics = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution', 
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control',
            'TA0040': 'Impact'
        }
        
        # Initialize threat intelligence engine
        self._initialize_threat_engine()
        
        threat_logger.info("Advanced Threat Intelligence Engine initialized")
    
    def _initialize_threat_engine(self):
        """Initialize threat intelligence engine components"""
        try:
            # Load existing IOCs and threat intelligence
            self._load_threat_data()
            
            # Initialize machine learning models
            if ML_AVAILABLE and self.config.get('ML_ANOMALY_DETECTION', True):
                self._initialize_ml_models()
            
            # Start background threat intelligence collection
            self._start_threat_collection()
            
            # Initialize threat hunting rules
            self._initialize_threat_hunting_rules()
            
            threat_logger.info("Threat intelligence engine components initialized")
            
        except Exception as e:
            threat_logger.error(f"Failed to initialize threat engine: {str(e)}")
    
    def _load_threat_data(self):
        """Load existing threat intelligence data"""
        try:
            # Load IOCs from cache
            cached_iocs = cache.get('threat_intelligence_iocs', {})
            self.iocs.update(cached_iocs)
            
            # Load threat actors from cache
            cached_actors = cache.get('threat_intelligence_actors', {})
            self.threat_actors.update(cached_actors)
            
            # Load threat intelligence from cache
            cached_intel = cache.get('threat_intelligence_data', {})
            self.threat_intelligence.update(cached_intel)
            
            threat_logger.info(f"Loaded {len(self.iocs)} IOCs, {len(self.threat_actors)} actors, {len(self.threat_intelligence)} intel records")
            
        except Exception as e:
            threat_logger.error(f"Failed to load threat data: {str(e)}")
    
    def _initialize_ml_models(self):
        """Initialize machine learning models for threat detection"""
        try:
            # Anomaly detection model
            self.ml_models['anomaly_detector'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Threat classification model
            self.ml_models['threat_classifier'] = RandomForestClassifier(
                n_estimators=200,
                random_state=42,
                max_depth=10
            )
            
            # Load pre-trained models if available
            self._load_pretrained_models()
            
            threat_logger.info("Machine learning models initialized")
            
        except Exception as e:
            threat_logger.error(f"Failed to initialize ML models: {str(e)}")
    
    def _load_pretrained_models(self):
        """Load pre-trained ML models"""
        try:
            model_dir = Path(settings.MEDIA_ROOT) / 'ml_models'
            model_dir.mkdir(exist_ok=True)
            
            # Load anomaly detection model
            anomaly_model_path = model_dir / 'anomaly_detector.joblib'
            if anomaly_model_path.exists():
                self.ml_models['anomaly_detector'] = joblib.load(anomaly_model_path)
                threat_logger.info("Loaded pre-trained anomaly detection model")
            
            # Load threat classification model
            classifier_model_path = model_dir / 'threat_classifier.joblib'
            if classifier_model_path.exists():
                self.ml_models['threat_classifier'] = joblib.load(classifier_model_path)
                threat_logger.info("Loaded pre-trained threat classification model")
            
        except Exception as e:
            threat_logger.error(f"Failed to load pre-trained models: {str(e)}")
    
    def _start_threat_collection(self):
        """Start background threat intelligence collection"""
        try:
            if self.config.get('EXTERNAL_FEEDS_ENABLED', True):
                collection_thread = threading.Thread(
                    target=self._threat_collection_loop,
                    name="ThreatCollection",
                    daemon=True
                )
                collection_thread.start()
                threat_logger.info("Background threat collection started")
        except Exception as e:
            threat_logger.error(f"Failed to start threat collection: {str(e)}")
    
    def _threat_collection_loop(self):
        """Background threat intelligence collection loop"""
        while True:
            try:
                # Collect from external feeds
                self._collect_external_threat_feeds()
                
                # Perform threat correlation
                if self.config.get('REAL_TIME_CORRELATION', True):
                    self._correlate_threats()
                
                # Update threat intelligence
                self._update_threat_intelligence()
                
                # Cache threat data
                self._cache_threat_data()
                
                # Sleep for collection interval
                time.sleep(3600)  # Collect every hour
                
            except Exception as e:
                threat_logger.error(f"Threat collection error: {str(e)}")
                time.sleep(3600)
    
    def _collect_external_threat_feeds(self):
        """Collect threat intelligence from external feeds"""
        try:
            if not NETWORK_ANALYSIS_AVAILABLE:
                return
            
            for feed_name, feed_url in self.threat_feeds.items():
                try:
                    # Collect from abuse.ch feeds
                    if 'abuse.ch' in feed_url:
                        self._collect_abuse_ch_feed(feed_name, feed_url)
                    
                except Exception as e:
                    threat_logger.error(f"Failed to collect from {feed_name}: {str(e)}")
            
        except Exception as e:
            threat_logger.error(f"Failed to collect external feeds: {str(e)}")
    
    def _collect_abuse_ch_feed(self, feed_name: str, feed_url: str):
        """Collect threat intelligence from abuse.ch feeds"""
        try:
            headers = {'User-Agent': 'HealthProgress-ThreatIntel/1.0'}
            
            if 'urlhaus' in feed_url:
                # URLhaus feed
                response = requests.get(feed_url, headers=headers, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    
                    for url_entry in data.get('urls', []):
                        ioc = IOC(
                            value=url_entry.get('url', ''),
                            ioc_type=IOCType.URL,
                            threat_level=self._map_threat_level(url_entry.get('threat', 'medium')),
                            categories=[ThreatCategory.MALWARE],
                            source=ThreatSource.OSINT,
                            confidence=0.8,
                            context={
                                'feed': 'urlhaus',
                                'malware_family': url_entry.get('tags', []),
                                'country': url_entry.get('country', ''),
                                'asn': url_entry.get('as', '')
                            },
                            tags=url_entry.get('tags', [])
                        )
                        
                        self._add_ioc(ioc)
            
            elif 'threatfox' in feed_url:
                # ThreatFox feed
                post_data = {"query": "get_iocs", "days": 1}
                response = requests.post(feed_url, json=post_data, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for ioc_entry in data.get('data', []):
                        ioc_type_mapping = {
                            'ip:port': IOCType.IP_ADDRESS,
                            'domain': IOCType.DOMAIN,
                            'url': IOCType.URL,
                            'md5_hash': IOCType.FILE_HASH,
                            'sha1_hash': IOCType.FILE_HASH,
                            'sha256_hash': IOCType.FILE_HASH
                        }
                        
                        ioc = IOC(
                            value=ioc_entry.get('ioc', ''),
                            ioc_type=ioc_type_mapping.get(ioc_entry.get('ioc_type', ''), IOCType.IP_ADDRESS),
                            threat_level=self._map_threat_level(ioc_entry.get('threat_type', 'medium')),
                            categories=[ThreatCategory.MALWARE],
                            source=ThreatSource.OSINT,
                            confidence=float(ioc_entry.get('confidence_level', 50)) / 100,
                            context={
                                'feed': 'threatfox',
                                'malware_family': ioc_entry.get('malware', ''),
                                'reference': ioc_entry.get('reference', '')
                            },
                            tags=ioc_entry.get('tags', [])
                        )
                        
                        self._add_ioc(ioc)
            
            threat_logger.info(f"Successfully collected from {feed_name}")
            
        except Exception as e:
            threat_logger.error(f"Failed to collect from {feed_name}: {str(e)}")
    
    def _map_threat_level(self, threat_string: str) -> ThreatLevel:
        """Map threat level string to enum"""
        threat_mapping = {
            'info': ThreatLevel.INFO,
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL,
            'malware_download': ThreatLevel.HIGH,
            'c2': ThreatLevel.HIGH,
            'botnet_cc': ThreatLevel.HIGH
        }
        
        return threat_mapping.get(threat_string.lower(), ThreatLevel.MEDIUM)
    
    def _add_ioc(self, ioc: IOC):
        """Add IOC to intelligence database"""
        try:
            # Check if IOC already exists
            existing_ioc = None
            for existing_id, existing in self.iocs.items():
                if existing.value == ioc.value and existing.ioc_type == ioc.ioc_type:
                    existing_ioc = existing
                    break
            
            if existing_ioc:
                # Update existing IOC
                existing_ioc.last_seen = timezone.now()
                existing_ioc.hit_count += 1
                existing_ioc.confidence = max(existing_ioc.confidence, ioc.confidence)
                
                # Merge context and tags
                existing_ioc.context.update(ioc.context)
                existing_ioc.tags.extend([tag for tag in ioc.tags if tag not in existing_ioc.tags])
                
            else:
                # Add new IOC
                self.iocs[ioc.ioc_id] = ioc
                
                # Perform IOC enrichment
                if self.config.get('AUTO_IOC_ENRICHMENT', True):
                    self._enrich_ioc(ioc)
            
        except Exception as e:
            threat_logger.error(f"Failed to add IOC: {str(e)}")
    
    def _enrich_ioc(self, ioc: IOC):
        """Enrich IOC with additional threat intelligence"""
        try:
            if not NETWORK_ANALYSIS_AVAILABLE:
                return
            
            # Enrich IP addresses
            if ioc.ioc_type == IOCType.IP_ADDRESS:
                self._enrich_ip_address(ioc)
            
            # Enrich domains
            elif ioc.ioc_type == IOCType.DOMAIN:
                self._enrich_domain(ioc)
            
            # Enrich URLs
            elif ioc.ioc_type == IOCType.URL:
                self._enrich_url(ioc)
            
        except Exception as e:
            threat_logger.error(f"Failed to enrich IOC {ioc.ioc_id}: {str(e)}")
    
    def _enrich_ip_address(self, ioc: IOC):
        """Enrich IP address IOC"""
        try:
            ip = ipaddress.ip_address(ioc.value)
            
            # Check if it's a private IP
            if ip.is_private:
                ioc.context['ip_type'] = 'private'
                ioc.threat_level = ThreatLevel.LOW
            else:
                ioc.context['ip_type'] = 'public'
                
                # Try to get geolocation and ASN info
                # This would typically use a GeoIP service
                ioc.context['geolocation_attempted'] = True
            
        except Exception as e:
            threat_logger.error(f"Failed to enrich IP address: {str(e)}")
    
    def _enrich_domain(self, ioc: IOC):
        """Enrich domain IOC"""
        try:
            domain = ioc.value
            
            # Check domain age and registration info
            if whois is not None:
                try:
                    domain_info = whois.whois(domain)
                    if domain_info.creation_date:
                        creation_date = domain_info.creation_date
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        
                        domain_age = (timezone.now() - creation_date).days
                        ioc.context['domain_age_days'] = domain_age
                        
                        # Young domains are more suspicious
                        if domain_age < 30:
                            ioc.confidence = min(ioc.confidence + 0.2, 1.0)
                            ioc.tags.append('newly_registered')
                    
                except Exception:
                    pass
            else:
                ioc.context['whois_not_available'] = True
            
            # DNS resolution check
            if dns is not None:
                try:
                    resolver = dns.resolver.Resolver()
                    answers = resolver.resolve(domain, 'A')
                    ips = [str(answer) for answer in answers]
                    ioc.context['resolved_ips'] = ips
                except Exception:
                    ioc.context['dns_resolution_failed'] = True
            else:
                ioc.context['dns_not_available'] = True
            
        except Exception as e:
            threat_logger.error(f"Failed to enrich domain: {str(e)}")
        except Exception as e:
            threat_logger.error(f"Failed to enrich domain: {str(e)}")
    
    def _enrich_url(self, ioc: IOC):
        """Enrich URL IOC"""
        try:
            from urllib.parse import urlparse
            
            parsed_url = urlparse(ioc.value)
            
            # Extract domain for further analysis
            domain = parsed_url.netloc
            if domain:
                # Create domain IOC if it doesn't exist
                domain_ioc = IOC(
                    value=domain,
                    ioc_type=IOCType.DOMAIN,
                    threat_level=ioc.threat_level,
                    categories=ioc.categories,
                    source=ioc.source,
                    confidence=ioc.confidence * 0.8,  # Slightly lower confidence
                    context={'derived_from_url': ioc.value}
                )
                
                self._add_ioc(domain_ioc)
            
            # Analyze URL structure for suspicious patterns
            suspicious_patterns = [
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP in URL
                r'[a-z0-9]{32}',  # MD5-like strings
                r'[a-z0-9]{40}',  # SHA1-like strings
                r'\.tk$|\.ml$|\.ga$|\.cf$',  # Suspicious TLDs
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, ioc.value, re.IGNORECASE):
                    ioc.confidence = min(ioc.confidence + 0.1, 1.0)
                    ioc.tags.append('suspicious_pattern')
                    break
            
        except Exception as e:
            threat_logger.error(f"Failed to enrich URL: {str(e)}")
    
    def _correlate_threats(self):
        """Correlate threats across different indicators and events"""
        try:
            # Correlate IOCs with recent security events
            self._correlate_iocs_with_events()
            
            # Identify threat actor patterns
            self._identify_threat_actor_patterns()
            
            # Detect attack campaigns
            self._detect_attack_campaigns()
            
        except Exception as e:
            threat_logger.error(f"Failed to correlate threats: {str(e)}")
    
    def _correlate_iocs_with_events(self):
        """Correlate IOCs with recent security events"""
        try:
            for event in list(self.security_events):
                if event.processed:
                    continue
                
                # Check if event matches any IOCs
                matches = []
                
                # Check source IP
                if event.source_ip:
                    for ioc in self.iocs.values():
                        if (ioc.ioc_type == IOCType.IP_ADDRESS and 
                            ioc.value == event.source_ip):
                            matches.append(ioc.ioc_id)
                
                # Check destination IP
                if event.destination_ip:
                    for ioc in self.iocs.values():
                        if (ioc.ioc_type == IOCType.IP_ADDRESS and 
                            ioc.value == event.destination_ip):
                            matches.append(ioc.ioc_id)
                
                # Check resource/URL
                if event.resource:
                    for ioc in self.iocs.values():
                        if (ioc.ioc_type in [IOCType.URL, IOCType.DOMAIN] and 
                            ioc.value in event.resource):
                            matches.append(ioc.ioc_id)
                
                if matches:
                    event.threat_indicators = matches
                    event.severity = ThreatLevel.HIGH
                    
                    # Create threat intelligence record
                    self._create_threat_intelligence_from_correlation(event, matches)
                
                event.processed = True
            
        except Exception as e:
            threat_logger.error(f"Failed to correlate IOCs with events: {str(e)}")
    
    def _identify_threat_actor_patterns(self):
        """Identify patterns that may indicate specific threat actors"""
        try:
            # Group IOCs by source and timing
            temporal_groups = defaultdict(list)
            
            for ioc in self.iocs.values():
                # Group by hour for pattern detection
                time_key = ioc.first_seen.strftime('%Y-%m-%d-%H')
                temporal_groups[time_key].append(ioc)
            
            # Analyze groups for threat actor signatures
            for time_key, iocs in temporal_groups.items():
                if len(iocs) >= 5:  # Threshold for actor identification
                    self._analyze_threat_actor_signature(iocs, time_key)
            
        except Exception as e:
            threat_logger.error(f"Failed to identify threat actor patterns: {str(e)}")
    
    def _analyze_threat_actor_signature(self, iocs: List[IOC], time_key: str):
        """Analyze IOCs for threat actor signature"""
        try:
            # Analyze IOC characteristics
            ip_count = len([ioc for ioc in iocs if ioc.ioc_type == IOCType.IP_ADDRESS])
            domain_count = len([ioc for ioc in iocs if ioc.ioc_type == IOCType.DOMAIN])
            url_count = len([ioc for ioc in iocs if ioc.ioc_type == IOCType.URL])
            
            # Extract common tags and categories
            all_tags = []
            all_categories = []
            
            for ioc in iocs:
                all_tags.extend(ioc.tags)
                all_categories.extend([cat.value for cat in ioc.categories])
            
            common_tags = [tag for tag in set(all_tags) if all_tags.count(tag) >= 2]
            common_categories = [cat for cat in set(all_categories) if all_categories.count(cat) >= 2]
            
            # Create threat actor profile if patterns detected
            if len(common_tags) >= 2 or len(common_categories) >= 2:
                actor = ThreatActor(
                    name=f"Unknown Actor {time_key}",
                    actor_type="unknown",
                    tactics=common_tags[:5],
                    associated_iocs=[ioc.ioc_id for ioc in iocs],
                    target_sectors=["healthcare"],  # Our application domain
                    first_observed=min(ioc.first_seen for ioc in iocs),
                    last_activity=max(ioc.last_seen for ioc in iocs)
                )
                
                self.threat_actors[actor.actor_id] = actor
                
                threat_logger.info(f"Identified potential threat actor: {actor.name}")
            
        except Exception as e:
            threat_logger.error(f"Failed to analyze threat actor signature: {str(e)}")
    
    def _detect_attack_campaigns(self):
        """Detect coordinated attack campaigns"""
        try:
            # Group IOCs by similar attributes
            campaign_groups = defaultdict(list)
            
            for ioc in self.iocs.values():
                # Group by malware family tags
                for tag in ioc.tags:
                    if any(malware in tag.lower() for malware in ['ransomware', 'trojan', 'botnet', 'apt']):
                        campaign_groups[tag].append(ioc)
            
            # Analyze each potential campaign
            for campaign_tag, campaign_iocs in campaign_groups.items():
                if len(campaign_iocs) >= 3:  # Minimum IOCs for campaign
                    self._create_campaign_intelligence(campaign_tag, campaign_iocs)
            
        except Exception as e:
            threat_logger.error(f"Failed to detect attack campaigns: {str(e)}")
    
    def _create_campaign_intelligence(self, campaign_tag: str, iocs: List[IOC]):
        """Create threat intelligence for detected campaign"""
        try:
            intel = ThreatIntelligence(
                title=f"Campaign: {campaign_tag}",
                description=f"Detected attack campaign with {len(iocs)} indicators",
                threat_level=ThreatLevel.HIGH,
                categories=[ThreatCategory.APT],
                iocs=iocs,
                attack_vectors=list(set([tag for ioc in iocs for tag in ioc.tags])),
                source=ThreatSource.INTERNAL,
                confidence=0.8,
                tags=[campaign_tag, 'campaign', 'automated_detection']
            )
            
            self.threat_intelligence[intel.intel_id] = intel
            
            threat_logger.warning(f"Detected attack campaign: {campaign_tag}")
            
        except Exception as e:
            threat_logger.error(f"Failed to create campaign intelligence: {str(e)}")
    
    def _create_threat_intelligence_from_correlation(self, event: SecurityEvent, ioc_matches: List[str]):
        """Create threat intelligence from IOC correlation"""
        try:
            matched_iocs = [self.iocs[ioc_id] for ioc_id in ioc_matches if ioc_id in self.iocs]
            
            if not matched_iocs:
                return
            
            # Determine threat level based on matched IOCs
            max_threat_level = max(ioc.threat_level for ioc in matched_iocs)
            
            intel = ThreatIntelligence(
                title=f"Threat Detection: {event.event_type}",
                description=f"Security event correlated with {len(matched_iocs)} threat indicators",
                threat_level=max_threat_level,
                categories=list(set([cat for ioc in matched_iocs for cat in ioc.categories])),
                iocs=matched_iocs,
                affected_systems=[event.resource] if event.resource else [],
                source=ThreatSource.INTERNAL,
                confidence=0.9,
                tags=['correlation', 'real_time_detection', event.event_type]
            )
            
            self.threat_intelligence[intel.intel_id] = intel
            
            threat_logger.warning(f"Created threat intelligence from correlation: {intel.intel_id}")
            
        except Exception as e:
            threat_logger.error(f"Failed to create correlation intelligence: {str(e)}")
    
    def _initialize_threat_hunting_rules(self):
        """Initialize threat hunting rules"""
        try:
            self.hunting_rules = {
                'suspicious_login_patterns': {
                    'description': 'Detect suspicious login patterns',
                    'conditions': {
                        'failed_logins_threshold': 10,
                        'time_window_minutes': 5,
                        'geographic_anomaly': True
                    }
                },
                'data_exfiltration_indicators': {
                    'description': 'Detect potential data exfiltration',
                    'conditions': {
                        'large_data_transfer': True,
                        'unusual_time': True,
                        'external_destination': True
                    }
                },
                'malware_communication': {
                    'description': 'Detect malware command and control communication',
                    'conditions': {
                        'known_c2_domains': True,
                        'suspicious_user_agents': True,
                        'encrypted_traffic_anomalies': True
                    }
                }
            }
            
            threat_logger.info(f"Initialized {len(self.hunting_rules)} threat hunting rules")
            
        except Exception as e:
            threat_logger.error(f"Failed to initialize hunting rules: {str(e)}")
    
    def _update_threat_intelligence(self):
        """Update threat intelligence with latest analysis"""
        try:
            # Clean up expired IOCs
            current_time = timezone.now()
            expired_iocs = []
            
            for ioc_id, ioc in self.iocs.items():
                if ioc.expiry_date and ioc.expiry_date < current_time:
                    expired_iocs.append(ioc_id)
                elif (current_time - ioc.last_seen).days > self.config.get('IOC_RETENTION_DAYS', 365):
                    expired_iocs.append(ioc_id)
            
            for ioc_id in expired_iocs:
                del self.iocs[ioc_id]
            
            if expired_iocs:
                threat_logger.info(f"Cleaned up {len(expired_iocs)} expired IOCs")
            
            # Update threat intelligence records
            expired_intel = []
            
            for intel_id, intel in self.threat_intelligence.items():
                if intel.expiry_date and intel.expiry_date < current_time:
                    expired_intel.append(intel_id)
                elif (current_time - intel.updated_date).days > self.config.get('THREAT_INTEL_RETENTION_DAYS', 730):
                    expired_intel.append(intel_id)
            
            for intel_id in expired_intel:
                del self.threat_intelligence[intel_id]
            
            if expired_intel:
                threat_logger.info(f"Cleaned up {len(expired_intel)} expired intelligence records")
            
        except Exception as e:
            threat_logger.error(f"Failed to update threat intelligence: {str(e)}")
    
    def _cache_threat_data(self):
        """Cache threat intelligence data"""
        try:
            # Cache IOCs
            cache.set('threat_intelligence_iocs', self.iocs, 86400)  # 24 hours
            
            # Cache threat actors
            cache.set('threat_intelligence_actors', self.threat_actors, 86400)
            
            # Cache threat intelligence
            cache.set('threat_intelligence_data', self.threat_intelligence, 86400)
            
        except Exception as e:
            threat_logger.error(f"Failed to cache threat data: {str(e)}")
    
    def analyze_security_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Analyze security event for threats"""
        try:
            analysis = {
                'event_id': event.event_id,
                'threat_level': event.severity.value,
                'threat_indicators': [],
                'recommended_actions': [],
                'related_intelligence': [],
                'ml_prediction': None,
                'confidence_score': 0.0
            }
            
            # Check against IOCs
            ioc_matches = []
            
            # Check IP addresses
            for ip_field in [event.source_ip, event.destination_ip]:
                if ip_field:
                    for ioc in self.iocs.values():
                        if ioc.ioc_type == IOCType.IP_ADDRESS and ioc.value == ip_field:
                            ioc_matches.append(ioc)
            
            # Check resource/URL
            if event.resource:
                for ioc in self.iocs.values():
                    if ioc.ioc_type in [IOCType.URL, IOCType.DOMAIN] and ioc.value in event.resource:
                        ioc_matches.append(ioc)
            
            if ioc_matches:
                analysis['threat_indicators'] = [
                    {
                        'ioc_id': ioc.ioc_id,
                        'value': ioc.value,
                        'type': ioc.ioc_type.value,
                        'threat_level': ioc.threat_level.value,
                        'confidence': ioc.confidence
                    }
                    for ioc in ioc_matches
                ]
                
                # Update threat level based on matches
                max_threat = max(ioc.threat_level for ioc in ioc_matches)
                if max_threat.value > event.severity.value:
                    analysis['threat_level'] = max_threat.value
                
                # Generate recommendations
                analysis['recommended_actions'] = self._generate_threat_recommendations(ioc_matches)
            
            # Machine learning analysis
            if ML_AVAILABLE and 'anomaly_detector' in self.ml_models:
                ml_result = self._ml_threat_analysis(event)
                analysis['ml_prediction'] = ml_result
            
            # Calculate overall confidence
            if ioc_matches:
                analysis['confidence_score'] = sum(ioc.confidence for ioc in ioc_matches) / len(ioc_matches)
            
            # Add event to processing queue
            self.security_events.append(event)
            
            return analysis
            
        except Exception as e:
            threat_logger.error(f"Failed to analyze security event: {str(e)}")
            return {'error': str(e)}
    
    def _generate_threat_recommendations(self, iocs: List[IOC]) -> List[str]:
        """Generate threat response recommendations"""
        recommendations = []
        
        threat_levels = [ioc.threat_level for ioc in iocs]
        categories = [cat for ioc in iocs for cat in ioc.categories]
        
        # High/Critical threats
        if any(level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL] for level in threat_levels):
            recommendations.extend([
                "Immediately isolate affected systems",
                "Conduct forensic analysis",
                "Review and update security controls"
            ])
        
        # Category-specific recommendations
        if ThreatCategory.MALWARE in categories:
            recommendations.extend([
                "Run full antivirus scan",
                "Check for lateral movement",
                "Update malware signatures"
            ])
        
        if ThreatCategory.PHISHING in categories:
            recommendations.extend([
                "Block malicious domains/URLs",
                "Notify affected users",
                "Review email security policies"
            ])
        
        if ThreatCategory.BRUTE_FORCE in categories:
            recommendations.extend([
                "Implement account lockout policies",
                "Enable multi-factor authentication",
                "Monitor authentication logs"
            ])
        
        return recommendations[:5]  # Return top 5 recommendations
    
    def _ml_threat_analysis(self, event: SecurityEvent) -> Dict[str, Any]:
        """Perform machine learning threat analysis"""
        try:
            # Convert event to feature vector
            features = self._extract_event_features(event)
            
            if not features:
                return {'error': 'Could not extract features'}
            
            # Anomaly detection
            anomaly_score = self.ml_models['anomaly_detector'].decision_function([features])[0]
            is_anomaly = self.ml_models['anomaly_detector'].predict([features])[0] == -1
            
            # Threat classification (if model is trained)
            threat_prediction = None
            if hasattr(self.ml_models['threat_classifier'], 'classes_'):
                threat_prediction = self.ml_models['threat_classifier'].predict_proba([features])[0]
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': bool(is_anomaly),
                'threat_prediction': threat_prediction.tolist() if threat_prediction is not None else None,
                'model_confidence': 0.8 if is_anomaly else 0.3
            }
            
        except Exception as e:
            threat_logger.error(f"ML threat analysis failed: {str(e)}")
            return {'error': str(e)}
    
    def _extract_event_features(self, event: SecurityEvent) -> List[float]:
        """Extract numerical features from security event"""
        try:
            features = []
            
            # Time-based features
            hour = event.timestamp.hour
            day_of_week = event.timestamp.weekday()
            features.extend([hour, day_of_week])
            
            # Event type encoding
            event_types = ['login', 'access', 'modify', 'delete', 'create', 'error']
            event_type_encoded = [1.0 if et in event.event_type.lower() else 0.0 for et in event_types]
            features.extend(event_type_encoded)
            
            # Outcome encoding
            success_outcome = 1.0 if 'success' in event.outcome.lower() else 0.0
            features.append(success_outcome)
            
            # IP address features (if available)
            if event.source_ip:
                try:
                    ip = ipaddress.ip_address(event.source_ip)
                    is_private = 1.0 if ip.is_private else 0.0
                    features.append(is_private)
                except:
                    features.append(0.0)
            else:
                features.append(0.0)
            
            # Resource length (proxy for complexity)
            resource_length = len(event.resource) if event.resource else 0
            features.append(float(resource_length))
            
            # Pad or trim to fixed size
            target_size = 12
            if len(features) < target_size:
                features.extend([0.0] * (target_size - len(features)))
            else:
                features = features[:target_size]
            
            return features
            
        except Exception as e:
            threat_logger.error(f"Feature extraction failed: {str(e)}")
            return []
    
    def hunt_threats(self, hunt_rules: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform proactive threat hunting"""
        try:
            hunt_results = {
                'hunt_timestamp': timezone.now().isoformat(),
                'rules_executed': [],
                'threats_found': [],
                'recommendations': [],
                'total_events_analyzed': len(self.security_events)
            }
            
            rules_to_execute = hunt_rules or list(self.hunting_rules.keys())
            
            for rule_name in rules_to_execute:
                if rule_name not in self.hunting_rules:
                    continue
                
                rule = self.hunting_rules[rule_name]
                hunt_results['rules_executed'].append(rule_name)
                
                # Execute hunting rule
                rule_results = self._execute_hunting_rule(rule_name, rule)
                
                if rule_results['threats_found']:
                    hunt_results['threats_found'].extend(rule_results['threats_found'])
                    hunt_results['recommendations'].extend(rule_results['recommendations'])
            
            threat_logger.info(f"Threat hunting completed: {len(hunt_results['threats_found'])} threats found")
            
            return hunt_results
            
        except Exception as e:
            threat_logger.error(f"Threat hunting failed: {str(e)}")
            return {'error': str(e)}
    
    def _execute_hunting_rule(self, rule_name: str, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Execute specific hunting rule"""
        try:
            results = {
                'rule_name': rule_name,
                'threats_found': [],
                'recommendations': []
            }
            
            # Suspicious login patterns
            if rule_name == 'suspicious_login_patterns':
                login_events = [e for e in self.security_events if 'login' in e.event_type.lower()]
                
                # Group by source IP and time window
                ip_groups = defaultdict(list)
                for event in login_events:
                    if event.source_ip:
                        ip_groups[event.source_ip].append(event)
                
                # Check for brute force patterns
                for ip, events in ip_groups.items():
                    failed_events = [e for e in events if 'fail' in e.outcome.lower()]
                    
                    if len(failed_events) >= rule['conditions']['failed_logins_threshold']:
                        threat = {
                            'type': 'brute_force_detected',
                            'source_ip': ip,
                            'failed_attempts': len(failed_events),
                            'time_range': f"{min(e.timestamp for e in failed_events)} - {max(e.timestamp for e in failed_events)}"
                        }
                        
                        results['threats_found'].append(threat)
                        results['recommendations'].extend([
                            f"Block IP address {ip}",
                            "Enable account lockout policies",
                            "Implement rate limiting"
                        ])
            
            # Data exfiltration indicators
            elif rule_name == 'data_exfiltration_indicators':
                # Look for large data transfers or unusual access patterns
                access_events = [e for e in self.security_events if 'access' in e.event_type.lower()]
                
                # Check for unusual time access (outside business hours)
                for event in access_events:
                    if event.timestamp.hour < 6 or event.timestamp.hour > 22:
                        threat = {
                            'type': 'unusual_time_access',
                            'user_id': event.user_id,
                            'resource': event.resource,
                            'timestamp': event.timestamp.isoformat()
                        }
                        
                        results['threats_found'].append(threat)
                        results['recommendations'].append(f"Investigate user {event.user_id} access patterns")
            
            # Malware communication
            elif rule_name == 'malware_communication':
                # Check network events against known C2 domains
                network_events = [e for e in self.security_events if 'network' in e.event_type.lower()]
                
                for event in network_events:
                    # Check against IOCs
                    for ioc in self.iocs.values():
                        if (ioc.ioc_type in [IOCType.DOMAIN, IOCType.IP_ADDRESS] and
                            ThreatCategory.MALWARE in ioc.categories and
                            ioc.value in (event.resource or '')):
                            
                            threat = {
                                'type': 'malware_c2_communication',
                                'destination': ioc.value,
                                'ioc_confidence': ioc.confidence,
                                'event_id': event.event_id
                            }
                            
                            results['threats_found'].append(threat)
                            results['recommendations'].extend([
                                f"Block communication to {ioc.value}",
                                "Investigate affected systems for malware",
                                "Update network security rules"
                            ])
            
            return results
            
        except Exception as e:
            threat_logger.error(f"Failed to execute hunting rule {rule_name}: {str(e)}")
            return {'rule_name': rule_name, 'threats_found': [], 'recommendations': [], 'error': str(e)}
    
    def get_threat_intelligence_summary(self) -> Dict[str, Any]:
        """Get comprehensive threat intelligence summary"""
        try:
            # IOC statistics
            ioc_stats = {
                'total_iocs': len(self.iocs),
                'by_type': {},
                'by_threat_level': {},
                'by_source': {},
                'active_iocs': 0
            }
            
            for ioc in self.iocs.values():
                # Count by type
                ioc_type = ioc.ioc_type.value
                ioc_stats['by_type'][ioc_type] = ioc_stats['by_type'].get(ioc_type, 0) + 1
                
                # Count by threat level
                threat_level = ioc.threat_level.value
                ioc_stats['by_threat_level'][threat_level] = ioc_stats['by_threat_level'].get(threat_level, 0) + 1
                
                # Count by source
                source = ioc.source.value
                ioc_stats['by_source'][source] = ioc_stats['by_source'].get(source, 0) + 1
                
                # Count active IOCs (seen in last 7 days)
                if (timezone.now() - ioc.last_seen).days <= 7:
                    ioc_stats['active_iocs'] += 1
            
            # Threat actor statistics
            actor_stats = {
                'total_actors': len(self.threat_actors),
                'by_type': {},
                'by_sophistication': {},
                'active_actors': 0
            }
            
            for actor in self.threat_actors.values():
                # Count by type
                actor_stats['by_type'][actor.actor_type] = actor_stats['by_type'].get(actor.actor_type, 0) + 1
                
                # Count by sophistication
                actor_stats['by_sophistication'][actor.sophistication] = actor_stats['by_sophistication'].get(actor.sophistication, 0) + 1
                
                # Count active actors (activity in last 30 days)
                if (timezone.now() - actor.last_activity).days <= 30:
                    actor_stats['active_actors'] += 1
            
            # Threat intelligence statistics
            intel_stats = {
                'total_intelligence': len(self.threat_intelligence),
                'by_category': {},
                'by_threat_level': {},
                'recent_intelligence': 0
            }
            
            for intel in self.threat_intelligence.values():
                # Count by category
                for category in intel.categories:
                    cat_name = category.value
                    intel_stats['by_category'][cat_name] = intel_stats['by_category'].get(cat_name, 0) + 1
                
                # Count by threat level
                threat_level = intel.threat_level.value
                intel_stats['by_threat_level'][threat_level] = intel_stats['by_threat_level'].get(threat_level, 0) + 1
                
                # Count recent intelligence (last 7 days)
                if (timezone.now() - intel.created_date).days <= 7:
                    intel_stats['recent_intelligence'] += 1
            
            # Overall summary
            summary = {
                'last_updated': timezone.now().isoformat(),
                'ioc_statistics': ioc_stats,
                'threat_actor_statistics': actor_stats,
                'intelligence_statistics': intel_stats,
                'recent_events_processed': len([e for e in self.security_events if e.processed]),
                'ml_models_available': ML_AVAILABLE and bool(self.ml_models),
                'external_feeds_active': NETWORK_ANALYSIS_AVAILABLE and self.config.get('EXTERNAL_FEEDS_ENABLED', True),
                'hunting_rules_configured': len(self.hunting_rules)
            }
            
            return summary
            
        except Exception as e:
            threat_logger.error(f"Failed to get threat intelligence summary: {str(e)}")
            return {'error': str(e)}
    
    def check_ip_reputation(self, ip_address: str) -> Optional[IOC]:
        """
        Check IP address reputation against IOC database
        
        Args:
            ip_address: IP address to check
            
        Returns:
            IOC object if found, None otherwise
        """
        try:
            # Look for IP in IOC database
            for ioc in self.iocs.values():
                if ioc.ioc_type == IOCType.IP_ADDRESS and ioc.value == ip_address:
                    threat_logger.info(f"IP reputation check: {ip_address} found in IOC database")
                    return ioc
            
            # If not found in local database, return None (clean reputation)
            threat_logger.info(f"IP reputation check: {ip_address} not found in IOC database (clean)")
            return None
            
        except Exception as e:
            threat_logger.error(f"Failed to check IP reputation: {str(e)}")
            return None


# Global threat intelligence engine instance
_global_threat_engine = None

def get_threat_intelligence_engine() -> ThreatIntelligenceEngine:
    """Get global threat intelligence engine instance"""
    global _global_threat_engine
    if _global_threat_engine is None:
        _global_threat_engine = ThreatIntelligenceEngine()
    return _global_threat_engine