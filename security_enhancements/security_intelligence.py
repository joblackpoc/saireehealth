"""
Phase 7: Advanced Security Monitoring & Intelligence
Security Intelligence Engine, Threat Hunting, ML Anomaly Detection, SOAR Integration

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
Component: Security Intelligence & Monitoring Platform
"""
import os
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import threading
import time
import hashlib
import statistics
from collections import deque, defaultdict
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
import logging
import pickle
import base64
import requests
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib

# Enhanced Security Logging
security_logger = logging.getLogger('security_core')

class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

class IncidentStatus(Enum):
    """Security incident status enumeration"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    event_type: str
    timestamp: datetime
    source_ip: str
    user_id: Optional[int]
    severity: ThreatLevel
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[str] = None
    threat_indicators: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None

@dataclass
class SecurityIncident:
    """Security incident data structure"""
    incident_id: str
    title: str
    description: str
    severity: ThreatLevel
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str]
    events: List[SecurityEvent] = field(default_factory=list)
    indicators_of_compromise: List[str] = field(default_factory=list)
    response_actions: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

class SecurityIntelligenceEngine:
    """
    Advanced Security Intelligence Engine
    Central hub for threat detection, correlation, and analysis
    """
    
    def __init__(self):
        self.event_buffer = deque(maxlen=10000)  # Ring buffer for recent events
        self.correlation_rules = []
        self.threat_indicators = defaultdict(list)
        self.active_incidents = {}
        
        # ML models for anomaly detection
        self.anomaly_models = {}
        self.feature_scalers = {}
        
        # Configuration
        self.correlation_window = getattr(settings, 'SECURITY_CORRELATION_WINDOW', 300)  # 5 minutes
        self.threat_threshold = getattr(settings, 'THREAT_DETECTION_THRESHOLD', 75)
        self.ml_enabled = getattr(settings, 'ML_SECURITY_ENABLED', True)
        
        # Initialize ML models
        if self.ml_enabled:
            self._initialize_ml_models()
        
        # Start background correlation engine
        self._start_correlation_engine()
    
    def ingest_security_event(self, event_data: Dict[str, Any]) -> SecurityEvent:
        """Ingest and process security event"""
        try:
            # Create security event
            event = SecurityEvent(
                event_id=event_data.get('event_id', self._generate_event_id()),
                event_type=event_data['event_type'],
                timestamp=datetime.fromisoformat(event_data.get('timestamp', timezone.now().isoformat())),
                source_ip=event_data['source_ip'],
                user_id=event_data.get('user_id'),
                severity=ThreatLevel(event_data.get('severity', ThreatLevel.LOW.value)),
                description=event_data['description'],
                metadata=event_data.get('metadata', {}),
                raw_data=event_data.get('raw_data'),
                threat_indicators=event_data.get('threat_indicators', [])
            )
            
            # Add to event buffer
            self.event_buffer.append(event)
            
            # Enrich event with threat intelligence
            enriched_event = self._enrich_event_with_threat_intel(event)
            
            # Real-time threat scoring
            threat_score = self._calculate_threat_score(enriched_event)
            enriched_event.metadata['threat_score'] = threat_score
            
            # ML-based anomaly detection
            if self.ml_enabled:
                anomaly_score = self._detect_anomalies(enriched_event)
                enriched_event.metadata['anomaly_score'] = anomaly_score
            
            # Store event for correlation
            self._store_event_for_correlation(enriched_event)
            
            # Trigger immediate analysis for high-severity events
            if enriched_event.severity.value >= ThreatLevel.HIGH.value:
                self._trigger_immediate_analysis(enriched_event)
            
            security_logger.info(f"Security event ingested: {event.event_id} - {event.event_type}")
            return enriched_event
            
        except Exception as e:
            security_logger.error(f"Security event ingestion failed: {str(e)}")
            raise
    
    def correlate_events(self, time_window_minutes: int = 5) -> List[Dict[str, Any]]:
        """Correlate security events to identify patterns and threats"""
        try:
            correlations = []
            current_time = timezone.now()
            cutoff_time = current_time - timedelta(minutes=time_window_minutes)
            
            # Get recent events
            recent_events = [
                event for event in self.event_buffer
                if event.timestamp >= cutoff_time
            ]
            
            # Group events by various criteria
            correlations.extend(self._correlate_by_source_ip(recent_events))
            correlations.extend(self._correlate_by_user_id(recent_events))
            correlations.extend(self._correlate_by_event_pattern(recent_events))
            correlations.extend(self._correlate_by_threat_indicators(recent_events))
            
            # Advanced correlation using ML
            if self.ml_enabled and len(recent_events) > 5:
                ml_correlations = self._ml_based_correlation(recent_events)
                correlations.extend(ml_correlations)
            
            # Filter and prioritize correlations
            significant_correlations = [
                corr for corr in correlations
                if corr.get('confidence', 0) >= 70
            ]
            
            security_logger.info(f"Event correlation completed: {len(significant_correlations)} significant correlations found")
            return significant_correlations
            
        except Exception as e:
            security_logger.error(f"Event correlation failed: {str(e)}")
            return []
    
    def create_security_incident(self, correlation_data: Dict[str, Any], 
                               events: List[SecurityEvent]) -> SecurityIncident:
        """Create security incident from correlated events"""
        try:
            incident_id = self._generate_incident_id()
            
            # Determine incident severity
            max_event_severity = max(event.severity for event in events)
            incident_severity = self._escalate_severity_for_correlation(max_event_severity, correlation_data)
            
            # Generate incident title and description
            title = self._generate_incident_title(correlation_data, events)
            description = self._generate_incident_description(correlation_data, events)
            
            # Extract indicators of compromise
            iocs = self._extract_indicators_of_compromise(events)
            
            incident = SecurityIncident(
                incident_id=incident_id,
                title=title,
                description=description,
                severity=incident_severity,
                status=IncidentStatus.NEW,
                created_at=timezone.now(),
                updated_at=timezone.now(),
                assigned_to=None,
                events=events,
                indicators_of_compromise=iocs,
                response_actions=[],
                timeline=[{
                    'timestamp': timezone.now().isoformat(),
                    'action': 'incident_created',
                    'description': f'Incident created from {len(events)} correlated events'
                }]
            )
            
            # Store incident
            self.active_incidents[incident_id] = incident
            
            # Cache incident for persistence
            incident_key = f"security_incident_{incident_id}"
            incident_data = self._serialize_incident(incident)
            cache.set(incident_key, incident_data, 86400 * 30)  # 30 days
            
            security_logger.warning(f"Security incident created: {incident_id} - {title}")
            return incident
            
        except Exception as e:
            security_logger.error(f"Security incident creation failed: {str(e)}")
            raise
    
    def _initialize_ml_models(self):
        """Initialize machine learning models for anomaly detection"""
        try:
            # Isolation Forest for outlier detection
            self.anomaly_models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # DBSCAN for clustering analysis
            self.anomaly_models['dbscan'] = DBSCAN(
                eps=0.5,
                min_samples=5
            )
            
            # Feature scalers
            self.feature_scalers['standard'] = StandardScaler()
            
            # Load pre-trained models if available
            try:
                model_path = getattr(settings, 'ML_SECURITY_MODEL_PATH', 'security_ml_models/')
                if hasattr(settings, 'BASE_DIR'):
                    model_path = settings.BASE_DIR / model_path
                
                for model_name in ['isolation_forest', 'dbscan']:
                    model_file = f"{model_path}/{model_name}.joblib"
                    if os.path.exists(model_file):
                        self.anomaly_models[model_name] = joblib.load(model_file)
                        security_logger.info(f"Loaded pre-trained model: {model_name}")
                        
            except Exception as model_load_error:
                security_logger.warning(f"Could not load pre-trained models: {str(model_load_error)}")
            
            security_logger.info("ML models initialized for security intelligence")
            
        except Exception as e:
            security_logger.error(f"ML model initialization failed: {str(e)}")
            self.ml_enabled = False
    
    def _enrich_event_with_threat_intel(self, event: SecurityEvent) -> SecurityEvent:
        """Enrich event with external threat intelligence"""
        try:
            # IP reputation check
            ip_reputation = self._check_ip_reputation(event.source_ip)
            event.metadata['ip_reputation'] = ip_reputation
            
            # Geolocation enrichment
            geolocation = self._get_ip_geolocation(event.source_ip)
            event.metadata['geolocation'] = geolocation
            
            # Known threat indicator matching
            threat_matches = self._match_threat_indicators(event)
            event.metadata['threat_matches'] = threat_matches
            
            # CVE enrichment for specific event types
            if event.event_type in ['vulnerability_exploit', 'malware_detection']:
                cve_info = self._enrich_with_cve_data(event)
                event.metadata['cve_info'] = cve_info
            
            return event
            
        except Exception as e:
            security_logger.error(f"Threat intelligence enrichment failed: {str(e)}")
            return event
    
    def _calculate_threat_score(self, event: SecurityEvent) -> int:
        """Calculate comprehensive threat score for event"""
        try:
            base_score = event.severity.value * 20  # 20-100 range based on severity
            
            # IP reputation impact
            ip_rep = event.metadata.get('ip_reputation', {})
            if ip_rep.get('malicious'):
                base_score += 30
            elif ip_rep.get('suspicious'):
                base_score += 15
            
            # Threat indicator matches
            threat_matches = event.metadata.get('threat_matches', [])
            base_score += min(len(threat_matches) * 10, 40)
            
            # Geographic risk factors
            geolocation = event.metadata.get('geolocation', {})
            high_risk_countries = getattr(settings, 'HIGH_RISK_COUNTRIES', [])
            if geolocation.get('country_code') in high_risk_countries:
                base_score += 20
            
            # Event type specific scoring
            high_risk_event_types = [
                'brute_force_attack', 'sql_injection', 'malware_detection',
                'privilege_escalation', 'data_exfiltration'
            ]
            if event.event_type in high_risk_event_types:
                base_score += 25
            
            # Time-based factors (attacks during off-hours)
            if self._is_off_hours(event.timestamp):
                base_score += 10
            
            # Cap at 100
            return min(base_score, 100)
            
        except Exception as e:
            security_logger.error(f"Threat score calculation failed: {str(e)}")
            return event.severity.value * 20
    
    def _detect_anomalies(self, event: SecurityEvent) -> float:
        """Use ML models to detect anomalous behavior"""
        try:
            # Extract features for ML analysis
            features = self._extract_ml_features(event)
            
            if not features or len(features) < 5:
                return 0.0
            
            # Scale features
            scaled_features = self.feature_scalers['standard'].transform([features])
            
            # Isolation Forest anomaly detection
            isolation_score = self.anomaly_models['isolation_forest'].decision_function(scaled_features)[0]
            
            # Convert to 0-100 scale (higher = more anomalous)
            normalized_score = max(0, min(100, (0.5 - isolation_score) * 100))
            
            return normalized_score
            
        except Exception as e:
            security_logger.error(f"ML anomaly detection failed: {str(e)}")
            return 0.0
    
    def _correlate_by_source_ip(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Correlate events by source IP address"""
        correlations = []
        ip_events = defaultdict(list)
        
        # Group events by IP
        for event in events:
            ip_events[event.source_ip].append(event)
        
        # Find IPs with multiple events
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 3:  # 3+ events from same IP
                correlation = {
                    'type': 'source_ip_correlation',
                    'source_ip': ip,
                    'event_count': len(ip_event_list),
                    'event_types': list(set(event.event_type for event in ip_event_list)),
                    'time_span_minutes': self._calculate_time_span(ip_event_list),
                    'confidence': min(85, 50 + len(ip_event_list) * 5),
                    'events': ip_event_list
                }
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_by_user_id(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Correlate events by user ID"""
        correlations = []
        user_events = defaultdict(list)
        
        # Group events by user
        for event in events:
            if event.user_id:
                user_events[event.user_id].append(event)
        
        # Find users with suspicious activity patterns
        for user_id, user_event_list in user_events.items():
            if len(user_event_list) >= 2:
                # Check for privilege escalation patterns
                event_types = [event.event_type for event in user_event_list]
                if 'authentication_failure' in event_types and 'privilege_escalation' in event_types:
                    correlation = {
                        'type': 'user_privilege_escalation',
                        'user_id': user_id,
                        'event_count': len(user_event_list),
                        'pattern': 'failed_auth_then_privilege_escalation',
                        'confidence': 90,
                        'events': user_event_list
                    }
                    correlations.append(correlation)
        
        return correlations
    
    def _correlate_by_event_pattern(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Correlate events by attack patterns"""
        correlations = []
        
        # Multi-stage attack detection
        attack_patterns = {
            'reconnaissance_attack': ['port_scan', 'vulnerability_scan', 'sql_injection'],
            'credential_attack': ['brute_force_attack', 'password_spray', 'credential_stuffing'],
            'data_exfiltration': ['file_access', 'large_data_transfer', 'suspicious_download']
        }
        
        for pattern_name, pattern_events in attack_patterns.items():
            matching_events = [
                event for event in events
                if event.event_type in pattern_events
            ]
            
            if len(matching_events) >= 2:
                correlation = {
                    'type': 'attack_pattern',
                    'pattern_name': pattern_name,
                    'matched_stages': len(matching_events),
                    'total_stages': len(pattern_events),
                    'confidence': min(95, 60 + len(matching_events) * 15),
                    'events': matching_events
                }
                correlations.append(correlation)
        
        return correlations
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        return f"evt_{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        return f"inc_{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
    
    def _start_correlation_engine(self):
        """Start background correlation engine"""
        def correlation_worker():
            while True:
                try:
                    correlations = self.correlate_events()
                    
                    for correlation in correlations:
                        if correlation.get('confidence', 0) >= 85:
                            # Create incident for high-confidence correlations
                            events = correlation.get('events', [])
                            if events:
                                self.create_security_incident(correlation, events)
                    
                    time.sleep(60)  # Run every minute
                    
                except Exception as e:
                    security_logger.error(f"Correlation engine error: {str(e)}")
                    time.sleep(60)
        
        # Start correlation worker in background thread
        correlation_thread = threading.Thread(target=correlation_worker, daemon=True)
        correlation_thread.start()
        
        security_logger.info("Security correlation engine started")


class AdvancedThreatHunting:
    """
    Proactive Threat Hunting Engine
    Hunt for advanced persistent threats and unknown attack vectors
    """
    
    def __init__(self):
        self.hunting_rules = []
        self.hunting_queries = {}
        self.threat_hypotheses = []
        self.hunting_results = deque(maxlen=1000)
        
        # Load hunting rules
        self._load_hunting_rules()
    
    def execute_hunt(self, hunt_name: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute specific threat hunt"""
        try:
            if hunt_name not in self.hunting_queries:
                raise ValueError(f"Hunt '{hunt_name}' not found")
            
            hunt_config = self.hunting_queries[hunt_name]
            parameters = parameters or {}
            
            # Execute hunt based on type
            if hunt_config['type'] == 'behavioral_analysis':
                results = self._hunt_behavioral_anomalies(hunt_config, parameters)
            elif hunt_config['type'] == 'network_analysis':
                results = self._hunt_network_anomalies(hunt_config, parameters)
            elif hunt_config['type'] == 'file_analysis':
                results = self._hunt_file_anomalies(hunt_config, parameters)
            elif hunt_config['type'] == 'timeline_analysis':
                results = self._hunt_timeline_anomalies(hunt_config, parameters)
            else:
                results = self._hunt_generic_patterns(hunt_config, parameters)
            
            # Score and prioritize results
            scored_results = self._score_hunting_results(results)
            
            # Store hunting results
            hunt_result = {
                'hunt_id': self._generate_hunt_id(),
                'hunt_name': hunt_name,
                'executed_at': timezone.now().isoformat(),
                'parameters': parameters,
                'findings': scored_results,
                'total_findings': len(scored_results),
                'high_risk_findings': len([r for r in scored_results if r.get('risk_score', 0) >= 80])
            }
            
            self.hunting_results.append(hunt_result)
            
            security_logger.info(f"Threat hunt executed: {hunt_name} - {len(scored_results)} findings")
            return hunt_result
            
        except Exception as e:
            security_logger.error(f"Threat hunt execution failed: {str(e)}")
            raise
    
    def create_custom_hunt(self, hunt_config: Dict[str, Any]) -> str:
        """Create custom threat hunting rule"""
        try:
            hunt_name = hunt_config['name']
            
            # Validate hunt configuration
            required_fields = ['name', 'description', 'type', 'query', 'severity']
            for field in required_fields:
                if field not in hunt_config:
                    raise ValueError(f"Missing required field: {field}")
            
            # Store hunting query
            self.hunting_queries[hunt_name] = {
                'name': hunt_name,
                'description': hunt_config['description'],
                'type': hunt_config['type'],
                'query': hunt_config['query'],
                'severity': hunt_config['severity'],
                'created_at': timezone.now().isoformat(),
                'enabled': hunt_config.get('enabled', True),
                'schedule': hunt_config.get('schedule', 'manual')
            }
            
            # Cache hunting rule
            hunt_key = f"threat_hunt_{hunt_name}"
            cache.set(hunt_key, self.hunting_queries[hunt_name], 86400 * 30)  # 30 days
            
            security_logger.info(f"Custom threat hunt created: {hunt_name}")
            return hunt_name
            
        except Exception as e:
            security_logger.error(f"Custom hunt creation failed: {str(e)}")
            raise
    
    def generate_threat_hypothesis(self, indicators: List[str], 
                                 context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat hypothesis for hunting"""
        try:
            hypothesis_id = f"hyp_{int(time.time())}_{hashlib.md5(str(indicators).encode()).hexdigest()[:8]}"
            
            # Analyze indicators to form hypothesis
            hypothesis_type = self._classify_threat_hypothesis(indicators, context)
            
            # Generate hunting suggestions
            hunting_suggestions = self._generate_hunting_suggestions(hypothesis_type, indicators)
            
            hypothesis = {
                'hypothesis_id': hypothesis_id,
                'created_at': timezone.now().isoformat(),
                'indicators': indicators,
                'context': context,
                'hypothesis_type': hypothesis_type,
                'confidence': self._calculate_hypothesis_confidence(indicators, context),
                'hunting_suggestions': hunting_suggestions,
                'status': 'active',
                'findings': []
            }
            
            self.threat_hypotheses.append(hypothesis)
            
            security_logger.info(f"Threat hypothesis generated: {hypothesis_id} - {hypothesis_type}")
            return hypothesis
            
        except Exception as e:
            security_logger.error(f"Threat hypothesis generation failed: {str(e)}")
            raise
    
    def _hunt_behavioral_anomalies(self, hunt_config: Dict, parameters: Dict) -> List[Dict]:
        """Hunt for behavioral anomalies"""
        findings = []
        
        try:
            # Get behavioral data from cache
            time_range = parameters.get('time_range_hours', 24)
            behavior_key = "user_behavior_analytics"
            behavior_data = cache.get(behavior_key, {})
            
            # Analyze login patterns
            for user_id, user_data in behavior_data.items():
                anomalies = self._detect_behavioral_anomalies(user_data, time_range)
                
                if anomalies:
                    finding = {
                        'type': 'behavioral_anomaly',
                        'user_id': user_id,
                        'anomalies': anomalies,
                        'risk_score': sum(a.get('severity', 0) for a in anomalies),
                        'timestamp': timezone.now().isoformat()
                    }
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            security_logger.error(f"Behavioral anomaly hunt failed: {str(e)}")
            return []
    
    def _hunt_network_anomalies(self, hunt_config: Dict, parameters: Dict) -> List[Dict]:
        """Hunt for network-based threats"""
        findings = []
        
        try:
            # Simulate network analysis
            # In production, integrate with network monitoring tools
            
            suspicious_patterns = [
                'beaconing_activity',
                'dns_tunneling',
                'lateral_movement',
                'data_exfiltration'
            ]
            
            for pattern in suspicious_patterns:
                # Simulate pattern detection
                if self._simulate_network_pattern_detection(pattern):
                    finding = {
                        'type': 'network_anomaly',
                        'pattern': pattern,
                        'risk_score': self._calculate_pattern_risk(pattern),
                        'timestamp': timezone.now().isoformat(),
                        'details': f"Detected {pattern} pattern in network traffic"
                    }
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            security_logger.error(f"Network anomaly hunt failed: {str(e)}")
            return []
    
    def _load_hunting_rules(self):
        """Load predefined hunting rules"""
        try:
            # Predefined hunting queries
            self.hunting_queries = {
                'suspicious_login_patterns': {
                    'name': 'Suspicious Login Patterns',
                    'description': 'Hunt for unusual login patterns indicating account compromise',
                    'type': 'behavioral_analysis',
                    'query': 'SELECT * FROM auth_logs WHERE failed_attempts > 5 AND time_span < 300',
                    'severity': 'medium',
                    'enabled': True
                },
                'privilege_escalation_hunt': {
                    'name': 'Privilege Escalation Hunt',
                    'description': 'Hunt for unauthorized privilege escalation attempts',
                    'type': 'behavioral_analysis',
                    'query': 'SELECT * FROM audit_logs WHERE event_type = "privilege_change"',
                    'severity': 'high',
                    'enabled': True
                },
                'data_exfiltration_hunt': {
                    'name': 'Data Exfiltration Hunt',
                    'description': 'Hunt for unusual data access and transfer patterns',
                    'type': 'network_analysis',
                    'query': 'SELECT * FROM network_logs WHERE bytes_out > threshold',
                    'severity': 'critical',
                    'enabled': True
                },
                'lateral_movement_hunt': {
                    'name': 'Lateral Movement Hunt',
                    'description': 'Hunt for lateral movement within the network',
                    'type': 'network_analysis',
                    'query': 'SELECT * FROM network_logs WHERE internal_connections > normal_baseline',
                    'severity': 'high',
                    'enabled': True
                }
            }
            
            security_logger.info(f"Loaded {len(self.hunting_queries)} hunting rules")
            
        except Exception as e:
            security_logger.error(f"Hunting rules loading failed: {str(e)}")


class MLBasedAnomalyDetection:
    """
    Machine Learning Based Anomaly Detection
    Advanced ML algorithms for detecting security anomalies
    """
    
    def __init__(self):
        self.models = {}
        self.feature_extractors = {}
        self.training_data = deque(maxlen=10000)
        self.anomaly_threshold = 0.8
        
        # Initialize ML models
        self._initialize_anomaly_models()
        
        # Start model training scheduler
        self._start_training_scheduler()
    
    def detect_user_behavior_anomalies(self, user_id: int, 
                                     behavior_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in user behavior"""
        try:
            # Extract behavioral features
            features = self._extract_user_behavior_features(behavior_data)
            
            if not features:
                return {'anomaly_detected': False, 'confidence': 0.0}
            
            # Use trained model for prediction
            if 'user_behavior' in self.models:
                model = self.models['user_behavior']
                
                # Standardize features
                scaled_features = self._standardize_features(features, 'user_behavior')
                
                # Predict anomaly
                anomaly_score = model.decision_function([scaled_features])[0]
                is_anomaly = model.predict([scaled_features])[0] == -1
                
                # Calculate confidence
                confidence = abs(anomaly_score)
                
                result = {
                    'anomaly_detected': is_anomaly,
                    'confidence': confidence,
                    'anomaly_score': anomaly_score,
                    'features_analyzed': len(features),
                    'model_type': 'isolation_forest',
                    'timestamp': timezone.now().isoformat()
                }
                
                # Store result for continuous learning
                self._store_anomaly_result(user_id, behavior_data, result)
                
                return result
            
            return {'anomaly_detected': False, 'confidence': 0.0, 'error': 'Model not available'}
            
        except Exception as e:
            security_logger.error(f"User behavior anomaly detection failed: {str(e)}")
            return {'anomaly_detected': False, 'confidence': 0.0, 'error': str(e)}
    
    def detect_network_anomalies(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in network traffic"""
        try:
            # Extract network features
            features = self._extract_network_features(network_data)
            
            if not features:
                return {'anomaly_detected': False, 'confidence': 0.0}
            
            # Use clustering model for network anomaly detection
            if 'network_clustering' in self.models:
                model = self.models['network_clustering']
                
                # Standardize features
                scaled_features = self._standardize_features(features, 'network')
                
                # Predict cluster
                cluster = model.fit_predict([scaled_features])
                
                # Anomaly if assigned to cluster -1 (noise in DBSCAN)
                is_anomaly = cluster[0] == -1
                
                result = {
                    'anomaly_detected': is_anomaly,
                    'cluster_id': int(cluster[0]),
                    'features_analyzed': len(features),
                    'model_type': 'dbscan_clustering',
                    'timestamp': timezone.now().isoformat()
                }
                
                return result
            
            return {'anomaly_detected': False, 'confidence': 0.0, 'error': 'Model not available'}
            
        except Exception as e:
            security_logger.error(f"Network anomaly detection failed: {str(e)}")
            return {'anomaly_detected': False, 'confidence': 0.0, 'error': str(e)}
    
    def train_anomaly_models(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train anomaly detection models with new data"""
        try:
            training_results = {}
            
            # Separate data by type
            user_behavior_data = [d for d in training_data if d.get('data_type') == 'user_behavior']
            network_data = [d for d in training_data if d.get('data_type') == 'network']
            
            # Train user behavior model
            if user_behavior_data:
                ub_result = self._train_user_behavior_model(user_behavior_data)
                training_results['user_behavior'] = ub_result
            
            # Train network anomaly model
            if network_data:
                net_result = self._train_network_model(network_data)
                training_results['network'] = net_result
            
            # Save trained models
            self._save_models()
            
            security_logger.info(f"ML models trained: {list(training_results.keys())}")
            return training_results
            
        except Exception as e:
            security_logger.error(f"ML model training failed: {str(e)}")
            return {'error': str(e)}
    
    def _initialize_anomaly_models(self):
        """Initialize ML models for anomaly detection"""
        try:
            # User behavior anomaly detection (Isolation Forest)
            self.models['user_behavior'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Network anomaly detection (DBSCAN clustering)
            self.models['network_clustering'] = DBSCAN(
                eps=0.5,
                min_samples=5
            )
            
            # Feature scalers for standardization
            self.feature_extractors['user_behavior_scaler'] = StandardScaler()
            self.feature_extractors['network_scaler'] = StandardScaler()
            
            security_logger.info("ML anomaly detection models initialized")
            
        except Exception as e:
            security_logger.error(f"ML model initialization failed: {str(e)}")
    
    def _extract_user_behavior_features(self, behavior_data: Dict[str, Any]) -> List[float]:
        """Extract features from user behavior data"""
        try:
            features = []
            
            # Login frequency features
            features.append(behavior_data.get('login_count', 0))
            features.append(behavior_data.get('failed_login_count', 0))
            features.append(behavior_data.get('login_time_variance', 0))
            
            # Access pattern features
            features.append(behavior_data.get('pages_visited', 0))
            features.append(behavior_data.get('session_duration', 0))
            features.append(behavior_data.get('unique_ips_count', 0))
            
            # Geographic features
            features.append(behavior_data.get('unique_countries', 0))
            features.append(1 if behavior_data.get('new_device') else 0)
            
            # Temporal features
            hour = datetime.now().hour
            features.append(hour)
            features.append(1 if 0 <= hour <= 6 else 0)  # Off-hours indicator
            
            return features
            
        except Exception as e:
            security_logger.error(f"User behavior feature extraction failed: {str(e)}")
            return []
    
    def _extract_network_features(self, network_data: Dict[str, Any]) -> List[float]:
        """Extract features from network traffic data"""
        try:
            features = []
            
            # Traffic volume features
            features.append(network_data.get('bytes_sent', 0))
            features.append(network_data.get('bytes_received', 0))
            features.append(network_data.get('packets_sent', 0))
            features.append(network_data.get('packets_received', 0))
            
            # Connection features
            features.append(network_data.get('connection_count', 0))
            features.append(network_data.get('unique_destinations', 0))
            features.append(network_data.get('connection_duration', 0))
            
            # Protocol features
            features.append(1 if network_data.get('protocol') == 'TCP' else 0)
            features.append(1 if network_data.get('protocol') == 'UDP' else 0)
            features.append(1 if network_data.get('encrypted') else 0)
            
            return features
            
        except Exception as e:
            security_logger.error(f"Network feature extraction failed: {str(e)}")
            return []


class SecurityOrchestrationSOAR:
    """
    Security Orchestration, Automation and Response (SOAR)
    Automated incident response and security workflow orchestration
    """
    
    def __init__(self):
        self.playbooks = {}
        self.automation_rules = []
        self.response_actions = {}
        self.integration_endpoints = {}
        
        # Load default playbooks
        self._load_default_playbooks()
        
        # Initialize response actions
        self._initialize_response_actions()
    
    def execute_incident_response(self, incident: SecurityIncident, 
                                playbook_name: Optional[str] = None) -> Dict[str, Any]:
        """Execute automated incident response"""
        try:
            # Select appropriate playbook
            if not playbook_name:
                playbook_name = self._select_playbook(incident)
            
            if playbook_name not in self.playbooks:
                raise ValueError(f"Playbook '{playbook_name}' not found")
            
            playbook = self.playbooks[playbook_name]
            
            # Execute playbook steps
            execution_results = []
            
            for step in playbook['steps']:
                step_result = self._execute_playbook_step(step, incident)
                execution_results.append(step_result)
                
                # Stop execution if critical step fails and playbook is strict
                if not step_result['success'] and playbook.get('strict_execution', False):
                    break
            
            # Update incident with response actions
            response_summary = {
                'playbook_executed': playbook_name,
                'execution_id': f"exec_{int(time.time())}",
                'executed_at': timezone.now().isoformat(),
                'steps_executed': len(execution_results),
                'successful_steps': len([r for r in execution_results if r['success']]),
                'failed_steps': len([r for r in execution_results if not r['success']]),
                'results': execution_results
            }
            
            # Add to incident timeline
            incident.response_actions.append(response_summary)
            incident.timeline.append({
                'timestamp': timezone.now().isoformat(),
                'action': 'automated_response_executed',
                'description': f'Executed playbook: {playbook_name}',
                'details': response_summary
            })
            
            security_logger.info(f"SOAR playbook executed: {playbook_name} for incident {incident.incident_id}")
            return response_summary
            
        except Exception as e:
            security_logger.error(f"SOAR execution failed: {str(e)}")
            raise
    
    def create_custom_playbook(self, playbook_config: Dict[str, Any]) -> str:
        """Create custom incident response playbook"""
        try:
            playbook_name = playbook_config['name']
            
            # Validate playbook configuration
            required_fields = ['name', 'description', 'trigger_conditions', 'steps']
            for field in required_fields:
                if field not in playbook_config:
                    raise ValueError(f"Missing required field: {field}")
            
            # Validate steps
            for step in playbook_config['steps']:
                if 'action' not in step or 'parameters' not in step:
                    raise ValueError("Each step must have 'action' and 'parameters'")
            
            # Store playbook
            self.playbooks[playbook_name] = {
                'name': playbook_name,
                'description': playbook_config['description'],
                'trigger_conditions': playbook_config['trigger_conditions'],
                'steps': playbook_config['steps'],
                'created_at': timezone.now().isoformat(),
                'enabled': playbook_config.get('enabled', True),
                'strict_execution': playbook_config.get('strict_execution', False)
            }
            
            # Cache playbook
            playbook_key = f"soar_playbook_{playbook_name}"
            cache.set(playbook_key, self.playbooks[playbook_name], 86400 * 30)  # 30 days
            
            security_logger.info(f"Custom SOAR playbook created: {playbook_name}")
            return playbook_name
            
        except Exception as e:
            security_logger.error(f"Custom playbook creation failed: {str(e)}")
            raise
    
    def _load_default_playbooks(self):
        """Load default incident response playbooks"""
        try:
            # Malware incident response playbook
            self.playbooks['malware_response'] = {
                'name': 'Malware Incident Response',
                'description': 'Automated response to malware detection',
                'trigger_conditions': {
                    'event_types': ['malware_detection', 'suspicious_file'],
                    'severity': ['HIGH', 'CRITICAL']
                },
                'steps': [
                    {
                        'action': 'isolate_host',
                        'description': 'Isolate affected host from network',
                        'parameters': {'isolation_method': 'network_quarantine'}
                    },
                    {
                        'action': 'collect_forensics',
                        'description': 'Collect forensic artifacts',
                        'parameters': {'artifacts': ['memory_dump', 'file_hash', 'process_list']}
                    },
                    {
                        'action': 'notify_team',
                        'description': 'Notify security team',
                        'parameters': {'channels': ['email', 'slack'], 'priority': 'high'}
                    }
                ]
            }
            
            # Brute force attack response playbook
            self.playbooks['brute_force_response'] = {
                'name': 'Brute Force Attack Response',
                'description': 'Automated response to brute force attacks',
                'trigger_conditions': {
                    'event_types': ['brute_force_attack'],
                    'confidence': 80
                },
                'steps': [
                    {
                        'action': 'block_ip',
                        'description': 'Block attacking IP address',
                        'parameters': {'duration': 3600, 'scope': 'global'}
                    },
                    {
                        'action': 'lock_account',
                        'description': 'Lock targeted user account',
                        'parameters': {'duration': 1800, 'notify_user': True}
                    },
                    {
                        'action': 'enhance_monitoring',
                        'description': 'Increase monitoring for related activities',
                        'parameters': {'duration': 7200, 'scope': 'authentication'}
                    }
                ]
            }
            
            security_logger.info(f"Loaded {len(self.playbooks)} default SOAR playbooks")
            
        except Exception as e:
            security_logger.error(f"Default playbook loading failed: {str(e)}")
    
    def _initialize_response_actions(self):
        """Initialize available response actions"""
        try:
            self.response_actions = {
                'isolate_host': self._isolate_host,
                'block_ip': self._block_ip,
                'lock_account': self._lock_account,
                'collect_forensics': self._collect_forensics,
                'notify_team': self._notify_security_team,
                'enhance_monitoring': self._enhance_monitoring,
                'quarantine_file': self._quarantine_file,
                'reset_password': self._reset_password,
                'revoke_sessions': self._revoke_user_sessions
            }
            
            security_logger.info(f"Initialized {len(self.response_actions)} SOAR response actions")
            
        except Exception as e:
            security_logger.error(f"Response actions initialization failed: {str(e)}")
    
    def _execute_playbook_step(self, step: Dict[str, Any], 
                             incident: SecurityIncident) -> Dict[str, Any]:
        """Execute individual playbook step"""
        try:
            action_name = step['action']
            parameters = step.get('parameters', {})
            
            if action_name not in self.response_actions:
                return {
                    'step': step,
                    'success': False,
                    'error': f"Unknown action: {action_name}",
                    'executed_at': timezone.now().isoformat()
                }
            
            # Execute the action
            action_function = self.response_actions[action_name]
            action_result = action_function(incident, parameters)
            
            return {
                'step': step,
                'success': action_result.get('success', False),
                'result': action_result,
                'executed_at': timezone.now().isoformat()
            }
            
        except Exception as e:
            security_logger.error(f"Playbook step execution failed: {str(e)}")
            return {
                'step': step,
                'success': False,
                'error': str(e),
                'executed_at': timezone.now().isoformat()
            }
    
    def _isolate_host(self, incident: SecurityIncident, parameters: Dict) -> Dict:
        """Isolate host from network"""
        try:
            # In production, integrate with network security tools
            isolation_method = parameters.get('isolation_method', 'network_quarantine')
            
            # Simulate host isolation
            security_logger.warning(f"HOST ISOLATION: Isolating hosts related to incident {incident.incident_id}")
            
            return {
                'success': True,
                'action': 'isolate_host',
                'method': isolation_method,
                'message': 'Host isolation initiated'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _block_ip(self, incident: SecurityIncident, parameters: Dict) -> Dict:
        """Block IP address"""
        try:
            duration = parameters.get('duration', 3600)  # 1 hour default
            scope = parameters.get('scope', 'global')
            
            # Get IP addresses from incident events
            blocked_ips = []
            for event in incident.events:
                if event.source_ip not in blocked_ips:
                    blocked_ips.append(event.source_ip)
                    
                    # Store IP block in cache
                    block_key = f"blocked_ip_{event.source_ip}"
                    block_data = {
                        'ip_address': event.source_ip,
                        'blocked_at': timezone.now().isoformat(),
                        'duration': duration,
                        'reason': f"Incident {incident.incident_id}",
                        'scope': scope
                    }
                    cache.set(block_key, block_data, duration)
            
            security_logger.warning(f"IP BLOCK: Blocked {len(blocked_ips)} IPs for incident {incident.incident_id}")
            
            return {
                'success': True,
                'action': 'block_ip',
                'blocked_ips': blocked_ips,
                'duration': duration,
                'message': f'Blocked {len(blocked_ips)} IP addresses'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _notify_security_team(self, incident: SecurityIncident, parameters: Dict) -> Dict:
        """Notify security team about incident"""
        try:
            channels = parameters.get('channels', ['email'])
            priority = parameters.get('priority', 'medium')
            
            notification_data = {
                'incident_id': incident.incident_id,
                'title': incident.title,
                'severity': incident.severity.name,
                'priority': priority,
                'description': incident.description,
                'event_count': len(incident.events),
                'created_at': incident.created_at.isoformat()
            }
            
            # Send notifications via configured channels
            notifications_sent = []
            
            if 'email' in channels:
                # In production, integrate with email system
                notifications_sent.append('email')
                security_logger.info(f"EMAIL NOTIFICATION: Sent for incident {incident.incident_id}")
            
            if 'slack' in channels:
                # In production, integrate with Slack API
                notifications_sent.append('slack')
                security_logger.info(f"SLACK NOTIFICATION: Sent for incident {incident.incident_id}")
            
            return {
                'success': True,
                'action': 'notify_team',
                'channels_used': notifications_sent,
                'message': 'Security team notifications sent'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _select_playbook(self, incident: SecurityIncident) -> str:
        """Automatically select appropriate playbook for incident"""
        try:
            # Simple rule-based playbook selection
            event_types = [event.event_type for event in incident.events]
            
            if any(et in ['malware_detection', 'suspicious_file'] for et in event_types):
                return 'malware_response'
            elif 'brute_force_attack' in event_types:
                return 'brute_force_response'
            else:
                return 'generic_incident_response'  # Default playbook
                
        except Exception as e:
            security_logger.error(f"Playbook selection failed: {str(e)}")
            return 'generic_incident_response'


# Global security intelligence engine instance
_global_security_intelligence = None

def get_security_intelligence() -> SecurityIntelligenceEngine:
    """Get global security intelligence engine instance"""
    global _global_security_intelligence
    if _global_security_intelligence is None:
        _global_security_intelligence = SecurityIntelligenceEngine()
    return _global_security_intelligence