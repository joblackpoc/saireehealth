"""
Phase 10: Predictive Security Analytics & AI-Powered Automation
Advanced ML-based security prediction and automated response systems

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Predictive Security Analytics
"""

import os
import json
import uuid
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import asyncio
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

# Advanced ML imports
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.decomposition import PCA
    from sklearn.feature_selection import SelectKBest, f_classif
    import joblib
    ADVANCED_ML_AVAILABLE = True
except ImportError:
    ADVANCED_ML_AVAILABLE = False

# Time series analysis
try:
    from statsmodels.tsa.arima.model import ARIMA
    from statsmodels.tsa.seasonal import seasonal_decompose
    import scipy.stats as stats
    TIME_SERIES_AVAILABLE = True
except ImportError:
    # Statsmodels not available - use alternative implementations
    TIME_SERIES_AVAILABLE = False
    # Define placeholder classes to avoid NameError
    class ARIMA:
        def __init__(self, *args, **kwargs):
            pass
        def fit(self, *args, **kwargs):
            return self
        def forecast(self, *args, **kwargs):
            return []
    
    def seasonal_decompose(*args, **kwargs):
        # Return a simple object with trend, seasonal, and resid attributes
        class DecomposeResult:
            def __init__(self):
                self.trend = None
                self.seasonal = None
                self.resid = None
        return DecomposeResult()
    
    # Use built-in statistics module as fallback
    try:
        import scipy.stats as stats
    except ImportError:
        import statistics
        # Create a stats-like object with basic functionality
        class StatsModule:
            @staticmethod
            def norm(*args, **kwargs):
                class NormResult:
                    @staticmethod
                    def pdf(x):
                        return 1.0
                    @staticmethod
                    def cdf(x):
                        return 0.5
                return NormResult()
        stats = StatsModule()

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from django.db import transaction

from .threat_intelligence import get_threat_intelligence_engine, ThreatLevel, SecurityEvent
from .advanced_monitoring import get_security_monitor
from .compliance_framework import get_compliance_manager

# Predictive Analytics Logger
analytics_logger = logging.getLogger('predictive_analytics')

class PredictionType(Enum):
    """Types of security predictions"""
    ATTACK_PROBABILITY = "attack_probability"
    BREACH_LIKELIHOOD = "breach_likelihood"
    USER_RISK_SCORE = "user_risk_score"
    SYSTEM_VULNERABILITY = "system_vulnerability"
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_EVOLUTION = "threat_evolution"
    COMPLIANCE_RISK = "compliance_risk"

class RiskLevel(Enum):
    """Risk assessment levels"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ModelType(Enum):
    """Machine learning model types"""
    CLASSIFICATION = "classification"
    REGRESSION = "regression"
    CLUSTERING = "clustering"
    ANOMALY_DETECTION = "anomaly_detection"
    TIME_SERIES = "time_series"

@dataclass
class SecurityPrediction:
    """Security prediction result"""
    prediction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    prediction_type: PredictionType = PredictionType.ATTACK_PROBABILITY
    target_entity: str = ""  # User, system, or resource
    predicted_risk_level: RiskLevel = RiskLevel.MEDIUM
    confidence_score: float = 0.5  # 0.0 to 1.0
    probability_scores: Dict[str, float] = field(default_factory=dict)
    contributing_factors: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    prediction_timestamp: datetime = field(default_factory=timezone.now)
    valid_until: datetime = field(default_factory=lambda: timezone.now() + timedelta(hours=24))
    model_used: str = ""
    feature_importance: Dict[str, float] = field(default_factory=dict)
    baseline_comparison: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MLModel:
    """Machine learning model metadata"""
    model_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    model_type: ModelType = ModelType.CLASSIFICATION
    target_prediction: PredictionType = PredictionType.ATTACK_PROBABILITY
    algorithm: str = ""
    version: str = "1.0"
    training_data_size: int = 0
    features: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    created_date: datetime = field(default_factory=timezone.now)
    last_trained: datetime = field(default_factory=timezone.now)
    last_updated: datetime = field(default_factory=timezone.now)
    is_active: bool = True
    hyperparameters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class UserRiskProfile:
    """User security risk profile"""
    user_id: str = ""
    username: str = ""
    risk_score: float = 0.5  # 0.0 to 1.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_factors: Dict[str, float] = field(default_factory=dict)
    behavioral_baseline: Dict[str, Any] = field(default_factory=dict)
    recent_activities: List[Dict[str, Any]] = field(default_factory=list)
    access_patterns: Dict[str, Any] = field(default_factory=dict)
    geographic_profile: Dict[str, Any] = field(default_factory=dict)
    device_profile: Dict[str, Any] = field(default_factory=dict)
    last_assessment: datetime = field(default_factory=timezone.now)
    trend_direction: str = "stable"  # improving, stable, deteriorating

class PredictiveSecurityAnalytics:
    """
    Advanced Predictive Security Analytics Engine
    
    Uses machine learning and statistical analysis to predict security threats,
    assess risks, and provide proactive security recommendations.
    """
    
    def __init__(self):
        self.ml_models = {}
        self.user_risk_profiles = {}
        self.predictions_cache = {}
        self.feature_extractors = {}
        
        # Configuration
        self.config = getattr(settings, 'PREDICTIVE_ANALYTICS_CONFIG', {
            'ENABLE_ML_PREDICTIONS': True,
            'RISK_ASSESSMENT_INTERVAL_HOURS': 4,
            'USER_BEHAVIOR_ANALYSIS': True,
            'ANOMALY_DETECTION_ENABLED': True,
            'PREDICTION_RETENTION_DAYS': 30,
            'MODEL_RETRAINING_INTERVAL_DAYS': 7,
            'CONFIDENCE_THRESHOLD': 0.7,
            'RISK_SCORE_WEIGHTS': {
                'authentication_anomalies': 0.25,
                'access_pattern_deviations': 0.20,
                'geographic_anomalies': 0.15,
                'time_based_anomalies': 0.15,
                'resource_access_risks': 0.15,
                'threat_intel_correlations': 0.10
            },
            'FEATURE_ENGINEERING': {
                'time_windows': [1, 6, 24, 168],  # hours
                'aggregation_methods': ['count', 'mean', 'std', 'max', 'min'],
                'categorical_encoding': 'label',
                'numerical_scaling': 'robust'
            }
        })
        
        # Initialize analytics engine
        self._initialize_predictive_engine()
        
        analytics_logger.info("Predictive Security Analytics Engine initialized")
    
    def _initialize_predictive_engine(self):
        """Initialize predictive analytics engine"""
        try:
            # Initialize feature extractors
            self._initialize_feature_extractors()
            
            # Load existing models
            self._load_ml_models()
            
            # Initialize user risk profiles
            self._initialize_user_risk_profiles()
            
            # Start background analytics
            self._start_analytics_engine()
            
            analytics_logger.info("Predictive analytics engine initialized")
            
        except Exception as e:
            analytics_logger.error(f"Failed to initialize predictive engine: {str(e)}")
    
    def _initialize_feature_extractors(self):
        """Initialize feature extraction functions"""
        try:
            self.feature_extractors = {
                'user_behavior': self._extract_user_behavior_features,
                'temporal': self._extract_temporal_features,
                'network': self._extract_network_features,
                'access_patterns': self._extract_access_pattern_features,
                'authentication': self._extract_authentication_features,
                'resource_usage': self._extract_resource_usage_features
            }
            
            analytics_logger.info(f"Initialized {len(self.feature_extractors)} feature extractors")
            
        except Exception as e:
            analytics_logger.error(f"Failed to initialize feature extractors: {str(e)}")
    
    def _load_ml_models(self):
        """Load machine learning models"""
        try:
            if not ADVANCED_ML_AVAILABLE:
                analytics_logger.warning("Advanced ML libraries not available")
                return
            
            # Load cached models
            cached_models = cache.get('predictive_ml_models', {})
            
            if not cached_models:
                # Initialize default models
                self._initialize_default_models()
            else:
                self.ml_models = cached_models
                analytics_logger.info(f"Loaded {len(self.ml_models)} cached ML models")
            
        except Exception as e:
            analytics_logger.error(f"Failed to load ML models: {str(e)}")
    
    def _initialize_default_models(self):
        """Initialize default ML models"""
        try:
            # Attack probability prediction model
            attack_model = MLModel(
                name="Attack Probability Predictor",
                model_type=ModelType.CLASSIFICATION,
                target_prediction=PredictionType.ATTACK_PROBABILITY,
                algorithm="RandomForest",
                features=[
                    'login_frequency_anomaly', 'access_time_anomaly', 'geographic_anomaly',
                    'resource_access_pattern', 'authentication_failures', 'threat_intel_matches'
                ]
            )
            
            # Initialize sklearn model
            attack_model.hyperparameters = {
                'n_estimators': 200,
                'max_depth': 10,
                'min_samples_split': 5,
                'random_state': 42
            }
            
            self.ml_models[attack_model.model_id] = attack_model
            
            # User risk assessment model
            user_risk_model = MLModel(
                name="User Risk Scorer",
                model_type=ModelType.REGRESSION,
                target_prediction=PredictionType.USER_RISK_SCORE,
                algorithm="GradientBoosting",
                features=[
                    'behavioral_deviation', 'privilege_changes', 'failed_access_rate',
                    'unusual_resource_access', 'time_based_anomalies', 'location_changes'
                ]
            )
            
            user_risk_model.hyperparameters = {
                'n_estimators': 150,
                'learning_rate': 0.1,
                'max_depth': 8,
                'random_state': 42
            }
            
            self.ml_models[user_risk_model.model_id] = user_risk_model
            
            # Anomaly detection model
            anomaly_model = MLModel(
                name="Security Anomaly Detector",
                model_type=ModelType.ANOMALY_DETECTION,
                target_prediction=PredictionType.ANOMALY_DETECTION,
                algorithm="IsolationForest",
                features=[
                    'event_frequency', 'event_diversity', 'time_patterns',
                    'user_patterns', 'resource_patterns', 'network_patterns'
                ]
            )
            
            anomaly_model.hyperparameters = {
                'contamination': 0.1,
                'n_estimators': 100,
                'random_state': 42
            }
            
            self.ml_models[anomaly_model.model_id] = anomaly_model
            
            analytics_logger.info(f"Initialized {len(self.ml_models)} default ML models")
            
        except Exception as e:
            analytics_logger.error(f"Failed to initialize default models: {str(e)}")
    
    def _initialize_user_risk_profiles(self):
        """Initialize user risk profiles"""
        try:
            # Load existing profiles from cache
            cached_profiles = cache.get('user_risk_profiles', {})
            self.user_risk_profiles.update(cached_profiles)
            
            analytics_logger.info(f"Loaded {len(self.user_risk_profiles)} user risk profiles")
            
        except Exception as e:
            analytics_logger.error(f"Failed to initialize user risk profiles: {str(e)}")
    
    def _start_analytics_engine(self):
        """Start background analytics processing"""
        try:
            analytics_thread = threading.Thread(
                target=self._analytics_processing_loop,
                name="PredictiveAnalytics",
                daemon=True
            )
            analytics_thread.start()
            analytics_logger.info("Background analytics processing started")
        except Exception as e:
            analytics_logger.error(f"Failed to start analytics engine: {str(e)}")
    
    def _analytics_processing_loop(self):
        """Background analytics processing loop"""
        while True:
            try:
                # Update user risk profiles
                self._update_user_risk_profiles()
                
                # Perform predictive analysis
                self._perform_predictive_analysis()
                
                # Clean up old predictions
                self._cleanup_old_predictions()
                
                # Cache analytics data
                self._cache_analytics_data()
                
                # Sleep for processing interval
                import time
                interval_hours = self.config.get('RISK_ASSESSMENT_INTERVAL_HOURS', 4)
                time.sleep(interval_hours * 3600)
                
            except Exception as e:
                analytics_logger.error(f"Analytics processing error: {str(e)}")
                import time
                time.sleep(3600)  # Sleep 1 hour on error
    
    def _update_user_risk_profiles(self):
        """Update user risk profiles based on recent activity"""
        try:
            # Get recent security events
            threat_engine = get_threat_intelligence_engine()
            recent_events = list(threat_engine.security_events)
            
            # Group events by user
            user_events = defaultdict(list)
            for event in recent_events:
                if event.user_id:
                    user_events[event.user_id].append(event)
            
            # Update each user's risk profile
            for user_id, events in user_events.items():
                self._update_user_risk_profile(user_id, events)
            
            analytics_logger.info(f"Updated risk profiles for {len(user_events)} users")
            
        except Exception as e:
            analytics_logger.error(f"Failed to update user risk profiles: {str(e)}")
    
    def _update_user_risk_profile(self, user_id: str, events: List[SecurityEvent]):
        """Update individual user risk profile"""
        try:
            # Get or create user profile
            if user_id not in self.user_risk_profiles:
                self.user_risk_profiles[user_id] = UserRiskProfile(
                    user_id=user_id,
                    username=user_id  # Could be enhanced with actual username lookup
                )
            
            profile = self.user_risk_profiles[user_id]
            
            # Extract risk factors from events
            risk_factors = self._calculate_user_risk_factors(events)
            profile.risk_factors.update(risk_factors)
            
            # Calculate overall risk score
            profile.risk_score = self._calculate_weighted_risk_score(profile.risk_factors)
            profile.risk_level = self._risk_score_to_level(profile.risk_score)
            
            # Update behavioral patterns
            profile.access_patterns = self._analyze_access_patterns(events)
            profile.behavioral_baseline = self._update_behavioral_baseline(profile, events)
            
            # Store recent activities
            profile.recent_activities = [
                {
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type,
                    'resource': event.resource,
                    'outcome': event.outcome
                }
                for event in events[-10:]  # Last 10 events
            ]
            
            # Determine trend direction
            profile.trend_direction = self._calculate_risk_trend(profile)
            profile.last_assessment = timezone.now()
            
        except Exception as e:
            analytics_logger.error(f"Failed to update user risk profile for {user_id}: {str(e)}")
    
    def _calculate_user_risk_factors(self, events: List[SecurityEvent]) -> Dict[str, float]:
        """Calculate risk factors for a user based on their events"""
        try:
            risk_factors = {}
            
            if not events:
                return risk_factors
            
            # Authentication anomalies
            auth_events = [e for e in events if 'auth' in e.event_type.lower() or 'login' in e.event_type.lower()]
            failed_auths = [e for e in auth_events if 'fail' in e.outcome.lower()]
            
            if auth_events:
                auth_failure_rate = len(failed_auths) / len(auth_events)
                risk_factors['authentication_anomalies'] = min(auth_failure_rate * 2, 1.0)
            
            # Time-based anomalies
            unusual_time_events = 0
            for event in events:
                hour = event.timestamp.hour
                if hour < 6 or hour > 22:  # Outside business hours
                    unusual_time_events += 1
            
            if events:
                risk_factors['time_based_anomalies'] = min(unusual_time_events / len(events), 1.0)
            
            # Access pattern deviations
            unique_resources = len(set(e.resource for e in events if e.resource))
            resource_diversity = min(unique_resources / 10.0, 1.0)  # Normalize to 0-1
            risk_factors['access_pattern_deviations'] = resource_diversity
            
            # Geographic anomalies (placeholder - would need IP geolocation)
            unique_source_ips = len(set(e.source_ip for e in events if e.source_ip))
            geographic_diversity = min(unique_source_ips / 5.0, 1.0)
            risk_factors['geographic_anomalies'] = geographic_diversity
            
            # Resource access risks
            sensitive_resources = [e for e in events if any(keyword in (e.resource or '').lower() 
                                                          for keyword in ['admin', 'config', 'sensitive', 'private'])]
            if events:
                risk_factors['resource_access_risks'] = min(len(sensitive_resources) / len(events), 1.0)
            
            # Threat intelligence correlations
            threat_matched_events = [e for e in events if e.threat_indicators]
            if events:
                risk_factors['threat_intel_correlations'] = min(len(threat_matched_events) / len(events), 1.0)
            
            return risk_factors
            
        except Exception as e:
            analytics_logger.error(f"Failed to calculate user risk factors: {str(e)}")
            return {}
    
    def _calculate_weighted_risk_score(self, risk_factors: Dict[str, float]) -> float:
        """Calculate weighted risk score from individual factors"""
        try:
            weights = self.config['RISK_SCORE_WEIGHTS']
            
            total_score = 0.0
            total_weight = 0.0
            
            for factor, score in risk_factors.items():
                if factor in weights:
                    weight = weights[factor]
                    total_score += score * weight
                    total_weight += weight
            
            # Normalize score
            if total_weight > 0:
                return min(total_score / total_weight, 1.0)
            else:
                return 0.5  # Default medium risk
            
        except Exception as e:
            analytics_logger.error(f"Failed to calculate weighted risk score: {str(e)}")
            return 0.5
    
    def _risk_score_to_level(self, risk_score: float) -> RiskLevel:
        """Convert risk score to risk level"""
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        elif risk_score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _analyze_access_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze user access patterns"""
        try:
            patterns = {
                'total_events': len(events),
                'unique_resources': len(set(e.resource for e in events if e.resource)),
                'time_distribution': {},
                'day_distribution': {},
                'resource_frequency': {}
            }
            
            # Time distribution (by hour)
            for event in events:
                hour = event.timestamp.hour
                patterns['time_distribution'][hour] = patterns['time_distribution'].get(hour, 0) + 1
            
            # Day distribution
            for event in events:
                day = event.timestamp.strftime('%A')
                patterns['day_distribution'][day] = patterns['day_distribution'].get(day, 0) + 1
            
            # Resource frequency
            for event in events:
                if event.resource:
                    patterns['resource_frequency'][event.resource] = patterns['resource_frequency'].get(event.resource, 0) + 1
            
            return patterns
            
        except Exception as e:
            analytics_logger.error(f"Failed to analyze access patterns: {str(e)}")
            return {}
    
    def _update_behavioral_baseline(self, profile: UserRiskProfile, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Update user's behavioral baseline"""
        try:
            baseline = profile.behavioral_baseline.copy()
            
            # Update with current patterns
            current_patterns = self._analyze_access_patterns(events)
            
            # Exponential moving average for baseline update
            alpha = 0.3  # Learning rate
            
            for key, value in current_patterns.items():
                if isinstance(value, (int, float)):
                    if key in baseline:
                        baseline[key] = alpha * value + (1 - alpha) * baseline[key]
                    else:
                        baseline[key] = value
                elif isinstance(value, dict):
                    if key not in baseline:
                        baseline[key] = {}
                    for subkey, subvalue in value.items():
                        if isinstance(subvalue, (int, float)):
                            if subkey in baseline[key]:
                                baseline[key][subkey] = alpha * subvalue + (1 - alpha) * baseline[key][subkey]
                            else:
                                baseline[key][subkey] = subvalue
            
            return baseline
            
        except Exception as e:
            analytics_logger.error(f"Failed to update behavioral baseline: {str(e)}")
            return profile.behavioral_baseline
    
    def _calculate_risk_trend(self, profile: UserRiskProfile) -> str:
        """Calculate risk trend direction for user"""
        try:
            # Simple trend calculation based on recent risk score changes
            # This could be enhanced with more sophisticated time series analysis
            
            # For now, use a simple heuristic
            current_score = profile.risk_score
            
            if current_score > 0.7:
                return "deteriorating"
            elif current_score < 0.3:
                return "improving"
            else:
                return "stable"
            
        except Exception as e:
            analytics_logger.error(f"Failed to calculate risk trend: {str(e)}")
            return "stable"
    
    def _perform_predictive_analysis(self):
        """Perform predictive analysis across all users and systems"""
        try:
            # Generate predictions for high-risk users
            high_risk_users = [
                user_id for user_id, profile in self.user_risk_profiles.items()
                if profile.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            ]
            
            for user_id in high_risk_users:
                prediction = self.predict_user_risk(user_id)
                if prediction:
                    self.predictions_cache[prediction.prediction_id] = prediction
            
            # Perform system-wide anomaly detection
            if self.config.get('ANOMALY_DETECTION_ENABLED', True):
                system_prediction = self.predict_system_anomalies()
                if system_prediction:
                    self.predictions_cache[system_prediction.prediction_id] = system_prediction
            
            analytics_logger.info(f"Performed predictive analysis for {len(high_risk_users)} high-risk users")
            
        except Exception as e:
            analytics_logger.error(f"Failed to perform predictive analysis: {str(e)}")
    
    def predict_user_risk(self, user_id: str) -> Optional[SecurityPrediction]:
        """Predict security risk for specific user"""
        try:
            if user_id not in self.user_risk_profiles:
                return None
            
            profile = self.user_risk_profiles[user_id]
            
            # Extract features for prediction
            features = self._extract_user_prediction_features(profile)
            
            if not features:
                return None
            
            # Generate prediction
            prediction = SecurityPrediction(
                prediction_type=PredictionType.USER_RISK_SCORE,
                target_entity=user_id,
                predicted_risk_level=profile.risk_level,
                confidence_score=0.8,  # Base confidence
                probability_scores={
                    level.value: self._calculate_risk_probability(profile.risk_score, level)
                    for level in RiskLevel
                },
                contributing_factors=list(profile.risk_factors.keys()),
                model_used="user_risk_baseline"
            )
            
            # Generate recommendations
            prediction.recommended_actions = self._generate_user_risk_recommendations(profile)
            
            # Feature importance
            prediction.feature_importance = profile.risk_factors
            
            analytics_logger.info(f"Generated user risk prediction for {user_id}: {prediction.predicted_risk_level.value}")
            
            return prediction
            
        except Exception as e:
            analytics_logger.error(f"Failed to predict user risk for {user_id}: {str(e)}")
            return None
    
    def _extract_user_prediction_features(self, profile: UserRiskProfile) -> List[float]:
        """Extract numerical features from user profile for ML prediction"""
        try:
            features = []
            
            # Risk factors
            features.extend([
                profile.risk_factors.get('authentication_anomalies', 0.0),
                profile.risk_factors.get('access_pattern_deviations', 0.0),
                profile.risk_factors.get('geographic_anomalies', 0.0),
                profile.risk_factors.get('time_based_anomalies', 0.0),
                profile.risk_factors.get('resource_access_risks', 0.0),
                profile.risk_factors.get('threat_intel_correlations', 0.0)
            ])
            
            # Behavioral patterns
            access_patterns = profile.access_patterns
            features.extend([
                access_patterns.get('total_events', 0),
                access_patterns.get('unique_resources', 0),
                len(access_patterns.get('time_distribution', {})),
                len(access_patterns.get('resource_frequency', {}))
            ])
            
            # Trend indicator
            trend_score = {'improving': 0.2, 'stable': 0.5, 'deteriorating': 0.8}.get(profile.trend_direction, 0.5)
            features.append(trend_score)
            
            # Days since last assessment
            days_since_assessment = (timezone.now() - profile.last_assessment).days
            features.append(min(days_since_assessment / 7.0, 1.0))  # Normalize to weeks
            
            return features
            
        except Exception as e:
            analytics_logger.error(f"Failed to extract user prediction features: {str(e)}")
            return []
    
    def _calculate_risk_probability(self, current_score: float, target_level: RiskLevel) -> float:
        """Calculate probability of user being at target risk level"""
        level_ranges = {
            RiskLevel.MINIMAL: (0.0, 0.2),
            RiskLevel.LOW: (0.2, 0.4),
            RiskLevel.MEDIUM: (0.4, 0.6),
            RiskLevel.HIGH: (0.6, 0.8),
            RiskLevel.CRITICAL: (0.8, 1.0)
        }
        
        min_val, max_val = level_ranges[target_level]
        
        if min_val <= current_score <= max_val:
            return 0.9  # High probability if in range
        else:
            # Calculate distance-based probability
            center = (min_val + max_val) / 2
            distance = abs(current_score - center)
            return max(0.1, 1.0 - distance * 2)
    
    def _generate_user_risk_recommendations(self, profile: UserRiskProfile) -> List[str]:
        """Generate risk mitigation recommendations for user"""
        recommendations = []
        
        # High-risk users
        if profile.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.extend([
                "Require additional authentication factors",
                "Implement enhanced monitoring for this user",
                "Review and limit user privileges"
            ])
        
        # Specific risk factors
        risk_factors = profile.risk_factors
        
        if risk_factors.get('authentication_anomalies', 0) > 0.5:
            recommendations.append("Investigate authentication failures and implement account lockout policies")
        
        if risk_factors.get('time_based_anomalies', 0) > 0.3:
            recommendations.append("Review and restrict after-hours access permissions")
        
        if risk_factors.get('geographic_anomalies', 0) > 0.4:
            recommendations.append("Implement geolocation-based access controls")
        
        if risk_factors.get('resource_access_risks', 0) > 0.3:
            recommendations.append("Review access to sensitive resources and implement least privilege")
        
        if risk_factors.get('threat_intel_correlations', 0) > 0.1:
            recommendations.extend([
                "Immediate security investigation required",
                "Isolate user systems for forensic analysis"
            ])
        
        # Trend-based recommendations
        if profile.trend_direction == "deteriorating":
            recommendations.append("Implement immediate risk reduction measures")
        
        return recommendations[:5]  # Return top 5 recommendations
    
    def predict_system_anomalies(self) -> Optional[SecurityPrediction]:
        """Predict system-wide security anomalies"""
        try:
            # Collect system-wide metrics
            system_features = self._extract_system_features()
            
            if not system_features:
                return None
            
            # Simple anomaly detection based on statistical thresholds
            anomaly_score = self._calculate_system_anomaly_score(system_features)
            
            # Determine if anomaly threshold is exceeded
            anomaly_threshold = 0.7
            is_anomaly = anomaly_score > anomaly_threshold
            
            if is_anomaly:
                prediction = SecurityPrediction(
                    prediction_type=PredictionType.ANOMALY_DETECTION,
                    target_entity="system",
                    predicted_risk_level=RiskLevel.HIGH if anomaly_score > 0.8 else RiskLevel.MEDIUM,
                    confidence_score=anomaly_score,
                    probability_scores={"anomaly": anomaly_score, "normal": 1 - anomaly_score},
                    contributing_factors=self._identify_anomaly_factors(system_features),
                    recommended_actions=[
                        "Investigate system-wide security metrics",
                        "Review recent security events for patterns",
                        "Consider implementing additional monitoring"
                    ],
                    model_used="statistical_anomaly_detection"
                )
                
                analytics_logger.warning(f"System anomaly detected with score: {anomaly_score:.2f}")
                return prediction
            
            return None
            
        except Exception as e:
            analytics_logger.error(f"Failed to predict system anomalies: {str(e)}")
            return None
    
    def _extract_system_features(self) -> Dict[str, float]:
        """Extract system-wide features for anomaly detection"""
        try:
            features = {}
            
            # User risk statistics
            risk_scores = [profile.risk_score for profile in self.user_risk_profiles.values()]
            if risk_scores:
                features['avg_user_risk'] = np.mean(risk_scores)
                features['max_user_risk'] = np.max(risk_scores)
                features['high_risk_user_count'] = sum(1 for score in risk_scores if score > 0.6)
            
            # Threat intelligence statistics
            threat_engine = get_threat_intelligence_engine()
            features['active_iocs'] = len([ioc for ioc in threat_engine.iocs.values() 
                                         if (timezone.now() - ioc.last_seen).days <= 7])
            features['high_threat_iocs'] = len([ioc for ioc in threat_engine.iocs.values() 
                                              if ioc.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]])
            
            # Security event statistics
            recent_events = [event for event in threat_engine.security_events 
                           if (timezone.now() - event.timestamp).days <= 1]
            features['daily_event_count'] = len(recent_events)
            features['failed_event_rate'] = sum(1 for event in recent_events if 'fail' in event.outcome.lower()) / len(recent_events) if recent_events else 0
            
            return features
            
        except Exception as e:
            analytics_logger.error(f"Failed to extract system features: {str(e)}")
            return {}
    
    def _calculate_system_anomaly_score(self, features: Dict[str, float]) -> float:
        """Calculate system anomaly score"""
        try:
            # Simple weighted scoring of anomaly indicators
            weights = {
                'avg_user_risk': 0.3,
                'max_user_risk': 0.2,
                'high_risk_user_count': 0.2,
                'active_iocs': 0.1,
                'high_threat_iocs': 0.1,
                'failed_event_rate': 0.1
            }
            
            score = 0.0
            total_weight = 0.0
            
            for feature, value in features.items():
                if feature in weights:
                    weight = weights[feature]
                    
                    # Normalize values to 0-1 range
                    if feature in ['avg_user_risk', 'max_user_risk', 'failed_event_rate']:
                        normalized_value = min(value, 1.0)
                    elif feature == 'high_risk_user_count':
                        normalized_value = min(value / 10.0, 1.0)  # Assume 10+ is high
                    elif feature in ['active_iocs', 'high_threat_iocs']:
                        normalized_value = min(value / 50.0, 1.0)  # Assume 50+ is high
                    else:
                        normalized_value = value
                    
                    score += normalized_value * weight
                    total_weight += weight
            
            return score / total_weight if total_weight > 0 else 0.0
            
        except Exception as e:
            analytics_logger.error(f"Failed to calculate system anomaly score: {str(e)}")
            return 0.0
    
    def _identify_anomaly_factors(self, features: Dict[str, float]) -> List[str]:
        """Identify contributing factors for system anomaly"""
        factors = []
        
        if features.get('avg_user_risk', 0) > 0.6:
            factors.append("High average user risk scores")
        
        if features.get('high_risk_user_count', 0) > 5:
            factors.append("Multiple high-risk users detected")
        
        if features.get('failed_event_rate', 0) > 0.2:
            factors.append("High rate of failed security events")
        
        if features.get('active_iocs', 0) > 20:
            factors.append("High number of active threat indicators")
        
        if features.get('high_threat_iocs', 0) > 5:
            factors.append("Multiple high-severity threat indicators")
        
        return factors
    
    def _extract_user_behavior_features(self, user_id: str, events: List[SecurityEvent]) -> List[float]:
        """Extract user behavior features"""
        # Implementation for user behavior feature extraction
        return []
    
    def _extract_temporal_features(self, events: List[SecurityEvent]) -> List[float]:
        """Extract temporal features from events"""
        # Implementation for temporal feature extraction
        return []
    
    def _extract_network_features(self, events: List[SecurityEvent]) -> List[float]:
        """Extract network-based features"""
        # Implementation for network feature extraction
        return []
    
    def _extract_access_pattern_features(self, events: List[SecurityEvent]) -> List[float]:
        """Extract access pattern features"""
        # Implementation for access pattern feature extraction
        return []
    
    def _extract_authentication_features(self, events: List[SecurityEvent]) -> List[float]:
        """Extract authentication-related features"""
        # Implementation for authentication feature extraction
        return []
    
    def _extract_resource_usage_features(self, events: List[SecurityEvent]) -> List[float]:
        """Extract resource usage features"""
        # Implementation for resource usage feature extraction
        return []
    
    def _cleanup_old_predictions(self):
        """Clean up old predictions"""
        try:
            current_time = timezone.now()
            retention_days = self.config.get('PREDICTION_RETENTION_DAYS', 30)
            cutoff_time = current_time - timedelta(days=retention_days)
            
            expired_predictions = []
            for pred_id, prediction in self.predictions_cache.items():
                if prediction.prediction_timestamp < cutoff_time:
                    expired_predictions.append(pred_id)
            
            for pred_id in expired_predictions:
                del self.predictions_cache[pred_id]
            
            if expired_predictions:
                analytics_logger.info(f"Cleaned up {len(expired_predictions)} old predictions")
            
        except Exception as e:
            analytics_logger.error(f"Failed to cleanup old predictions: {str(e)}")
    
    def _cache_analytics_data(self):
        """Cache analytics data"""
        try:
            # Cache ML models
            cache.set('predictive_ml_models', self.ml_models, 86400)  # 24 hours
            
            # Cache user risk profiles
            cache.set('user_risk_profiles', self.user_risk_profiles, 86400)
            
            # Cache recent predictions
            cache.set('security_predictions', self.predictions_cache, 3600)  # 1 hour
            
        except Exception as e:
            analytics_logger.error(f"Failed to cache analytics data: {str(e)}")
    
    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get predictive analytics summary"""
        try:
            # User risk statistics
            risk_levels = [profile.risk_level for profile in self.user_risk_profiles.values()]
            risk_stats = {level.value: risk_levels.count(level) for level in RiskLevel}
            
            # Recent predictions
            recent_predictions = [
                pred for pred in self.predictions_cache.values()
                if (timezone.now() - pred.prediction_timestamp).days <= 7
            ]
            
            # Prediction statistics
            pred_types = [pred.prediction_type for pred in recent_predictions]
            pred_stats = {ptype.value: pred_types.count(ptype) for ptype in PredictionType}
            
            summary = {
                'last_updated': timezone.now().isoformat(),
                'total_users_analyzed': len(self.user_risk_profiles),
                'user_risk_distribution': risk_stats,
                'ml_models_active': len(self.ml_models),
                'recent_predictions': len(recent_predictions),
                'prediction_type_distribution': pred_stats,
                'high_risk_users': risk_stats.get('high', 0) + risk_stats.get('critical', 0),
                'analytics_enabled': self.config.get('ENABLE_ML_PREDICTIONS', True),
                'average_confidence': np.mean([pred.confidence_score for pred in recent_predictions]) if recent_predictions else 0.0
            }
            
            return summary
            
        except Exception as e:
            analytics_logger.error(f"Failed to get analytics summary: {str(e)}")
            return {'error': str(e)}
    
    def get_user_risk_profile(self, user_id: str) -> UserRiskProfile:
        """
        Get or create user risk profile
        
        Args:
            user_id: User identifier
            
        Returns:
            UserRiskProfile object
        """
        try:
            if user_id not in self.user_risk_profiles:
                # Create new risk profile for user
                self.user_risk_profiles[user_id] = UserRiskProfile(
                    user_id=user_id,
                    risk_level=RiskLevel.LOW,
                    risk_score=0.1
                )
                analytics_logger.info(f"Created new risk profile for user: {user_id}")
            
            return self.user_risk_profiles[user_id]
            
        except Exception as e:
            analytics_logger.error(f"Failed to get user risk profile: {str(e)}")
            # Return default low-risk profile
            return UserRiskProfile(user_id=user_id, risk_level=RiskLevel.LOW, risk_score=0.1)


# Global predictive analytics engine instance
_global_analytics_engine = None

def get_predictive_analytics_engine() -> PredictiveSecurityAnalytics:
    """Get global predictive analytics engine instance"""
    global _global_analytics_engine
    if _global_analytics_engine is None:
        _global_analytics_engine = PredictiveSecurityAnalytics()
    return _global_analytics_engine