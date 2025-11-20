"""
ML-Based Security Analytics Engine
Advanced machine learning algorithms for security pattern detection and prediction
Expert Blue Team Implementation - ETH Standards
"""
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
from django.core.cache import cache
from django.utils import timezone
from .security_core import SecurityLogger


class SecurityAnalyticsEngine:
    """
    Main ML-based security analytics engine
    """
    
    def __init__(self):
        self.feature_extractors = {
            'request_patterns': RequestPatternExtractor(),
            'user_behavior': UserBehaviorExtractor(),
            'network_analysis': NetworkAnalysisExtractor(),
            'temporal_patterns': TemporalPatternExtractor()
        }
        
        self.anomaly_models = {
            'isolation_forest': IsolationForestDetector(),
            'statistical_analysis': StatisticalAnomalyDetector(),
            'sequence_analysis': SequenceAnomalyDetector(),
            'clustering_analysis': ClusteringAnomalyDetector()
        }
        
        self.prediction_models = {
            'attack_prediction': AttackPredictionModel(),
            'user_risk_scoring': UserRiskScoringModel(),
            'threat_evolution': ThreatEvolutionModel()
        }
    
    def analyze_security_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Comprehensive analysis of security events using ML
        """
        if not events:
            return {'status': 'no_events', 'analysis': {}}
        
        # Extract features from events
        features = self._extract_comprehensive_features(events)
        
        # Run anomaly detection
        anomaly_results = {}
        for model_name, model in self.anomaly_models.items():
            try:
                result = model.detect_anomalies(features)
                anomaly_results[model_name] = result
            except Exception as e:
                SecurityLogger.log_security_event(
                    'ml_model_error',
                    'medium',
                    {'model': model_name, 'error': str(e)}
                )
        
        # Generate predictions
        predictions = {}
        for model_name, model in self.prediction_models.items():
            try:
                result = model.predict(features)
                predictions[model_name] = result
            except Exception as e:
                SecurityLogger.log_security_event(
                    'prediction_model_error',
                    'medium',
                    {'model': model_name, 'error': str(e)}
                )
        
        # Combine results and generate insights
        analysis_result = self._combine_ml_results(anomaly_results, predictions, events)
        
        # Store results for continuous learning
        self._update_learning_models(features, analysis_result)
        
        return analysis_result
    
    def _extract_comprehensive_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract comprehensive feature set from security events
        """
        features = {}
        
        for extractor_name, extractor in self.feature_extractors.items():
            try:
                extracted_features = extractor.extract_features(events)
                features[extractor_name] = extracted_features
            except Exception as e:
                SecurityLogger.log_security_event(
                    'feature_extraction_error',
                    'low',
                    {'extractor': extractor_name, 'error': str(e)}
                )
        
        return features
    
    def _combine_ml_results(self, anomaly_results: Dict[str, Any], 
                           predictions: Dict[str, Any], 
                           events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Combine ML model results into comprehensive analysis
        """
        combined_result = {
            'timestamp': datetime.utcnow().isoformat(),
            'events_analyzed': len(events),
            'anomaly_detection': anomaly_results,
            'predictions': predictions,
            'overall_risk_score': 0,
            'threat_level': 'low',
            'recommended_actions': [],
            'confidence_level': 0
        }
        
        # Calculate overall risk score
        risk_factors = []
        
        # Anomaly detection scores
        for model_result in anomaly_results.values():
            if isinstance(model_result, dict) and 'risk_score' in model_result:
                risk_factors.append(model_result['risk_score'])
        
        # Prediction model scores
        for prediction_result in predictions.values():
            if isinstance(prediction_result, dict) and 'risk_score' in prediction_result:
                risk_factors.append(prediction_result['risk_score'])
        
        if risk_factors:
            combined_result['overall_risk_score'] = sum(risk_factors) / len(risk_factors)
            combined_result['confidence_level'] = min(100, len(risk_factors) * 20)
        
        # Determine threat level
        if combined_result['overall_risk_score'] > 80:
            combined_result['threat_level'] = 'critical'
        elif combined_result['overall_risk_score'] > 60:
            combined_result['threat_level'] = 'high'
        elif combined_result['overall_risk_score'] > 40:
            combined_result['threat_level'] = 'medium'
        
        # Generate recommendations
        combined_result['recommended_actions'] = self._generate_recommendations(
            combined_result, anomaly_results, predictions
        )
        
        return combined_result
    
    def _generate_recommendations(self, analysis: Dict[str, Any], 
                                anomaly_results: Dict[str, Any], 
                                predictions: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on ML analysis
        """
        recommendations = []
        
        # High-level recommendations based on threat level
        if analysis['threat_level'] == 'critical':
            recommendations.extend([
                'Implement emergency response protocol',
                'Consider temporary service restrictions',
                'Activate incident response team',
                'Review and update IP blocking rules'
            ])
        elif analysis['threat_level'] == 'high':
            recommendations.extend([
                'Increase monitoring frequency',
                'Review user access permissions',
                'Implement additional authentication steps',
                'Update threat intelligence feeds'
            ])
        
        # Specific recommendations based on anomaly detection
        for model_name, result in anomaly_results.items():
            if isinstance(result, dict) and result.get('anomalies_detected', 0) > 0:
                if model_name == 'isolation_forest':
                    recommendations.append('Investigate isolated suspicious activities')
                elif model_name == 'statistical_analysis':
                    recommendations.append('Review statistical deviations in user behavior')
                elif model_name == 'sequence_analysis':
                    recommendations.append('Analyze unusual request sequences')
        
        # Recommendations based on predictions
        for model_name, result in predictions.items():
            if isinstance(result, dict) and result.get('risk_score', 0) > 60:
                if model_name == 'attack_prediction':
                    recommendations.append('Prepare for potential attack escalation')
                elif model_name == 'user_risk_scoring':
                    recommendations.append('Review high-risk user accounts')
        
        return list(set(recommendations))  # Remove duplicates
    
    def _update_learning_models(self, features: Dict[str, Any], analysis_result: Dict[str, Any]) -> None:
        """
        Update ML models with new data for continuous learning
        """
        # Store features and results for model retraining
        learning_data = {
            'features': features,
            'analysis': analysis_result,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Use cache to store learning data
        learning_key = f"ml_learning_data:{int(datetime.utcnow().timestamp())}"
        cache.set(learning_key, learning_data, timeout=86400 * 7)  # Keep for 7 days


class RequestPatternExtractor:
    """
    Extract features from request patterns
    """
    
    def extract_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract request pattern features
        """
        features = {
            'total_requests': len(events),
            'unique_ips': len(set(event.get('ip_address', '') for event in events)),
            'unique_user_agents': len(set(event.get('user_agent', '') for event in events)),
            'unique_endpoints': len(set(event.get('endpoint', '') for event in events)),
            'method_distribution': defaultdict(int),
            'status_code_distribution': defaultdict(int),
            'request_size_stats': [],
            'response_time_stats': [],
            'error_rate': 0
        }
        
        for event in events:
            # Method distribution
            method = event.get('method', 'unknown')
            features['method_distribution'][method] += 1
            
            # Status code distribution
            status_code = event.get('status_code', 0)
            features['status_code_distribution'][str(status_code)] += 1
            
            # Request size statistics
            request_size = event.get('request_size', 0)
            if request_size > 0:
                features['request_size_stats'].append(request_size)
            
            # Response time statistics
            response_time = event.get('response_time', 0)
            if response_time > 0:
                features['response_time_stats'].append(response_time)
        
        # Calculate statistics
        if features['request_size_stats']:
            features['avg_request_size'] = sum(features['request_size_stats']) / len(features['request_size_stats'])
            features['max_request_size'] = max(features['request_size_stats'])
        
        if features['response_time_stats']:
            features['avg_response_time'] = sum(features['response_time_stats']) / len(features['response_time_stats'])
            features['max_response_time'] = max(features['response_time_stats'])
        
        # Calculate error rate
        error_codes = [code for code in features['status_code_distribution'].keys() 
                      if code.startswith('4') or code.startswith('5')]
        total_errors = sum(features['status_code_distribution'][code] for code in error_codes)
        features['error_rate'] = (total_errors / features['total_requests']) * 100 if features['total_requests'] > 0 else 0
        
        return features


class UserBehaviorExtractor:
    """
    Extract features from user behavior patterns
    """
    
    def extract_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract user behavior features
        """
        user_events = defaultdict(list)
        
        # Group events by user
        for event in events:
            user_id = event.get('user_id')
            if user_id:
                user_events[user_id].append(event)
        
        features = {
            'total_users': len(user_events),
            'user_activity_distribution': {},
            'session_patterns': {},
            'navigation_patterns': {},
            'anomalous_users': []
        }
        
        for user_id, user_event_list in user_events.items():
            user_features = self._analyze_user_events(user_event_list)
            features['user_activity_distribution'][str(user_id)] = user_features
            
            # Detect anomalous behavior
            if self._is_user_behavior_anomalous(user_features):
                features['anomalous_users'].append(user_id)
        
        return features
    
    def _analyze_user_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze events for a specific user
        """
        user_features = {
            'request_count': len(events),
            'unique_endpoints': len(set(event.get('endpoint', '') for event in events)),
            'time_span_minutes': 0,
            'request_frequency': 0,
            'endpoint_diversity': 0
        }
        
        if len(events) > 1:
            timestamps = [event.get('timestamp', 0) for event in events if event.get('timestamp', 0) > 0]
            if timestamps:
                time_span = max(timestamps) - min(timestamps)
                user_features['time_span_minutes'] = time_span / 60
                user_features['request_frequency'] = len(events) / (time_span / 60) if time_span > 0 else 0
        
        # Endpoint diversity score
        if user_features['request_count'] > 0:
            user_features['endpoint_diversity'] = user_features['unique_endpoints'] / user_features['request_count']
        
        return user_features
    
    def _is_user_behavior_anomalous(self, user_features: Dict[str, Any]) -> bool:
        """
        Determine if user behavior is anomalous
        """
        # Simple heuristics for anomaly detection
        anomaly_indicators = []
        
        # Too many requests in short time
        if user_features['request_frequency'] > 10:  # More than 10 requests per minute
            anomaly_indicators.append('high_frequency')
        
        # Too much endpoint diversity (potential scanning)
        if user_features['endpoint_diversity'] > 0.8:
            anomaly_indicators.append('high_endpoint_diversity')
        
        # Very short time span with many requests
        if user_features['request_count'] > 20 and user_features['time_span_minutes'] < 1:
            anomaly_indicators.append('burst_activity')
        
        return len(anomaly_indicators) >= 2


class NetworkAnalysisExtractor:
    """
    Extract network-level features
    """
    
    def extract_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract network analysis features
        """
        ip_analysis = defaultdict(lambda: {
            'request_count': 0,
            'unique_endpoints': set(),
            'user_agents': set(),
            'methods': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        for event in events:
            ip_address = event.get('ip_address', 'unknown')
            timestamp = event.get('timestamp', 0)
            
            ip_data = ip_analysis[ip_address]
            ip_data['request_count'] += 1
            ip_data['unique_endpoints'].add(event.get('endpoint', ''))
            ip_data['user_agents'].add(event.get('user_agent', ''))
            ip_data['methods'].add(event.get('method', ''))
            
            if ip_data['first_seen'] is None or timestamp < ip_data['first_seen']:
                ip_data['first_seen'] = timestamp
            
            if ip_data['last_seen'] is None or timestamp > ip_data['last_seen']:
                ip_data['last_seen'] = timestamp
        
        # Calculate network features
        features = {
            'unique_ips': len(ip_analysis),
            'ip_request_distribution': {},
            'suspicious_ips': [],
            'distributed_attack_indicators': 0
        }
        
        for ip_address, ip_data in ip_analysis.items():
            ip_features = {
                'request_count': ip_data['request_count'],
                'endpoint_count': len(ip_data['unique_endpoints']),
                'user_agent_count': len(ip_data['user_agents']),
                'method_count': len(ip_data['methods']),
                'activity_duration': ip_data['last_seen'] - ip_data['first_seen'] if ip_data['last_seen'] and ip_data['first_seen'] else 0
            }
            
            features['ip_request_distribution'][ip_address] = ip_features
            
            # Identify suspicious IPs
            if self._is_ip_suspicious(ip_features):
                features['suspicious_ips'].append(ip_address)
        
        # Detect distributed attack patterns
        if len(features['suspicious_ips']) >= 3:
            features['distributed_attack_indicators'] += 1
        
        return features
    
    def _is_ip_suspicious(self, ip_features: Dict[str, Any]) -> bool:
        """
        Determine if IP behavior is suspicious
        """
        suspicious_indicators = 0
        
        # High request count
        if ip_features['request_count'] > 100:
            suspicious_indicators += 1
        
        # Many different endpoints (scanning)
        if ip_features['endpoint_count'] > 20:
            suspicious_indicators += 1
        
        # Multiple user agents (possible bot rotation)
        if ip_features['user_agent_count'] > 3:
            suspicious_indicators += 1
        
        # High request rate
        if ip_features['activity_duration'] > 0:
            request_rate = ip_features['request_count'] / (ip_features['activity_duration'] / 60)
            if request_rate > 5:  # More than 5 requests per minute
                suspicious_indicators += 1
        
        return suspicious_indicators >= 2


class TemporalPatternExtractor:
    """
    Extract temporal pattern features
    """
    
    def extract_features(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract temporal pattern features
        """
        timestamps = [event.get('timestamp', 0) for event in events if event.get('timestamp', 0) > 0]
        
        if not timestamps:
            return {'no_temporal_data': True}
        
        timestamps.sort()
        
        features = {
            'time_span_hours': (max(timestamps) - min(timestamps)) / 3600,
            'request_intervals': [],
            'peak_activity_periods': [],
            'temporal_anomalies': 0
        }
        
        # Calculate intervals between requests
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            features['request_intervals'].append(interval)
        
        # Analyze request patterns by hour
        hourly_requests = defaultdict(int)
        for timestamp in timestamps:
            hour = datetime.fromtimestamp(timestamp).hour
            hourly_requests[hour] += 1
        
        # Identify peak periods
        avg_hourly_requests = sum(hourly_requests.values()) / len(hourly_requests) if hourly_requests else 0
        
        for hour, count in hourly_requests.items():
            if count > avg_hourly_requests * 2:  # More than 2x average
                features['peak_activity_periods'].append(hour)
        
        # Detect temporal anomalies
        if features['request_intervals']:
            avg_interval = sum(features['request_intervals']) / len(features['request_intervals'])
            
            for interval in features['request_intervals']:
                # Very short intervals might indicate automated attacks
                if interval < avg_interval * 0.1:  # Less than 10% of average
                    features['temporal_anomalies'] += 1
        
        return features


class IsolationForestDetector:
    """
    Isolation Forest-based anomaly detection
    """
    
    def detect_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies using Isolation Forest algorithm (simplified version)
        """
        # This is a simplified implementation
        # In production, you would use scikit-learn's IsolationForest
        
        result = {
            'model_type': 'isolation_forest',
            'anomalies_detected': 0,
            'risk_score': 0,
            'anomalous_features': []
        }
        
        # Simplified anomaly detection based on feature analysis
        request_patterns = features.get('request_patterns', {})
        
        # Check for anomalous patterns
        if request_patterns.get('error_rate', 0) > 20:  # High error rate
            result['anomalies_detected'] += 1
            result['anomalous_features'].append('high_error_rate')
            result['risk_score'] += 30
        
        if request_patterns.get('unique_ips', 0) > request_patterns.get('total_requests', 1) * 0.8:
            result['anomalies_detected'] += 1
            result['anomalous_features'].append('too_many_unique_ips')
            result['risk_score'] += 25
        
        return result


class StatisticalAnomalyDetector:
    """
    Statistical-based anomaly detection
    """
    
    def detect_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies using statistical analysis
        """
        result = {
            'model_type': 'statistical_analysis',
            'anomalies_detected': 0,
            'risk_score': 0,
            'statistical_deviations': []
        }
        
        # Analyze user behavior features
        user_behavior = features.get('user_behavior', {})
        
        if user_behavior.get('anomalous_users'):
            result['anomalies_detected'] = len(user_behavior['anomalous_users'])
            result['risk_score'] = min(100, result['anomalies_detected'] * 20)
            result['statistical_deviations'].append('anomalous_user_behavior')
        
        # Analyze network features
        network_analysis = features.get('network_analysis', {})
        
        if network_analysis.get('suspicious_ips'):
            result['anomalies_detected'] += len(network_analysis['suspicious_ips'])
            result['risk_score'] += min(50, len(network_analysis['suspicious_ips']) * 15)
            result['statistical_deviations'].append('suspicious_ip_behavior')
        
        return result


class SequenceAnomalyDetector:
    """
    Sequence-based anomaly detection
    """
    
    def detect_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies in request sequences
        """
        result = {
            'model_type': 'sequence_analysis',
            'anomalies_detected': 0,
            'risk_score': 0,
            'sequence_anomalies': []
        }
        
        # Analyze temporal patterns
        temporal_patterns = features.get('temporal_patterns', {})
        
        if temporal_patterns.get('temporal_anomalies', 0) > 5:
            result['anomalies_detected'] += 1
            result['risk_score'] += 35
            result['sequence_anomalies'].append('unusual_request_timing')
        
        if len(temporal_patterns.get('peak_activity_periods', [])) > 12:  # Active in most hours
            result['anomalies_detected'] += 1
            result['risk_score'] += 20
            result['sequence_anomalies'].append('continuous_activity')
        
        return result


class ClusteringAnomalyDetector:
    """
    Clustering-based anomaly detection
    """
    
    def detect_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies using clustering analysis
        """
        result = {
            'model_type': 'clustering_analysis',
            'anomalies_detected': 0,
            'risk_score': 0,
            'clusters_identified': 0
        }
        
        # Simple clustering analysis based on IP patterns
        network_analysis = features.get('network_analysis', {})
        
        if network_analysis.get('distributed_attack_indicators', 0) > 0:
            result['anomalies_detected'] += 1
            result['risk_score'] += 40
            result['clusters_identified'] = 1
        
        return result


class AttackPredictionModel:
    """
    Model for predicting potential attacks
    """
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict potential attack probability
        """
        prediction = {
            'model_type': 'attack_prediction',
            'attack_probability': 0.0,
            'predicted_attack_types': [],
            'risk_score': 0,
            'confidence': 0
        }
        
        # Simple prediction based on current features
        request_patterns = features.get('request_patterns', {})
        network_analysis = features.get('network_analysis', {})
        
        risk_factors = 0
        
        # High error rate indicates potential probing
        if request_patterns.get('error_rate', 0) > 15:
            risk_factors += 1
            prediction['predicted_attack_types'].append('reconnaissance')
        
        # Multiple suspicious IPs
        if len(network_analysis.get('suspicious_ips', [])) > 2:
            risk_factors += 1
            prediction['predicted_attack_types'].append('distributed_attack')
        
        # High endpoint diversity
        total_requests = request_patterns.get('total_requests', 1)
        unique_endpoints = request_patterns.get('unique_endpoints', 0)
        
        if unique_endpoints / total_requests > 0.5:
            risk_factors += 1
            prediction['predicted_attack_types'].append('scanning')
        
        prediction['attack_probability'] = min(1.0, risk_factors * 0.3)
        prediction['risk_score'] = risk_factors * 25
        prediction['confidence'] = min(100, risk_factors * 30)
        
        return prediction


class UserRiskScoringModel:
    """
    Model for scoring user risk levels
    """
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate user risk scores
        """
        prediction = {
            'model_type': 'user_risk_scoring',
            'high_risk_users': [],
            'risk_score': 0,
            'total_users_analyzed': 0
        }
        
        user_behavior = features.get('user_behavior', {})
        prediction['total_users_analyzed'] = user_behavior.get('total_users', 0)
        
        anomalous_users = user_behavior.get('anomalous_users', [])
        prediction['high_risk_users'] = anomalous_users
        
        if anomalous_users:
            # Calculate risk score based on percentage of anomalous users
            total_users = prediction['total_users_analyzed']
            if total_users > 0:
                anomalous_percentage = len(anomalous_users) / total_users
                prediction['risk_score'] = min(100, anomalous_percentage * 100)
        
        return prediction


class ThreatEvolutionModel:
    """
    Model for analyzing threat evolution patterns
    """
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze threat evolution trends
        """
        prediction = {
            'model_type': 'threat_evolution',
            'evolution_indicators': [],
            'trend_direction': 'stable',
            'risk_score': 0
        }
        
        # Analyze temporal patterns for evolution
        temporal_patterns = features.get('temporal_patterns', {})
        
        if temporal_patterns.get('temporal_anomalies', 0) > 0:
            prediction['evolution_indicators'].append('timing_pattern_changes')
            prediction['risk_score'] += 20
        
        # Analyze network patterns
        network_analysis = features.get('network_analysis', {})
        
        if network_analysis.get('distributed_attack_indicators', 0) > 0:
            prediction['evolution_indicators'].append('attack_distribution_increase')
            prediction['risk_score'] += 30
            prediction['trend_direction'] = 'escalating'
        
        return prediction