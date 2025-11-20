"""
Advanced Threat Detection Middleware
Real-time integration with ML-based detection, pattern recognition, and threat intelligence
Expert Blue Team Implementation - ETH Standards
"""
import json
import time
from typing import Dict, Any, Optional
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.conf import settings
from .threat_detection import (
    MLBasedAnomalyDetector,
    AdvancedPatternRecognition,
    RealTimeThreatIntelligence
)
from .security_core import SecurityLogger


class ThreatDetectionMiddleware(MiddlewareMixin):
    """
    Main threat detection middleware integrating all detection engines
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.anomaly_detector = MLBasedAnomalyDetector()
        self.pattern_recognizer = AdvancedPatternRecognition()
        self.threat_intelligence = RealTimeThreatIntelligence()
        self.max_requests_per_minute = 300  # Configurable rate limit
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request through threat detection engines
        """
        start_time = time.time()
        
        # Extract request data for analysis
        request_data = self._extract_request_data(request)
        
        # Stage 1: IP Reputation Check
        ip_reputation = self.threat_intelligence.check_ip_reputation(request_data['ip_address'])
        
        if ip_reputation['threat_level'] == 'critical':
            SecurityLogger.log_security_event(
                'critical_threat_blocked',
                'critical',
                {
                    'ip_address': request_data['ip_address'],
                    'reputation': ip_reputation,
                    'request_path': request.path
                }
            )
            return JsonResponse(
                {'error': 'Access denied', 'code': 'THREAT_DETECTED'}, 
                status=403
            )
        
        # Stage 2: Rate Limiting with Behavioral Analysis
        rate_limit_result = self._check_rate_limits(request_data)
        
        if rate_limit_result['blocked']:
            return JsonResponse(
                {'error': 'Rate limit exceeded', 'retry_after': rate_limit_result['retry_after']},
                status=429
            )
        
        # Stage 3: Advanced Pattern Recognition
        pattern_analysis = self.pattern_recognizer.analyze_request_for_attacks(request_data)
        
        if pattern_analysis['total_risk_score'] > 150:  # High-risk threshold
            SecurityLogger.log_security_event(
                'high_risk_attack_blocked',
                'high',
                {
                    'request_data': request_data,
                    'pattern_analysis': pattern_analysis
                }
            )
            return JsonResponse(
                {'error': 'Malicious request detected', 'code': 'ATTACK_PATTERN'},
                status=403
            )
        
        # Stage 4: ML-Based Anomaly Detection (for authenticated users)
        if hasattr(request, 'user') and request.user.is_authenticated:
            anomaly_result = self.anomaly_detector.analyze_user_behavior(
                request.user.id, request_data
            )
            
            if anomaly_result['anomaly_detected'] and anomaly_result['anomaly_score'] > 70:
                # Don't block, but increase monitoring
                self._increase_user_monitoring(request.user.id)
                
                SecurityLogger.log_security_event(
                    'user_anomaly_high_score',
                    'medium',
                    {
                        'user_id': request.user.id,
                        'anomaly_result': anomaly_result
                    }
                )
        
        # Stage 5: Coordinated Attack Detection
        coordinated_attack = self.anomaly_detector.detect_coordinated_attacks(request_data)
        
        if coordinated_attack['coordinated_attack'] and coordinated_attack['attack_score'] > 60:
            # Implement temporary IP blocking
            self._implement_temporary_block(request_data['ip_address'], duration=300)  # 5 minutes
            
            return JsonResponse(
                {'error': 'Coordinated attack detected', 'code': 'COORDINATED_ATTACK'},
                status=403
            )
        
        # Store threat analysis results in request for use by other middleware/views
        request.threat_analysis = {
            'ip_reputation': ip_reputation,
            'pattern_analysis': pattern_analysis,
            'anomaly_result': getattr(request, 'anomaly_result', None),
            'coordinated_attack': coordinated_attack,
            'processing_time': time.time() - start_time
        }
        
        return None
    
    def _extract_request_data(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Extract relevant data from Django request
        """
        # Get client IP (handle proxies)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0].strip()
        else:
            ip_address = request.META.get('REMOTE_ADDR', 'unknown')
        
        # Extract parameters from all sources
        parameters = {}
        parameters.update(request.GET.dict())
        
        if request.content_type == 'application/json':
            try:
                parameters.update(json.loads(request.body.decode('utf-8')))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        else:
            parameters.update(request.POST.dict())
        
        return {
            'ip_address': ip_address,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'endpoint': request.path,
            'method': request.method,
            'parameters': parameters,
            'query_string': request.META.get('QUERY_STRING', ''),
            'headers': dict(request.headers),
            'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
            'timestamp': time.time()
        }
    
    def _check_rate_limits(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Advanced rate limiting with behavioral analysis
        """
        ip_address = request_data['ip_address']
        current_time = time.time()
        
        # Per-IP rate limiting
        ip_key = f"rate_limit:ip:{ip_address}"
        ip_requests = cache.get(ip_key, [])
        
        # Remove old requests (older than 1 minute)
        ip_requests = [req_time for req_time in ip_requests if current_time - req_time < 60]
        ip_requests.append(current_time)
        
        cache.set(ip_key, ip_requests, timeout=60)
        
        result = {'blocked': False, 'retry_after': 0}
        
        # Check if exceeding rate limit
        if len(ip_requests) > self.max_requests_per_minute:
            result['blocked'] = True
            result['retry_after'] = 60
            
            SecurityLogger.log_security_event(
                'rate_limit_exceeded',
                'medium',
                {
                    'ip_address': ip_address,
                    'request_count': len(ip_requests),
                    'time_window': 60
                }
            )
        
        # Per-user rate limiting (if authenticated)
        user_id = request_data.get('user_id')
        if user_id:
            user_key = f"rate_limit:user:{user_id}"
            user_requests = cache.get(user_key, [])
            
            user_requests = [req_time for req_time in user_requests if current_time - req_time < 60]
            user_requests.append(current_time)
            
            cache.set(user_key, user_requests, timeout=60)
            
            # Higher limit for authenticated users
            if len(user_requests) > self.max_requests_per_minute * 2:
                result['blocked'] = True
                result['retry_after'] = max(result['retry_after'], 60)
        
        return result
    
    def _increase_user_monitoring(self, user_id: int) -> None:
        """
        Increase monitoring level for suspicious user
        """
        monitoring_key = f"user_monitoring:{user_id}"
        monitoring_data = cache.get(monitoring_key, {'level': 0, 'expires': time.time() + 3600})
        
        monitoring_data['level'] = min(monitoring_data['level'] + 1, 5)  # Max level 5
        monitoring_data['expires'] = time.time() + 3600  # Extend for 1 hour
        
        cache.set(monitoring_key, monitoring_data, timeout=3600)
    
    def _implement_temporary_block(self, ip_address: str, duration: int) -> None:
        """
        Implement temporary IP blocking
        """
        block_key = f"ip_blocked:{ip_address}"
        cache.set(block_key, True, timeout=duration)
        
        SecurityLogger.log_security_event(
            'temporary_ip_block_implemented',
            'high',
            {
                'ip_address': ip_address,
                'duration': duration,
                'reason': 'coordinated_attack_detection'
            }
        )


class IPReputationMiddleware(MiddlewareMixin):
    """
    Dedicated middleware for IP reputation and geolocation blocking
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.threat_intelligence = RealTimeThreatIntelligence()
        self.blocked_countries = getattr(settings, 'BLOCKED_COUNTRIES', [])
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Check IP reputation before processing request
        """
        # Check if IP is temporarily blocked
        ip_address = self._get_client_ip(request)
        
        block_key = f"ip_blocked:{ip_address}"
        if cache.get(block_key):
            return JsonResponse(
                {'error': 'IP temporarily blocked', 'code': 'IP_BLOCKED'},
                status=403
            )
        
        # Check IP reputation
        reputation = self.threat_intelligence.check_ip_reputation(ip_address)
        
        if reputation['is_malicious'] and reputation['threat_level'] in ['high', 'critical']:
            SecurityLogger.log_security_event(
                'malicious_ip_blocked',
                reputation['threat_level'],
                {
                    'ip_address': ip_address,
                    'reputation': reputation,
                    'request_path': request.path
                }
            )
            
            return JsonResponse(
                {'error': 'Access denied - malicious IP', 'code': 'MALICIOUS_IP'},
                status=403
            )
        
        # Store reputation in request for other middleware
        request.ip_reputation = reputation
        
        return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address handling proxy headers
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class BehavioralAnalysisMiddleware(MiddlewareMixin):
    """
    Middleware for continuous behavioral analysis and adaptive security
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.anomaly_detector = MLBasedAnomalyDetector()
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Perform behavioral analysis on request patterns
        """
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return None
        
        # Extract behavioral data
        request_data = {
            'endpoint': request.path,
            'method': request.method,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'ip_address': self._get_client_ip(request),
            'parameters': {**request.GET.dict(), **request.POST.dict()},
            'timestamp': time.time()
        }
        
        # Analyze user behavior
        anomaly_result = self.anomaly_detector.analyze_user_behavior(
            request.user.id, request_data
        )
        
        # Store results in request
        request.behavioral_analysis = anomaly_result
        
        # Implement adaptive security measures
        if anomaly_result['anomaly_detected']:
            self._apply_adaptive_security(request, anomaly_result)
        
        return None
    
    def _apply_adaptive_security(self, request: HttpRequest, anomaly_result: Dict[str, Any]) -> None:
        """
        Apply adaptive security measures based on anomaly score
        """
        score = anomaly_result['anomaly_score']
        user_id = request.user.id
        
        # Increase session timeout frequency
        if score > 30:
            request.session.set_expiry(1800)  # 30 minutes instead of default
        
        # Require additional verification for high scores
        if score > 60:
            request.session['require_reverification'] = True
            request.session['anomaly_detected'] = True
        
        # Log for security team review
        if score > 50:
            SecurityLogger.log_security_event(
                'adaptive_security_applied',
                'medium',
                {
                    'user_id': user_id,
                    'anomaly_score': score,
                    'reasons': anomaly_result['anomaly_reasons'],
                    'security_measures': ['session_timeout_reduced']
                }
            )
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class GraphQLSecurityMiddleware(MiddlewareMixin):
    """
    Specialized middleware for GraphQL security
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.pattern_recognizer = AdvancedPatternRecognition()
        self.max_query_depth = 10
        self.max_query_complexity = 1000
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Analyze GraphQL requests for security issues
        """
        # Only process GraphQL endpoints
        if not request.path.startswith('/graphql'):
            return None
        
        if request.method == 'POST' and request.content_type == 'application/json':
            try:
                body = json.loads(request.body.decode('utf-8'))
                query = body.get('query', '')
                
                # Analyze query for security issues
                analysis = self._analyze_graphql_query(query)
                
                if analysis['blocked']:
                    SecurityLogger.log_security_event(
                        'graphql_security_violation',
                        'high',
                        {
                            'query': query[:500],  # Truncate for logging
                            'analysis': analysis,
                            'ip_address': request.META.get('REMOTE_ADDR')
                        }
                    )
                    
                    return JsonResponse(
                        {'error': 'GraphQL security violation', 'details': analysis['reasons']},
                        status=403
                    )
                
                # Store analysis in request
                request.graphql_analysis = analysis
                
            except (json.JSONDecodeError, UnicodeDecodeError):
                return JsonResponse(
                    {'error': 'Invalid GraphQL request'},
                    status=400
                )
        
        return None
    
    def _analyze_graphql_query(self, query: str) -> Dict[str, Any]:
        """
        Analyze GraphQL query for security violations
        """
        analysis = {
            'blocked': False,
            'reasons': [],
            'risk_score': 0,
            'depth': 0,
            'complexity': 0
        }
        
        # Check for introspection queries
        if any(keyword in query.lower() for keyword in ['__schema', '__type', '__field']):
            analysis['blocked'] = True
            analysis['reasons'].append('Introspection query detected')
            analysis['risk_score'] += 50
        
        # Check query depth
        depth = self._calculate_query_depth(query)
        analysis['depth'] = depth
        
        if depth > self.max_query_depth:
            analysis['blocked'] = True
            analysis['reasons'].append(f'Query depth ({depth}) exceeds maximum ({self.max_query_depth})')
            analysis['risk_score'] += 30
        
        # Check for mutation attempts on sensitive operations
        if 'mutation' in query.lower():
            sensitive_operations = ['delete', 'update', 'create', 'admin']
            for operation in sensitive_operations:
                if operation in query.lower():
                    analysis['risk_score'] += 20
                    if analysis['risk_score'] > 100:
                        analysis['blocked'] = True
                        analysis['reasons'].append('High-risk mutation detected')
        
        # Use pattern recognizer for additional checks
        pattern_result = self.pattern_recognizer.analyze_request_for_attacks({'query': query})
        if pattern_result['total_risk_score'] > 50:
            analysis['blocked'] = True
            analysis['reasons'].extend([f"Attack pattern: {attack}" for attack in pattern_result['attacks_detected']])
            analysis['risk_score'] += pattern_result['total_risk_score']
        
        return analysis
    
    def _calculate_query_depth(self, query: str) -> int:
        """
        Calculate the depth of a GraphQL query
        """
        depth = 0
        current_depth = 0
        
        for char in query:
            if char == '{':
                current_depth += 1
                depth = max(depth, current_depth)
            elif char == '}':
                current_depth -= 1
        
        return depth