"""
Advanced Injection Prevention Middleware for HealthProgress
Real-time Multi-Vector Injection Attack Prevention
Expert Blue Team Implementation - ETH Standards
"""
import json
import time
from typing import Dict, Any, Optional, List
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.html import escape
from .injection_prevention import MultiVectorInjectionDetector
from .security_core import SecurityLogger


class InjectionPreventionMiddleware(MiddlewareMixin):
    """
    Main middleware for preventing injection attacks across all vectors
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.injection_detector = MultiVectorInjectionDetector()
        self.risk_threshold = getattr(settings, 'INJECTION_RISK_THRESHOLD', 80)
        self.auto_sanitize = getattr(settings, 'AUTO_SANITIZE_INPUTS', True)
        self.blocked_patterns_cache_ttl = 300  # 5 minutes
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process request for injection attacks
        """
        start_time = time.time()
        
        # Skip certain paths that don't need injection checking
        skip_paths = ['/static/', '/media/', '/favicon.ico', '/robots.txt']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Extract all input data from request
        input_data = self._extract_request_inputs(request)
        
        # Perform comprehensive injection scan
        scan_results = self.injection_detector.comprehensive_injection_scan(
            input_data, 
            context=f"{request.method}:{request.path}"
        )
        
        # Store scan results in request for other middleware/views
        request.injection_scan = scan_results
        request.injection_processing_time = time.time() - start_time
        
        # Check if we should block the request
        if scan_results['overall_malicious'] and scan_results['total_risk_score'] > self.risk_threshold:
            # Log high-risk injection attempt
            SecurityLogger.log_security_event(
                'injection_attack_blocked',
                'high',
                {
                    'ip_address': self._get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'path': request.path,
                    'method': request.method,
                    'scan_results': scan_results,
                    'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None
                }
            )
            
            # Implement temporary IP blocking for repeat offenders
            self._implement_injection_blocking(request, scan_results)
            
            return JsonResponse({
                'error': 'Malicious input detected',
                'code': 'INJECTION_ATTACK',
                'details': 'Your request contains patterns associated with injection attacks'
            }, status=403)
        
        # Auto-sanitize inputs if enabled and low-medium risk
        elif scan_results['overall_malicious'] and self.auto_sanitize:
            self._sanitize_request_inputs(request, scan_results)
            
            # Log sanitization action
            SecurityLogger.log_security_event(
                'input_auto_sanitized',
                'medium',
                {
                    'path': request.path,
                    'risk_score': scan_results['total_risk_score'],
                    'attacks_sanitized': [attack['type'] for attack in scan_results['detected_attacks']]
                }
            )
        
        return None
    
    def _extract_request_inputs(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Extract all inputs from HTTP request
        """
        inputs = {}
        
        # GET parameters
        for key, value in request.GET.items():
            inputs[f'GET_{key}'] = value
        
        # POST parameters
        for key, value in request.POST.items():
            inputs[f'POST_{key}'] = value
        
        # JSON body (for API requests)
        if request.content_type == 'application/json':
            try:
                json_data = json.loads(request.body.decode('utf-8'))
                if isinstance(json_data, dict):
                    for key, value in json_data.items():
                        inputs[f'JSON_{key}'] = value
                else:
                    inputs['JSON_body'] = json_data
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        
        # Headers (selected security-relevant ones)
        security_headers = ['HTTP_USER_AGENT', 'HTTP_REFERER', 'HTTP_X_FORWARDED_FOR']
        for header in security_headers:
            if header in request.META:
                inputs[f'HEADER_{header}'] = request.META[header]
        
        # URL path and query string
        inputs['URL_path'] = request.path
        inputs['URL_query'] = request.META.get('QUERY_STRING', '')
        
        return inputs
    
    def _sanitize_request_inputs(self, request: HttpRequest, scan_results: Dict[str, Any]) -> None:
        """
        Sanitize request inputs based on detected attack types
        """
        detected_types = [attack['type'] for attack in scan_results['detected_attacks']]
        
        # Sanitize GET parameters
        sanitized_get = {}
        for key, value in request.GET.items():
            sanitized_value = self.injection_detector.sanitize_input(value, detected_types)
            sanitized_get[key] = sanitized_value
        
        # Replace GET QueryDict with sanitized version
        request.GET = request.GET.copy()
        request.GET.clear()
        request.GET.update(sanitized_get)
        
        # Sanitize POST parameters
        sanitized_post = {}
        for key, value in request.POST.items():
            sanitized_value = self.injection_detector.sanitize_input(value, detected_types)
            sanitized_post[key] = sanitized_value
        
        # Replace POST QueryDict with sanitized version
        request.POST = request.POST.copy()
        request.POST.clear()
        request.POST.update(sanitized_post)
    
    def _implement_injection_blocking(self, request: HttpRequest, scan_results: Dict[str, Any]) -> None:
        """
        Implement blocking measures for injection attacks
        """
        client_ip = self._get_client_ip(request)
        
        # Track injection attempts per IP
        attempts_key = f"injection_attempts:{client_ip}"
        attempts = cache.get(attempts_key, 0)
        attempts += 1
        
        # Escalating blocking durations
        if attempts >= 5:
            block_duration = 3600  # 1 hour for repeat offenders
        elif attempts >= 3:
            block_duration = 1800  # 30 minutes
        else:
            block_duration = 300   # 5 minutes for first attempts
        
        # Implement IP block
        block_key = f"injection_blocked:{client_ip}"
        cache.set(block_key, {
            'blocked_at': time.time(),
            'reason': 'injection_attack',
            'attempts': attempts,
            'scan_results': scan_results
        }, timeout=block_duration)
        
        # Update attempts counter
        cache.set(attempts_key, attempts, timeout=86400)  # Track for 24 hours
        
        SecurityLogger.log_security_event(
            'injection_ip_blocked',
            'high',
            {
                'ip_address': client_ip,
                'attempts': attempts,
                'block_duration': block_duration,
                'risk_score': scan_results['total_risk_score']
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


class AdvancedSQLProtectionMiddleware(MiddlewareMixin):
    """
    Specialized middleware for advanced SQL injection protection
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.sql_detector = MultiVectorInjectionDetector().detectors['sql']
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Advanced SQL injection protection
        """
        # Focus on database-heavy endpoints
        database_endpoints = ['/api/', '/search/', '/filter/', '/query/']
        
        if not any(request.path.startswith(endpoint) for endpoint in database_endpoints):
            return None
        
        # Check all parameters for SQL injection
        all_params = {**request.GET.dict(), **request.POST.dict()}
        
        for param_name, param_value in all_params.items():
            sql_result = self.sql_detector.detect_sql_injection(param_value)
            
            if sql_result['is_malicious'] and sql_result['confidence'] > 70:
                SecurityLogger.log_security_event(
                    'advanced_sql_injection_blocked',
                    'high',
                    {
                        'parameter': param_name,
                        'value_hash': hash(param_value),
                        'confidence': sql_result['confidence'],
                        'patterns': sql_result['detected_patterns'],
                        'ip_address': self._get_client_ip(request)
                    }
                )
                
                return JsonResponse({
                    'error': 'SQL injection detected',
                    'parameter': param_name,
                    'code': 'SQL_INJECTION'
                }, status=403)
        
        return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class TemplateInjectionMiddleware(MiddlewareMixin):
    """
    Specialized middleware for template injection protection
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.template_detector = MultiVectorInjectionDetector().detectors['template']
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Protect against template injection attacks
        """
        # Focus on content creation/editing endpoints
        template_sensitive_endpoints = ['/create/', '/edit/', '/update/', '/comment/', '/message/']
        
        if not any(request.path.startswith(endpoint) for endpoint in template_sensitive_endpoints):
            return None
        
        # Check text fields for template injection
        text_fields = []
        
        # Collect text data from various sources
        for key, value in request.POST.items():
            if isinstance(value, str) and len(value) > 10:  # Focus on substantial text
                text_fields.append((key, value))
        
        # Check JSON body for text fields
        if request.content_type == 'application/json':
            try:
                json_data = json.loads(request.body.decode('utf-8'))
                if isinstance(json_data, dict):
                    for key, value in json_data.items():
                        if isinstance(value, str) and len(value) > 10:
                            text_fields.append((f'json_{key}', value))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        
        # Analyze text fields for template injection
        for field_name, field_value in text_fields:
            template_result = self.template_detector.detect_template_injection(field_value)
            
            if template_result['is_malicious'] and template_result['confidence'] > 60:
                SecurityLogger.log_security_event(
                    'template_injection_blocked',
                    'high',
                    {
                        'field': field_name,
                        'confidence': template_result['confidence'],
                        'patterns': template_result['detected_patterns'][:5],  # Limit patterns logged
                        'ip_address': self._get_client_ip(request),
                        'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None
                    }
                )
                
                return JsonResponse({
                    'error': 'Template injection detected',
                    'field': field_name,
                    'code': 'TEMPLATE_INJECTION'
                }, status=403)
        
        return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class CodeInjectionMiddleware(MiddlewareMixin):
    """
    Specialized middleware for code injection protection
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.code_detector = MultiVectorInjectionDetector().detectors['code']
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Protect against code injection attacks
        """
        # Check all input parameters for code injection
        all_inputs = {}
        
        # Collect all inputs
        all_inputs.update(request.GET.dict())
        all_inputs.update(request.POST.dict())
        
        # Check JSON inputs
        if request.content_type == 'application/json':
            try:
                json_data = json.loads(request.body.decode('utf-8'))
                if isinstance(json_data, dict):
                    all_inputs.update(json_data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        
        # Analyze inputs for code injection
        for input_name, input_value in all_inputs.items():
            if not isinstance(input_value, str):
                input_value = str(input_value)
            
            # Skip very short inputs
            if len(input_value) < 5:
                continue
            
            code_result = self.code_detector.detect_code_injection(input_value)
            
            if code_result['is_malicious'] and code_result['confidence'] > 50:
                SecurityLogger.log_security_event(
                    'code_injection_blocked',
                    'critical',
                    {
                        'input': input_name,
                        'confidence': code_result['confidence'],
                        'patterns': code_result['detected_patterns'],
                        'ip_address': self._get_client_ip(request),
                        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                        'path': request.path
                    }
                )
                
                return JsonResponse({
                    'error': 'Code injection detected',
                    'input': input_name,
                    'code': 'CODE_INJECTION'
                }, status=403)
        
        return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class LDAPXPathProtectionMiddleware(MiddlewareMixin):
    """
    Specialized middleware for LDAP and XPath injection protection
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.ldap_detector = MultiVectorInjectionDetector().detectors['ldap']
        self.xpath_detector = MultiVectorInjectionDetector().detectors['xpath']
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Protect against LDAP and XPath injection attacks
        """
        # Focus on search and authentication endpoints
        sensitive_endpoints = ['/search/', '/auth/', '/login/', '/directory/', '/lookup/']
        
        if not any(request.path.startswith(endpoint) for endpoint in sensitive_endpoints):
            return None
        
        # Check search parameters
        search_params = []
        
        for key, value in request.GET.items():
            if 'search' in key.lower() or 'query' in key.lower() or 'filter' in key.lower():
                search_params.append((key, value))
        
        for key, value in request.POST.items():
            if 'search' in key.lower() or 'query' in key.lower() or 'filter' in key.lower():
                search_params.append((key, value))
        
        # Analyze search parameters
        for param_name, param_value in search_params:
            # Check for LDAP injection
            ldap_result = self.ldap_detector.detect_ldap_injection(param_value)
            if ldap_result['is_malicious'] and ldap_result['confidence'] > 60:
                SecurityLogger.log_security_event(
                    'ldap_injection_blocked',
                    'high',
                    {
                        'parameter': param_name,
                        'confidence': ldap_result['confidence'],
                        'patterns': ldap_result['detected_patterns'],
                        'ip_address': self._get_client_ip(request)
                    }
                )
                
                return JsonResponse({
                    'error': 'LDAP injection detected',
                    'parameter': param_name,
                    'code': 'LDAP_INJECTION'
                }, status=403)
            
            # Check for XPath injection
            xpath_result = self.xpath_detector.detect_xpath_injection(param_value)
            if xpath_result['is_malicious'] and xpath_result['confidence'] > 60:
                SecurityLogger.log_security_event(
                    'xpath_injection_blocked',
                    'high',
                    {
                        'parameter': param_name,
                        'confidence': xpath_result['confidence'],
                        'patterns': xpath_result['detected_patterns'],
                        'ip_address': self._get_client_ip(request)
                    }
                )
                
                return JsonResponse({
                    'error': 'XPath injection detected',
                    'parameter': param_name,
                    'code': 'XPATH_INJECTION'
                }, status=403)
        
        return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class InjectionAnalyticsMiddleware(MiddlewareMixin):
    """
    Analytics and reporting middleware for injection attacks
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Analyze injection scan results and generate analytics
        """
        if not hasattr(request, 'injection_scan'):
            return response
        
        scan_results = request.injection_scan
        processing_time = getattr(request, 'injection_processing_time', 0)
        
        # Store analytics data
        analytics_data = {
            'timestamp': time.time(),
            'path': request.path,
            'method': request.method,
            'malicious': scan_results['overall_malicious'],
            'risk_score': scan_results['total_risk_score'],
            'attack_types': [attack['type'] for attack in scan_results['detected_attacks']],
            'processing_time': processing_time,
            'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
            'ip_address': self._get_client_ip(request)
        }
        
        # Cache analytics for reporting dashboard
        analytics_key = f"injection_analytics:{int(time.time())}"
        cache.set(analytics_key, analytics_data, timeout=86400)  # Keep for 24 hours
        
        # Update summary statistics
        self._update_injection_statistics(analytics_data)
        
        # Add security headers to response
        if scan_results['overall_malicious']:
            response['X-Security-Scan'] = 'malicious-detected'
            response['X-Risk-Score'] = str(scan_results['total_risk_score'])
        else:
            response['X-Security-Scan'] = 'clean'
        
        return response
    
    def _update_injection_statistics(self, analytics_data: Dict[str, Any]) -> None:
        """
        Update injection attack statistics
        """
        stats_key = "injection_stats_hourly"
        current_hour = int(time.time() // 3600) * 3600  # Round to hour
        
        # Get existing stats
        stats = cache.get(stats_key, {})
        
        if current_hour not in stats:
            stats[current_hour] = {
                'total_requests': 0,
                'malicious_requests': 0,
                'attack_types': {},
                'avg_processing_time': 0,
                'max_risk_score': 0
            }
        
        hour_stats = stats[current_hour]
        
        # Update statistics
        hour_stats['total_requests'] += 1
        
        if analytics_data['malicious']:
            hour_stats['malicious_requests'] += 1
            hour_stats['max_risk_score'] = max(
                hour_stats['max_risk_score'], 
                analytics_data['risk_score']
            )
            
            # Count attack types
            for attack_type in analytics_data['attack_types']:
                hour_stats['attack_types'][attack_type] = \
                    hour_stats['attack_types'].get(attack_type, 0) + 1
        
        # Update average processing time
        total_requests = hour_stats['total_requests']
        current_avg = hour_stats['avg_processing_time']
        new_avg = ((current_avg * (total_requests - 1)) + analytics_data['processing_time']) / total_requests
        hour_stats['avg_processing_time'] = new_avg
        
        # Store updated stats
        cache.set(stats_key, stats, timeout=86400)
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')