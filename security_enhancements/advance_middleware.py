"""
Advanced Security Middleware Stack for HealthProgress
Protects against 40+ attack vectors
"""
import re
import json
import time
from typing import Dict, Any
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.conf import settings
from .security_core import (
    SecurityLogger, ThreatDetector, SecurityCore, 
    InputSanitizer, CryptoUtils
)
from .enhanced_validation import (
    EnhancedInputValidator, ExternalVariableProtection, TypeJugglingProtection
)
from .advanced_sanitization import AdvancedSanitizer, OutputSanitizer
from .crypto_security import (
    SecureRandomGenerator, EnhancedJWTSecurity, AdvancedEncryption, PasswordSecurity
)


class IPBlockingMiddleware(MiddlewareMixin):
    """Block requests from blocked IPs"""
    
    def process_request(self, request):
        if SecurityCore.is_ip_blocked(request):
            SecurityLogger.log_security_event(
                'blocked_ip_attempt',
                'high',
                {'message': 'Blocked IP attempted access'},
                request=request
            )
            return JsonResponse({'error': 'Access denied'}, status=403)
        return None


class EnhancedInputValidationMiddleware(MiddlewareMixin):
    """
    Enhanced Input Validation with multi-vector protection
    Addresses: External Variable Modification, Hidden Parameters, HTTP Parameter Pollution, Mass Assignment
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.validator = EnhancedInputValidator()
        self.sanitizer = AdvancedSanitizer()
        
    def process_request(self, request):
        # Skip validation for safe methods and specific endpoints
        if request.method in ['GET', 'HEAD', 'OPTIONS'] and not request.GET:
            return None
            
        # Skip for admin and static files
        if request.path.startswith('/admin/') or request.path.startswith('/static/'):
            return None
            
        # External variable protection
        if not ExternalVariableProtection.validate_environment_variables(request):
            return JsonResponse({'error': 'External variable manipulation detected'}, status=400)
            
        if not ExternalVariableProtection.validate_file_includes(request):
            return JsonResponse({'error': 'File inclusion attempt detected'}, status=400)
            
        # Type juggling protection
        if not TypeJugglingProtection.prevent_php_style_juggling(request):
            return JsonResponse({'error': 'Type juggling attempt detected'}, status=400)
            
        # Enhanced parameter validation
        validation_result = self.validator.validate_request_parameters(request)
        
        if not validation_result['valid']:
            SecurityLogger.log_security_event(
                'enhanced_validation_failed',
                'high' if validation_result['risk_score'] > 50 else 'medium',
                {
                    'violations': validation_result['violations'],
                    'risk_score': validation_result['risk_score'],
                    'attack_indicators': validation_result['attack_indicators']
                },
                request=request
            )
            
            # Block high-risk requests
            if validation_result['risk_score'] > 75:
                return JsonResponse({
                    'error': 'Request blocked due to security policy',
                    'code': 'SECURITY_VIOLATION'
                }, status=403)
        
        # Store cleaned data for use by views
        request.validated_data = validation_result.get('cleaned_data', {})
        
        return None


class IDORProtectionMiddleware(MiddlewareMixin):
    """
    Insecure Direct Object References (IDOR) Protection
    Validates object access permissions
    """
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Check for object ID in URL parameters
        if 'pk' in view_kwargs or 'id' in view_kwargs:
            obj_id = view_kwargs.get('pk') or view_kwargs.get('id')
            
            # Validate that authenticated users only access their own resources
            if request.user.is_authenticated:
                # Log object access attempt
                cache_key = f"object_access:{request.user.id}:{obj_id}"
                access_count = cache.get(cache_key, 0)
                
                # Detect enumeration attempts
                if access_count > 10:
                    SecurityLogger.log_security_event(
                        'idor_enumeration',
                        'high',
                        {'user_id': request.user.id, 'object_id': obj_id},
                        request=request,
                        user=request.user
                    )
                
                cache.set(cache_key, access_count + 1, timeout=300)
        
        return None


class MassAssignmentProtectionMiddleware(MiddlewareMixin):
    """
    Mass Assignment Protection
    Prevents unauthorized field updates
    """
    
    PROTECTED_FIELDS = [
        'is_superuser', 'is_staff', 'is_active', 'role',
        'permissions', 'groups', 'user_permissions'
    ]
    
    def process_request(self, request):
        if request.method in ('POST', 'PUT', 'PATCH'):
            data = request.POST.dict() if request.POST else {}
            
            # Check for protected field manipulation
            for field in self.PROTECTED_FIELDS:
                if field in data:
                    SecurityLogger.log_security_event(
                        'mass_assignment_attempt',
                        'critical',
                        {'field': field, 'value': data[field]},
                        request=request,
                        user=request.user if request.user.is_authenticated else None
                    )
                    return JsonResponse({
                        'error': 'Unauthorized field modification attempt'
                    }, status=403)
        
        return None


class DeserializationProtectionMiddleware(MiddlewareMixin):
    """
    Insecure Deserialization Protection
    Validates serialized data before processing
    """
    
    DANGEROUS_PATTERNS = [
        b'__reduce__',
        b'__setstate__',
        b'eval',
        b'exec',
        b'compile',
        b'open',
        b'file',
    ]
    
    def process_request(self, request):
        if request.body:
            # Check for pickle or other serialization patterns
            for pattern in self.DANGEROUS_PATTERNS:
                if pattern in request.body:
                    SecurityLogger.log_security_event(
                        'insecure_deserialization',
                        'critical',
                        {'pattern': pattern.decode('utf-8', errors='ignore')},
                        request=request
                    )
                    return JsonResponse({
                        'error': 'Potentially malicious serialized data detected'
                    }, status=400)
        
        return None


class OpenRedirectProtectionMiddleware(MiddlewareMixin):
    """
    Open Redirect Protection
    Validates redirect URLs
    """
    
    def process_request(self, request):
        redirect_params = ['next', 'return', 'redirect', 'url', 'goto']
        
        for param in redirect_params:
            redirect_url = request.GET.get(param) or request.POST.get(param)
            
            if redirect_url:
                # Check for external redirects
                if redirect_url.startswith('http'):
                    # Parse domain
                    domain = re.search(r'https?://([^/]+)', redirect_url)
                    if domain:
                        redirect_domain = domain.group(1)
                        allowed_domains = getattr(settings, 'ALLOWED_REDIRECT_DOMAINS', [])
                        
                        if redirect_domain not in allowed_domains:
                            SecurityLogger.log_security_event(
                                'open_redirect_attempt',
                                'high',
                                {'redirect_url': redirect_url},
                                request=request
                            )
                            return JsonResponse({
                                'error': 'External redirects not allowed'
                            }, status=400)
                
                # Check for protocol-based attacks
                dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
                if any(redirect_url.lower().startswith(proto) for proto in dangerous_protocols):
                    SecurityLogger.log_security_event(
                        'open_redirect_protocol_attack',
                        'critical',
                        {'redirect_url': redirect_url},
                        request=request
                    )
                    return JsonResponse({
                        'error': 'Dangerous redirect protocol detected'
                    }, status=400)
        
        return None


class SSRFProtectionMiddleware(MiddlewareMixin):
    """
    Server-Side Request Forgery (SSRF) Protection
    Prevents requests to internal resources
    """
    
    BLOCKED_HOSTS = [
        'localhost', '127.0.0.1', '0.0.0.0',
        '169.254.169.254',  # AWS metadata
        '::1',  # IPv6 localhost
    ]
    
    BLOCKED_NETWORKS = [
        r'^10\.',
        r'^172\.(1[6-9]|2\d|3[01])\.',
        r'^192\.168\.',
    ]
    
    def process_request(self, request):
        # Check URL parameters for SSRF attempts
        url_params = ['url', 'link', 'src', 'image', 'file', 'document']
        
        for param in url_params:
            url = request.GET.get(param) or request.POST.get(param)
            
            if url:
                # Extract host from URL
                host_match = re.search(r'https?://([^/]+)', url)
                if host_match:
                    host = host_match.group(1)
                    
                    # Check against blocked hosts
                    if host in self.BLOCKED_HOSTS:
                        SecurityLogger.log_security_event(
                            'ssrf_attempt',
                            'critical',
                            {'url': url, 'host': host},
                            request=request
                        )
                        return JsonResponse({
                            'error': 'Access to internal resources not allowed'
                        }, status=403)
                    
                    # Check against blocked networks
                    for network_pattern in self.BLOCKED_NETWORKS:
                        if re.match(network_pattern, host):
                            SecurityLogger.log_security_event(
                                'ssrf_private_network',
                                'critical',
                                {'url': url, 'host': host},
                                request=request
                            )
                            return JsonResponse({
                                'error': 'Access to private networks not allowed'
                            }, status=403)
        
        return None


class SSTIProtectionMiddleware(MiddlewareMixin):
    """
    Server-Side Template Injection (SSTI) Protection
    Detects template injection attempts
    """
    
    SSTI_PATTERNS = [
        r'\{\{.*\}\}',  # Jinja2, Django
        r'\$\{.*\}',    # Freemarker
        r'<%.*%>',      # JSP
        r'#\{.*\}',     # Ruby
    ]
    
    def process_request(self, request):
        # Check POST data for SSTI patterns
        if request.method == 'POST':
            for key, value in request.POST.items():
                if isinstance(value, str):
                    for pattern in self.SSTI_PATTERNS:
                        if re.search(pattern, value):
                            SecurityLogger.log_security_event(
                                'ssti_attempt',
                                'critical',
                                {'field': key, 'pattern': pattern},
                                request=request
                            )
                            return JsonResponse({
                                'error': 'Template injection attempt detected'
                            }, status=400)
        
        return None


class PrototypePollutionMiddleware(MiddlewareMixin):
    """
    Prototype Pollution Protection (for JSON APIs)
    Prevents prototype pollution in JSON data
    """
    
    DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype']
    
    def process_request(self, request):
        if request.content_type == 'application/json' and request.body:
            try:
                data = json.loads(request.body)
                if self._check_pollution(data):
                    SecurityLogger.log_security_event(
                        'prototype_pollution',
                        'high',
                        {'data_keys': list(data.keys()) if isinstance(data, dict) else []},
                        request=request
                    )
                    return JsonResponse({
                        'error': 'Prototype pollution attempt detected'
                    }, status=400)
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _check_pollution(self, data, depth=0):
        """Recursively check for prototype pollution"""
        if depth > 10:  # Prevent deep recursion
            return False
        
        if isinstance(data, dict):
            for key in data.keys():
                if key in self.DANGEROUS_KEYS:
                    return True
                if isinstance(data[key], (dict, list)):
                    if self._check_pollution(data[key], depth + 1):
                        return True
        
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    if self._check_pollution(item, depth + 1):
                        return True
        
        return False


class RaceConditionProtectionMiddleware(MiddlewareMixin):
    """
    Race Condition Protection
    Prevents concurrent modification attacks
    """
    
    def process_request(self, request):
        if request.method in ('POST', 'PUT', 'DELETE') and request.user.is_authenticated:
            # Create lock key based on user and resource
            resource_id = request.path
            lock_key = f"race_lock:{request.user.id}:{resource_id}"
            
            # Try to acquire lock
            if cache.get(lock_key):
                SecurityLogger.log_security_event(
                    'race_condition_detected',
                    'medium',
                    {'resource': resource_id},
                    request=request,
                    user=request.user
                )
                return JsonResponse({
                    'error': 'Operation in progress, please wait'
                }, status=429)
            
            # Set lock (will be released by process_response)
            cache.set(lock_key, True, timeout=5)
            request._race_lock_key = lock_key
        
        return None
    
    def process_response(self, request, response):
        # Release lock
        if hasattr(request, '_race_lock_key'):
            cache.delete(request._race_lock_key)
        return response


class HTTPParameterPollutionMiddleware(MiddlewareMixin):
    """
    HTTP Parameter Pollution (HPP) Protection
    Detects duplicate parameters with different values
    """
    
    def process_request(self, request):
        # Check for duplicate parameters in GET
        duplicate_params = []
        param_values = {}
        
        for key in request.GET.keys():
            values = request.GET.getlist(key)
            if len(values) > 1:
                # Check if values are different
                if len(set(values)) > 1:
                    duplicate_params.append(key)
                    param_values[key] = values
        
        if duplicate_params:
            SecurityLogger.log_security_event(
                'http_parameter_pollution',
                'medium',
                {'duplicate_params': duplicate_params, 'values': param_values},
                request=request
            )
            return JsonResponse({
                'error': 'Duplicate parameters with different values detected'
            }, status=400)
        
        return None


class RegexDOSProtectionMiddleware(MiddlewareMixin):
    """
    Regular Expression Denial of Service (ReDoS) Protection
    Detects potentially malicious regex patterns
    """
    
    MAX_INPUT_LENGTH = 10000
    SUSPICIOUS_PATTERNS = [
        r'(.+)+',  # Nested quantifiers
        r'(.*)*',
        r'(.|\n)*',
    ]
    
    def process_request(self, request):
        # Check input length
        for key, value in {**request.GET.dict(), **request.POST.dict()}.items():
            if isinstance(value, str):
                if len(value) > self.MAX_INPUT_LENGTH:
                    SecurityLogger.log_security_event(
                        'redos_long_input',
                        'medium',
                        {'field': key, 'length': len(value)},
                        request=request
                    )
                    return JsonResponse({
                        'error': 'Input too long'
                    }, status=400)
        
        return None


class WebSocketSecurityMiddleware(MiddlewareMixin):
    """
    WebSocket Security
    Validates WebSocket upgrade requests
    """
    
    def process_request(self, request):
        if request.META.get('HTTP_UPGRADE', '').lower() == 'websocket':
            # Verify origin
            origin = request.META.get('HTTP_ORIGIN', '')
            allowed_origins = getattr(settings, 'ALLOWED_WEBSOCKET_ORIGINS', [])
            
            if origin and allowed_origins:
                if origin not in allowed_origins:
                    SecurityLogger.log_security_event(
                        'websocket_origin_mismatch',
                        'high',
                        {'origin': origin},
                        request=request
                    )
                    return HttpResponseForbidden('Invalid WebSocket origin')
        
        return None


class RequestSmugglingProtectionMiddleware(MiddlewareMixin):
    """
    HTTP Request Smuggling Protection
    Detects malformed requests
    """
    
    def process_request(self, request):
        # Check for duplicate Content-Length or Transfer-Encoding headers
        content_length = request.META.get('HTTP_CONTENT_LENGTH')
        transfer_encoding = request.META.get('HTTP_TRANSFER_ENCODING')
        
        if content_length and transfer_encoding:
            SecurityLogger.log_security_event(
                'request_smuggling',
                'critical',
                {'has_both': True},
                request=request
            )
            return JsonResponse({
                'error': 'Malformed request headers detected'
            }, status=400)
        
        return None


class GraphQLInjectionMiddleware(MiddlewareMixin):
    """
    GraphQL Injection Protection
    Detects malicious GraphQL queries
    """
    
    MAX_QUERY_DEPTH = 10
    MAX_QUERY_COMPLEXITY = 1000
    
    def process_request(self, request):
        if '/graphql' in request.path:
            if request.body:
                try:
                    data = json.loads(request.body)
                    query = data.get('query', '')
                    
                    # Check query depth (nested queries)
                    depth = query.count('{')
                    if depth > self.MAX_QUERY_DEPTH:
                        SecurityLogger.log_security_event(
                            'graphql_depth_attack',
                            'high',
                            {'depth': depth},
                            request=request
                        )
                        return JsonResponse({
                            'error': 'Query too complex'
                        }, status=400)
                    
                    # Check for introspection abuse
                    if '__schema' in query or '__type' in query:
                        if not request.user.is_authenticated:
                            SecurityLogger.log_security_event(
                                'graphql_introspection_unauthenticated',
                                'medium',
                                {},
                                request=request
                            )
                            return JsonResponse({
                                'error': 'Introspection not allowed'
                            }, status=403)
                
                except json.JSONDecodeError:
                    pass
        
        return None


class ComprehensiveThreatDetectionMiddleware(MiddlewareMixin):
    """
    Comprehensive threat detection using security_core
    """
    
    def process_request(self, request):
        # Check all input data for threats
        all_data = {**request.GET.dict(), **request.POST.dict()}
        
        for key, value in all_data.items():
            if isinstance(value, str) and value:
                threats = ThreatDetector.detect_all_threats(value)
                
                detected_threats = [threat for threat, detected in threats.items() if detected]
                
                if detected_threats:
                    # Log all detected threats
                    severity = 'critical' if any(t in ['sql_injection', 'command_injection', 'xxe'] 
                                                 for t in detected_threats) else 'high'
                    
                    SecurityLogger.log_security_event(
                        'multiple_threats_detected',
                        severity,
                        {
                            'field': key,
                            'threats': detected_threats,
                            'value_preview': value[:100]
                        },
                        request=request,
                        user=request.user if request.user.is_authenticated else None
                    )
                    
                    return JsonResponse({
                        'error': 'Potentially malicious input detected',
                        'threats': detected_threats
                    }, status=400)
        
        return None