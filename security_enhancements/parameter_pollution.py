"""
Advanced HTTP Parameter Pollution (HPP) Protection System for HealthProgress
Multi-Layer Parameter Validation and Pollution Prevention
Expert Blue Team Implementation - ETH Standards
"""
import json
import re
from typing import Dict, Any, List, Optional, Tuple, Union
from urllib.parse import parse_qs, unquote
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from .security_core import SecurityLogger


class ParameterPollutionDetector:
    """
    Advanced HTTP Parameter Pollution detection and prevention
    """
    
    def __init__(self):
        self.pollution_patterns = self._compile_pollution_patterns()
        self.max_parameters = 50  # Maximum allowed parameters per request
        self.max_parameter_length = 1000  # Maximum length per parameter value
        self.max_duplicate_params = 3  # Maximum allowed duplicate parameter names
        
    def _compile_pollution_patterns(self) -> List[re.Pattern]:
        """
        Compile parameter pollution attack patterns
        """
        return [
            # Parameter name pollution
            re.compile(r'(&|\?)\w+(&|\?)\w+=', re.IGNORECASE),  # Duplicate param names
            re.compile(r'(&|\?)(\w+)=.*&\2=', re.IGNORECASE),   # Same param multiple times
            
            # Encoding-based pollution
            re.compile(r'%26\w+=', re.IGNORECASE),  # URL-encoded ampersand
            re.compile(r'%3D\w+', re.IGNORECASE),   # URL-encoded equals
            re.compile(r'%3B\w+=', re.IGNORECASE),  # URL-encoded semicolon
            
            # Array pollution attempts
            re.compile(r'\[\d*\].*\[\d*\]', re.IGNORECASE),  # Multiple array indices
            re.compile(r'\w+\[\].*\w+\[\]', re.IGNORECASE),   # Multiple empty arrays
            
            # Nested parameter pollution
            re.compile(r'\[.*\[.*\].*\]', re.IGNORECASE),  # Nested brackets
            re.compile(r'\..*\..*\.', re.IGNORECASE),       # Multiple dots (object notation)
            
            # Protocol pollution
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'data:', re.IGNORECASE),
            re.compile(r'vbscript:', re.IGNORECASE),
        ]
    
    def analyze_parameter_pollution(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Comprehensive parameter pollution analysis
        """
        analysis_result = {
            'is_polluted': False,
            'pollution_type': [],
            'risk_score': 0,
            'violations': [],
            'parameter_stats': {},
            'recommendations': []
        }
        
        # Analyze GET parameters
        get_analysis = self._analyze_parameter_dict(dict(request.GET), 'GET')
        self._merge_analysis(analysis_result, get_analysis)
        
        # Analyze POST parameters
        post_analysis = self._analyze_parameter_dict(dict(request.POST), 'POST')
        self._merge_analysis(analysis_result, post_analysis)
        
        # Analyze raw query string for advanced pollution
        query_analysis = self._analyze_raw_query_string(request.META.get('QUERY_STRING', ''))
        self._merge_analysis(analysis_result, query_analysis)
        
        # Analyze JSON body parameters
        if request.content_type == 'application/json':
            json_analysis = self._analyze_json_parameters(request)
            self._merge_analysis(analysis_result, json_analysis)
        
        # Generate recommendations
        analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
        
        return analysis_result
    
    def _analyze_parameter_dict(self, params: Dict[str, Any], param_type: str) -> Dict[str, Any]:
        """
        Analyze parameter dictionary for pollution
        """
        analysis = {
            'is_polluted': False,
            'pollution_type': [],
            'risk_score': 0,
            'violations': [],
            'parameter_stats': {
                'count': len(params),
                'type': param_type,
                'avg_length': 0,
                'max_length': 0,
                'duplicate_names': []
            }
        }
        
        if not params:
            return analysis
        
        # Check parameter count
        if len(params) > self.max_parameters:
            analysis['is_polluted'] = True
            analysis['pollution_type'].append('excessive_parameters')
            analysis['risk_score'] += 30
            analysis['violations'].append(f'Too many {param_type} parameters: {len(params)}')
        
        # Analyze individual parameters
        total_length = 0
        for key, value in params.items():
            param_length = len(str(value))
            total_length += param_length
            
            # Check parameter length
            if param_length > self.max_parameter_length:
                analysis['is_polluted'] = True
                analysis['pollution_type'].append('oversized_parameter')
                analysis['risk_score'] += 25
                analysis['violations'].append(f'Oversized {param_type} parameter: {key}')
            
            # Check for suspicious parameter names
            if self._is_suspicious_parameter_name(key):
                analysis['is_polluted'] = True
                analysis['pollution_type'].append('suspicious_parameter_name')
                analysis['risk_score'] += 20
                analysis['violations'].append(f'Suspicious {param_type} parameter name: {key}')
            
            # Check for pollution patterns in values
            pollution_check = self._check_pollution_patterns(str(value))
            if pollution_check['is_polluted']:
                analysis['is_polluted'] = True
                analysis['pollution_type'].extend(pollution_check['types'])
                analysis['risk_score'] += pollution_check['risk_score']
                analysis['violations'].extend(pollution_check['violations'])
        
        # Calculate statistics
        analysis['parameter_stats']['avg_length'] = total_length // len(params) if params else 0
        analysis['parameter_stats']['max_length'] = max((len(str(v)) for v in params.values()), default=0)
        
        return analysis
    
    def _analyze_raw_query_string(self, query_string: str) -> Dict[str, Any]:
        """
        Analyze raw query string for advanced pollution techniques
        """
        analysis = {
            'is_polluted': False,
            'pollution_type': [],
            'risk_score': 0,
            'violations': []
        }
        
        if not query_string:
            return analysis
        
        # Parse query string manually to detect pollution
        try:
            # Check for duplicate parameter names
            params = parse_qs(query_string, keep_blank_values=True)
            duplicate_params = {k: v for k, v in params.items() if len(v) > 1}
            
            if duplicate_params:
                analysis['is_polluted'] = True
                analysis['pollution_type'].append('duplicate_parameters')
                analysis['risk_score'] += len(duplicate_params) * 15
                
                for param_name, param_values in duplicate_params.items():
                    if len(param_values) > self.max_duplicate_params:
                        analysis['violations'].append(f'Excessive duplicates for parameter: {param_name}')
                        analysis['risk_score'] += 20
        
        except Exception:
            # If parsing fails, it might indicate malformed pollution attempt
            analysis['is_polluted'] = True
            analysis['pollution_type'].append('malformed_query')
            analysis['risk_score'] += 25
            analysis['violations'].append('Malformed query string detected')
        
        # Check for encoded pollution attempts
        for pattern in self.pollution_patterns:
            if pattern.search(query_string):
                analysis['is_polluted'] = True
                analysis['pollution_type'].append('encoded_pollution')
                analysis['risk_score'] += 20
                analysis['violations'].append('Encoded parameter pollution detected')
                break
        
        return analysis
    
    def _analyze_json_parameters(self, request: HttpRequest) -> Dict[str, Any]:
        """
        Analyze JSON body for parameter pollution
        """
        analysis = {
            'is_polluted': False,
            'pollution_type': [],
            'risk_score': 0,
            'violations': []
        }
        
        try:
            json_data = json.loads(request.body.decode('utf-8'))
            
            # Check for deeply nested objects (potential pollution)
            nesting_depth = self._calculate_nesting_depth(json_data)
            if nesting_depth > 10:
                analysis['is_polluted'] = True
                analysis['pollution_type'].append('deep_nesting')
                analysis['risk_score'] += 25
                analysis['violations'].append(f'Excessive JSON nesting depth: {nesting_depth}')
            
            # Check for excessive array sizes
            if isinstance(json_data, list) and len(json_data) > 1000:
                analysis['is_polluted'] = True
                analysis['pollution_type'].append('excessive_array')
                analysis['risk_score'] += 30
                analysis['violations'].append(f'Excessive JSON array size: {len(json_data)}')
            
            # Check for duplicate keys in nested objects
            duplicate_keys = self._find_duplicate_keys(json_data)
            if duplicate_keys:
                analysis['is_polluted'] = True
                analysis['pollution_type'].append('duplicate_json_keys')
                analysis['risk_score'] += len(duplicate_keys) * 10
                analysis['violations'].append(f'Duplicate JSON keys found: {duplicate_keys}')
        
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Not JSON or malformed JSON
        
        return analysis
    
    def _is_suspicious_parameter_name(self, param_name: str) -> bool:
        """
        Check if parameter name is suspicious
        """
        suspicious_names = [
            '__proto__', 'prototype', 'constructor', '__constructor__',
            'eval', 'exec', 'system', 'shell', 'cmd', 'command',
            'script', 'javascript', 'vbscript', 'onload', 'onerror',
            'admin', 'root', 'administrator', 'superuser',
            'password', 'passwd', 'pwd', 'secret', 'key', 'token'
        ]
        
        return param_name.lower() in suspicious_names
    
    def _check_pollution_patterns(self, value: str) -> Dict[str, Any]:
        """
        Check value for pollution patterns
        """
        result = {
            'is_polluted': False,
            'types': [],
            'risk_score': 0,
            'violations': []
        }
        
        for pattern in self.pollution_patterns:
            if pattern.search(value):
                result['is_polluted'] = True
                result['types'].append('pattern_match')
                result['risk_score'] += 15
                result['violations'].append(f'Pollution pattern detected in value')
                break
        
        return result
    
    def _calculate_nesting_depth(self, obj: Any, current_depth: int = 0) -> int:
        """
        Calculate maximum nesting depth of JSON object
        """
        if not isinstance(obj, (dict, list)):
            return current_depth
        
        max_depth = current_depth
        
        if isinstance(obj, dict):
            for value in obj.values():
                depth = self._calculate_nesting_depth(value, current_depth + 1)
                max_depth = max(max_depth, depth)
        elif isinstance(obj, list):
            for item in obj:
                depth = self._calculate_nesting_depth(item, current_depth + 1)
                max_depth = max(max_depth, depth)
        
        return max_depth
    
    def _find_duplicate_keys(self, obj: Any, keys_seen: set = None) -> List[str]:
        """
        Find duplicate keys in nested JSON structure
        """
        if keys_seen is None:
            keys_seen = set()
        
        duplicates = []
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in keys_seen:
                    duplicates.append(key)
                else:
                    keys_seen.add(key)
                
                # Recursively check nested objects
                nested_duplicates = self._find_duplicate_keys(value, keys_seen.copy())
                duplicates.extend(nested_duplicates)
        elif isinstance(obj, list):
            for item in obj:
                nested_duplicates = self._find_duplicate_keys(item, keys_seen.copy())
                duplicates.extend(nested_duplicates)
        
        return duplicates
    
    def _merge_analysis(self, main_analysis: Dict[str, Any], sub_analysis: Dict[str, Any]) -> None:
        """
        Merge sub-analysis results into main analysis
        """
        if sub_analysis['is_polluted']:
            main_analysis['is_polluted'] = True
        
        main_analysis['pollution_type'].extend(sub_analysis['pollution_type'])
        main_analysis['risk_score'] += sub_analysis['risk_score']
        main_analysis['violations'].extend(sub_analysis['violations'])
        
        # Merge parameter stats
        if 'parameter_stats' in sub_analysis:
            param_type = sub_analysis['parameter_stats']['type']
            main_analysis['parameter_stats'][param_type] = sub_analysis['parameter_stats']
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on analysis
        """
        recommendations = []
        
        if 'excessive_parameters' in analysis['pollution_type']:
            recommendations.append('Limit the number of parameters in requests')
        
        if 'oversized_parameter' in analysis['pollution_type']:
            recommendations.append('Implement parameter size limits')
        
        if 'duplicate_parameters' in analysis['pollution_type']:
            recommendations.append('Validate and deduplicate parameters')
        
        if 'suspicious_parameter_name' in analysis['pollution_type']:
            recommendations.append('Implement parameter name whitelist')
        
        if 'deep_nesting' in analysis['pollution_type']:
            recommendations.append('Limit JSON nesting depth')
        
        if 'encoded_pollution' in analysis['pollution_type']:
            recommendations.append('Normalize and validate encoded parameters')
        
        return recommendations
    
    def sanitize_parameters(self, request: HttpRequest, analysis: Dict[str, Any]) -> None:
        """
        Sanitize polluted parameters
        """
        # Remove duplicate parameters (keep first occurrence)
        if 'duplicate_parameters' in analysis['pollution_type']:
            self._deduplicate_parameters(request)
        
        # Truncate oversized parameters
        if 'oversized_parameter' in analysis['pollution_type']:
            self._truncate_oversized_parameters(request)
        
        # Remove suspicious parameter names
        if 'suspicious_parameter_name' in analysis['pollution_type']:
            self._remove_suspicious_parameters(request)
    
    def _deduplicate_parameters(self, request: HttpRequest) -> None:
        """
        Remove duplicate parameters, keeping first occurrence
        """
        # Deduplicate GET parameters
        if hasattr(request, 'GET') and request.GET:
            cleaned_get = {}
            for key in request.GET:
                if key not in cleaned_get:
                    cleaned_get[key] = request.GET[key]
            
            request.GET = request.GET.copy()
            request.GET.clear()
            request.GET.update(cleaned_get)
        
        # Deduplicate POST parameters
        if hasattr(request, 'POST') and request.POST:
            cleaned_post = {}
            for key in request.POST:
                if key not in cleaned_post:
                    cleaned_post[key] = request.POST[key]
            
            request.POST = request.POST.copy()
            request.POST.clear()
            request.POST.update(cleaned_post)
    
    def _truncate_oversized_parameters(self, request: HttpRequest) -> None:
        """
        Truncate parameters that exceed maximum length
        """
        # Truncate GET parameters
        if hasattr(request, 'GET') and request.GET:
            request.GET = request.GET.copy()
            for key in list(request.GET.keys()):
                value = request.GET[key]
                if len(value) > self.max_parameter_length:
                    request.GET[key] = value[:self.max_parameter_length]
        
        # Truncate POST parameters
        if hasattr(request, 'POST') and request.POST:
            request.POST = request.POST.copy()
            for key in list(request.POST.keys()):
                value = request.POST[key]
                if len(value) > self.max_parameter_length:
                    request.POST[key] = value[:self.max_parameter_length]
    
    def _remove_suspicious_parameters(self, request: HttpRequest) -> None:
        """
        Remove parameters with suspicious names
        """
        # Remove suspicious GET parameters
        if hasattr(request, 'GET') and request.GET:
            request.GET = request.GET.copy()
            for key in list(request.GET.keys()):
                if self._is_suspicious_parameter_name(key):
                    del request.GET[key]
        
        # Remove suspicious POST parameters
        if hasattr(request, 'POST') and request.POST:
            request.POST = request.POST.copy()
            for key in list(request.POST.keys()):
                if self._is_suspicious_parameter_name(key):
                    del request.POST[key]


class ParameterPollutionMiddleware(MiddlewareMixin):
    """
    Middleware for HTTP Parameter Pollution protection
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.detector = ParameterPollutionDetector()
        self.risk_threshold = 50  # Risk threshold for blocking
        self.auto_sanitize = True  # Auto-sanitize detected pollution
        
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process request for parameter pollution
        """
        # Skip static resources
        if request.path.startswith(('/static/', '/media/')):
            return None
        
        # Analyze for parameter pollution
        analysis = self.detector.analyze_parameter_pollution(request)
        
        # Store analysis in request for other middleware/views
        request.parameter_pollution_analysis = analysis
        
        # Check if we should block the request
        if analysis['is_polluted'] and analysis['risk_score'] > self.risk_threshold:
            # Log the pollution attempt
            SecurityLogger.log_security_event(
                'parameter_pollution_blocked',
                'high',
                {
                    'ip_address': self._get_client_ip(request),
                    'path': request.path,
                    'method': request.method,
                    'risk_score': analysis['risk_score'],
                    'pollution_types': analysis['pollution_type'],
                    'violations': analysis['violations']
                }
            )
            
            return JsonResponse({
                'error': 'Parameter pollution detected',
                'code': 'PARAMETER_POLLUTION',
                'violations': analysis['violations'][:3]  # Limit violations in response
            }, status=400)
        
        # Auto-sanitize if enabled and pollution detected
        elif analysis['is_polluted'] and self.auto_sanitize:
            self.detector.sanitize_parameters(request, analysis)
            
            SecurityLogger.log_security_event(
                'parameter_pollution_sanitized',
                'medium',
                {
                    'path': request.path,
                    'risk_score': analysis['risk_score'],
                    'pollution_types': analysis['pollution_type'],
                    'sanitization_applied': True
                }
            )
        
        return None
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')