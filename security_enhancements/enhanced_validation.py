"""
Enhanced Input Validation Engine for HealthProgress
Addresses: External Variable Modification, Hidden Parameters, HTTP Parameter Pollution, Mass Assignment
Expert Blue Team Implementation - ETH Standards
"""
import re
import json
import ast
import urllib.parse
from typing import Dict, Any, List, Set, Optional, Union
from django.http import QueryDict
from django.core.exceptions import ValidationError
from django.conf import settings
from .security_core import SecurityLogger, ThreatDetector


class EnhancedInputValidator:
    """
    Advanced input validation engine with multi-vector protection
    Implements defense against parameter pollution, hidden parameters, and mass assignment
    """
    
    # Dangerous parameter patterns that indicate potential attacks
    DANGEROUS_PARAMS = {
        # Django ORM dangerous fields
        '__class__', '__module__', '__dict__', '__weakref__', '__doc__',
        '__init__', '__new__', '__str__', '__repr__', '__getattribute__',
        
        # Database dangerous operations
        'raw_query', 'extra', 'select_related', 'prefetch_related',
        'aggregate', 'annotate', 'values', 'values_list',
        
        # System dangerous parameters
        'exec', 'eval', 'compile', 'globals', 'locals', 'vars',
        '__import__', 'open', 'file', 'input', 'raw_input',
        
        # Framework dangerous fields
        'request', 'response', 'session', 'user', 'META',
        'FILES', 'POST', 'GET', 'COOKIES', 'method',
        
        # Hidden administrative parameters
        'is_admin', 'is_staff', 'is_superuser', 'is_active',
        'permissions', 'groups', 'user_permissions',
        
        # Mass assignment dangerous fields
        'password', 'password_hash', 'salt', 'token', 'secret',
        'api_key', 'private_key', 'credit_card', 'ssn', 'social_security',
        
        # SQL injection attempts
        'union', 'select', 'drop', 'delete', 'update', 'insert',
        'alter', 'create', 'truncate', 'execute', 'sp_',
        
        # XSS/Script injection
        'script', 'iframe', 'object', 'embed', 'form', 'input',
        'onclick', 'onload', 'onerror', 'onmouseover', 'javascript:',
        
        # Path traversal
        '../', '..\\', '/etc/', '/var/', '/tmp/', '/proc/',
        'c:\\', 'd:\\', '\\windows\\', '\\system32\\',
        
        # Command injection
        '|', '&', ';', '`', '$', '$(', '${', '<%', '%>',
        'system', 'shell', 'cmd', 'powershell', 'bash',
    }
    
    # Suspicious parameter name patterns
    SUSPICIOUS_PATTERNS = [
        r'.*password.*',
        r'.*token.*', 
        r'.*secret.*',
        r'.*key.*',
        r'.*admin.*',
        r'.*root.*',
        r'.*sql.*',
        r'.*query.*',
        r'.*exec.*',
        r'.*eval.*',
        r'.*system.*',
        r'.*cmd.*',
        r'.*shell.*',
        r'__.*__',  # Python magic methods
        r'.*\..*\..*',  # Nested object access
        r'.*\[.*\].*',  # Array/dict access
    ]
    
    def __init__(self):
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SUSPICIOUS_PATTERNS]
    
    def validate_request_parameters(self, request) -> Dict[str, Any]:
        """
        Comprehensive parameter validation against multiple attack vectors
        """
        validation_result = {
            'valid': True,
            'violations': [],
            'cleaned_data': {},
            'risk_score': 0,
            'attack_indicators': []
        }
        
        try:
            # Combine all request data
            all_params = {}
            
            # GET parameters
            if hasattr(request, 'GET') and request.GET:
                all_params.update(dict(request.GET.lists()))
            
            # POST parameters  
            if hasattr(request, 'POST') and request.POST:
                all_params.update(dict(request.POST.lists()))
                
            # JSON body parameters
            if hasattr(request, 'body') and request.body:
                try:
                    json_data = json.loads(request.body.decode('utf-8'))
                    if isinstance(json_data, dict):
                        all_params.update({k: [v] if not isinstance(v, list) else v 
                                         for k, v in json_data.items()})
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            
            # Validate each parameter
            for param_name, param_values in all_params.items():
                param_validation = self._validate_parameter(param_name, param_values, request)
                
                if not param_validation['valid']:
                    validation_result['valid'] = False
                    validation_result['violations'].extend(param_validation['violations'])
                    validation_result['risk_score'] += param_validation['risk_score']
                    validation_result['attack_indicators'].extend(param_validation['attack_indicators'])
                else:
                    validation_result['cleaned_data'][param_name] = param_validation['cleaned_value']
            
            # Check for HTTP Parameter Pollution
            pollution_check = self._check_parameter_pollution(all_params)
            if pollution_check['detected']:
                validation_result['valid'] = False
                validation_result['violations'].append('HTTP Parameter Pollution detected')
                validation_result['risk_score'] += 25
                validation_result['attack_indicators'].append('parameter_pollution')
            
            # Log security events
            if validation_result['risk_score'] > 10:
                SecurityLogger.log_security_event(
                    'suspicious_parameters',
                    'medium' if validation_result['risk_score'] < 50 else 'high',
                    {
                        'risk_score': validation_result['risk_score'],
                        'violations': validation_result['violations'],
                        'attack_indicators': validation_result['attack_indicators']
                    },
                    request=request
                )
                
        except Exception as e:
            SecurityLogger.log_security_event(
                'parameter_validation_error',
                'medium',
                {'error': str(e)},
                request=request
            )
            validation_result['valid'] = False
            validation_result['violations'].append(f'Validation error: {str(e)}')
        
        return validation_result
    
    def _validate_parameter(self, param_name: str, param_values: List, request) -> Dict[str, Any]:
        """
        Validate individual parameter against security threats
        """
        result = {
            'valid': True,
            'violations': [],
            'cleaned_value': param_values,
            'risk_score': 0,
            'attack_indicators': []
        }
        
        # Check for dangerous parameter names
        if self._is_dangerous_parameter(param_name):
            result['valid'] = False
            result['violations'].append(f'Dangerous parameter name: {param_name}')
            result['risk_score'] += 30
            result['attack_indicators'].append('dangerous_parameter')
        
        # Check for hidden parameters (parameters with suspicious patterns)
        if self._is_hidden_parameter(param_name):
            result['valid'] = False
            result['violations'].append(f'Hidden/suspicious parameter: {param_name}')
            result['risk_score'] += 20
            result['attack_indicators'].append('hidden_parameter')
        
        # Validate parameter values
        for value in param_values:
            if isinstance(value, str):
                value_validation = self._validate_parameter_value(param_name, value)
                if not value_validation['valid']:
                    result['valid'] = False
                    result['violations'].extend(value_validation['violations'])
                    result['risk_score'] += value_validation['risk_score']
                    result['attack_indicators'].extend(value_validation['attack_indicators'])
        
        # Check for mass assignment attempts
        if self._is_mass_assignment_attempt(param_name, request):
            result['valid'] = False
            result['violations'].append(f'Mass assignment attempt: {param_name}')
            result['risk_score'] += 40
            result['attack_indicators'].append('mass_assignment')
        
        return result
    
    def _is_dangerous_parameter(self, param_name: str) -> bool:
        """Check if parameter name is in dangerous parameters list"""
        return param_name.lower() in [p.lower() for p in self.DANGEROUS_PARAMS]
    
    def _is_hidden_parameter(self, param_name: str) -> bool:
        """Check if parameter name matches suspicious patterns"""
        return any(pattern.match(param_name) for pattern in self.compiled_patterns)
    
    def _validate_parameter_value(self, param_name: str, value: str) -> Dict[str, Any]:
        """
        Validate parameter value against injection attacks
        """
        result = {
            'valid': True,
            'violations': [],
            'risk_score': 0,
            'attack_indicators': []
        }
        
        # SQL Injection detection
        sql_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(or|and)\s+\d+\s*=\s*\d+)",
            r"(\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
            r"(;.*--)",
            r"(\|\||\|\s+)",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                result['valid'] = False
                result['violations'].append(f'SQL injection pattern in {param_name}: {pattern}')
                result['risk_score'] += 25
                result['attack_indicators'].append('sql_injection')
        
        # XSS detection
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"<object",
            r"<embed",
            r"vbscript:",
            r"expression\s*\(",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                result['valid'] = False
                result['violations'].append(f'XSS pattern in {param_name}: {pattern}')
                result['risk_score'] += 20
                result['attack_indicators'].append('xss_attempt')
        
        # Path traversal detection
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"/etc/",
            r"/var/",
            r"/tmp/",
            r"c:\\",
            r"\\windows\\",
        ]
        
        for pattern in traversal_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                result['valid'] = False
                result['violations'].append(f'Path traversal in {param_name}: {pattern}')
                result['risk_score'] += 15
                result['attack_indicators'].append('path_traversal')
        
        # Command injection detection
        command_patterns = [
            r"[|&;`$]",
            r"\$\(",
            r"\$\{",
            r"<%",
            r"%>",
            r"\b(system|exec|eval|shell|cmd|powershell|bash)\b",
        ]
        
        for pattern in command_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                result['valid'] = False
                result['violations'].append(f'Command injection in {param_name}: {pattern}')
                result['risk_score'] += 30
                result['attack_indicators'].append('command_injection')
        
        return result
    
    def _is_mass_assignment_attempt(self, param_name: str, request) -> bool:
        """
        Detect mass assignment attempts by checking for model field manipulation
        """
        # Check if parameter tries to modify sensitive model fields
        sensitive_fields = [
            'id', 'pk', 'created_at', 'updated_at', 'date_joined',
            'last_login', 'is_staff', 'is_superuser', 'is_active',
            'user_permissions', 'groups', 'password'
        ]
        
        if param_name in sensitive_fields:
            return True
        
        # Check for nested object manipulation
        if '.' in param_name or '[' in param_name:
            return True
        
        # Check for Django model field patterns
        model_patterns = [
            r'.*__.*',  # Django field lookups
            r'.*_set',  # Reverse foreign key relationships
            r'.*_ptr',  # Model inheritance pointers
        ]
        
        return any(re.match(pattern, param_name) for pattern in model_patterns)
    
    def _check_parameter_pollution(self, params: Dict[str, List]) -> Dict[str, Any]:
        """
        Detect HTTP Parameter Pollution attacks
        """
        result = {
            'detected': False,
            'polluted_parameters': [],
            'risk_level': 'low'
        }
        
        for param_name, param_values in params.items():
            if len(param_values) > 1:
                # Multiple values for same parameter - potential pollution
                result['detected'] = True
                result['polluted_parameters'].append({
                    'parameter': param_name,
                    'count': len(param_values),
                    'values': param_values[:5]  # Limit logged values
                })
                
                # Assess risk based on parameter name and value count
                if param_name in ['id', 'user_id', 'admin', 'role']:
                    result['risk_level'] = 'high'
                elif len(param_values) > 5:
                    result['risk_level'] = 'medium'
        
        return result
    
    def get_allowed_fields(self, model_class, user_role: str = 'user') -> Set[str]:
        """
        Get allowed fields for mass assignment based on user role
        """
        # Default allowed fields for regular users
        base_allowed = {
            'first_name', 'last_name', 'email', 'phone', 'address',
            'city', 'state', 'country', 'postal_code', 'date_of_birth',
            'gender', 'emergency_contact', 'medical_notes'
        }
        
        # Admin users get additional fields
        admin_allowed = base_allowed | {
            'is_active', 'notes', 'account_type', 'subscription_plan'
        }
        
        # Super admin gets most fields except sensitive ones
        superadmin_forbidden = {
            'password', 'password_hash', 'salt', 'token', 'secret_key',
            'api_key', 'private_key', 'session_key'
        }
        
        if user_role == 'superuser':
            model_fields = {f.name for f in model_class._meta.fields}
            return model_fields - superadmin_forbidden
        elif user_role == 'admin':
            return admin_allowed
        else:
            return base_allowed


class ExternalVariableProtection:
    """
    Protection against External Variable Modification attacks
    Validates and sanitizes external input sources
    """
    
    @staticmethod
    def validate_environment_variables(request) -> bool:
        """
        Prevent manipulation of environment variables through request
        """
        dangerous_env_params = [
            'PATH', 'PYTHONPATH', 'LD_LIBRARY_PATH', 'HOME', 'USER',
            'DJANGO_SETTINGS_MODULE', 'SECRET_KEY', 'DATABASE_URL',
            'DEBUG', 'ALLOWED_HOSTS'
        ]
        
        # Check request parameters for environment variable names
        all_params = []
        if hasattr(request, 'GET'):
            all_params.extend(request.GET.keys())
        if hasattr(request, 'POST'):
            all_params.extend(request.POST.keys())
        
        for param in all_params:
            if param.upper() in dangerous_env_params:
                SecurityLogger.log_security_event(
                    'environment_variable_manipulation',
                    'high',
                    {'parameter': param, 'value': request.GET.get(param) or request.POST.get(param)},
                    request=request
                )
                return False
        
        return True
    
    @staticmethod
    def validate_file_includes(request) -> bool:
        """
        Protect against file inclusion attacks through external variables
        """
        file_params = ['file', 'include', 'page', 'template', 'view', 'load', 'import']
        
        for param in file_params:
            value = request.GET.get(param) or request.POST.get(param)
            if value:
                # Check for dangerous file patterns
                dangerous_patterns = [
                    r'\.\./.*',  # Path traversal
                    r'/etc/.*',  # System files
                    r'/var/.*',  # Variable files
                    r'/proc/.*', # Process files
                    r'.*\.py$',  # Python files
                    r'.*\.exe$', # Executables
                    r'.*\.sh$',  # Shell scripts
                    r'.*\.bat$', # Batch files
                    r'file://.*', # File protocol
                    r'ftp://.*',  # FTP protocol
                ]
                
                for pattern in dangerous_patterns:
                    if re.match(pattern, value, re.IGNORECASE):
                        SecurityLogger.log_security_event(
                            'file_inclusion_attempt',
                            'high',
                            {'parameter': param, 'value': value, 'pattern': pattern},
                            request=request
                        )
                        return False
        
        return True


class TypeJugglingProtection:
    """
    Protection against Type Juggling attacks
    Ensures strict type validation and prevents type confusion
    """
    
    EXPECTED_TYPES = {
        'int': int,
        'float': float,
        'str': str,
        'bool': bool,
        'list': list,
        'dict': dict
    }
    
    @staticmethod
    def validate_type_safety(data: Dict[str, Any], expected_schema: Dict[str, str]) -> Dict[str, Any]:
        """
        Validate that data matches expected types exactly
        """
        result = {
            'valid': True,
            'type_errors': [],
            'sanitized_data': {}
        }
        
        for field_name, expected_type in expected_schema.items():
            if field_name in data:
                value = data[field_name]
                
                # Get expected Python type
                python_type = TypeJugglingProtection.EXPECTED_TYPES.get(expected_type, str)
                
                # Strict type checking - no automatic conversion
                if not isinstance(value, python_type):
                    result['valid'] = False
                    result['type_errors'].append({
                        'field': field_name,
                        'expected': expected_type,
                        'received': type(value).__name__,
                        'value': str(value)[:100]  # Truncate long values
                    })
                else:
                    result['sanitized_data'][field_name] = value
        
        return result
    
    @staticmethod
    def prevent_php_style_juggling(request) -> bool:
        """
        Prevent PHP-style type juggling attacks common in web applications
        """
        dangerous_comparisons = [
            '0e', '0x', '+0', '-0', ' 0', '0 ',
            'true', 'false', 'null', 'undefined',
            'NaN', 'Infinity', '-Infinity'
        ]
        
        # Check all request parameters
        all_params = {}
        if hasattr(request, 'GET'):
            all_params.update(request.GET.dict())
        if hasattr(request, 'POST'):
            all_params.update(request.POST.dict())
        
        for param_name, value in all_params.items():
            if isinstance(value, str):
                for dangerous_val in dangerous_comparisons:
                    if value.lower() == dangerous_val.lower():
                        SecurityLogger.log_security_event(
                            'type_juggling_attempt',
                            'medium',
                            {'parameter': param_name, 'value': value, 'dangerous_pattern': dangerous_val},
                            request=request
                        )
                        return False
        
        return True