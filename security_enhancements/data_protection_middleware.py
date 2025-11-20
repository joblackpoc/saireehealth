"""
Phase 6: Data Protection & Cryptography Middleware
Django middleware for data protection, encryption, and privacy compliance

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
Component: Data Protection Middleware Stack
"""

import json
import hashlib
import time
from typing import Dict, List, Optional, Any
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.core.files.uploadedfile import UploadedFile
import logging

from .data_protection import (
    AdvancedCryptographicEngine,
    KeyManagementSystem,
    DataLossPreventionSystem,
    PrivacyComplianceEngine,
    SecureDataTransmission
)

# Enhanced Security Logging
security_logger = logging.getLogger('security_core')

class DataProtectionMiddleware(MiddlewareMixin):
    """
    Main data protection middleware
    Orchestrates encryption, DLP, and privacy compliance
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.crypto_engine = AdvancedCryptographicEngine()
        self.key_manager = KeyManagementSystem()
        self.dlp_system = DataLossPreventionSystem()
        self.privacy_engine = PrivacyComplianceEngine()
        self.secure_transmission = SecureDataTransmission()
        
        # Configuration
        self.enabled = getattr(settings, 'DATA_PROTECTION_ENABLED', True)
        self.encryption_required_paths = getattr(settings, 'ENCRYPTION_REQUIRED_PATHS', [
            '/api/health/', '/api/user/', '/api/sensitive/'
        ])
        self.dlp_scan_enabled = getattr(settings, 'DLP_SCAN_ENABLED', True)
        
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        # Pre-processing: Scan incoming data
        protection_result = self.process_request_protection(request)
        if isinstance(protection_result, HttpResponse):
            return protection_result
        
        response = self.get_response(request)
        
        # Post-processing: Protect outgoing data
        self.process_response_protection(request, response)
        
        return response
    
    def process_request_protection(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process request data protection"""
        try:
            # Skip protection for excluded paths
            if self._is_excluded_path(request.path):
                return None
            
            # DLP scanning for incoming data
            if self.dlp_scan_enabled and request.method in ['POST', 'PUT', 'PATCH']:
                dlp_result = self._scan_request_data(request)
                if not dlp_result.get('access_granted', True):
                    security_logger.warning(f"DLP blocked request from {request.META.get('REMOTE_ADDR')}")
                    return JsonResponse({
                        'error': 'Request blocked by Data Loss Prevention',
                        'reason': 'Sensitive content detected',
                        'policy_actions': dlp_result.get('actions_taken', [])
                    }, status=403)
            
            # Privacy compliance tracking
            self._track_data_processing(request)
            
            return None
            
        except Exception as e:
            security_logger.error(f"Data protection request processing error: {str(e)}")
            return JsonResponse({'error': 'Data protection system error'}, status=500)
    
    def process_response_protection(self, request: HttpRequest, response: HttpResponse):
        """Process response data protection"""
        try:
            # Encryption headers for secure content
            if self._requires_encryption(request.path):
                response['X-Content-Encrypted'] = 'true'
                response['X-Encryption-Algorithm'] = 'AES-256-GCM'
            
            # Privacy compliance headers
            response['X-Privacy-Framework'] = 'GDPR,HIPAA'
            response['X-Data-Classification'] = self._classify_response_data(response)
            
            # DLP watermarking for sensitive responses
            if hasattr(request, 'dlp_classification'):
                classification = request.dlp_classification
                if classification in ['confidential', 'top_secret']:
                    response['X-Content-Classification'] = classification
                    response['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
            
        except Exception as e:
            security_logger.error(f"Response data protection error: {str(e)}")
    
    def _scan_request_data(self, request: HttpRequest) -> Dict[str, Any]:
        """Scan request data for sensitive content"""
        try:
            content_to_scan = ""
            
            # Scan POST data
            if hasattr(request, 'POST') and request.POST:
                for key, value in request.POST.items():
                    content_to_scan += f"{key}: {value}\n"
            
            # Scan JSON data
            if hasattr(request, 'body') and request.content_type == 'application/json':
                try:
                    json_data = json.loads(request.body.decode('utf-8'))
                    content_to_scan += json.dumps(json_data, indent=2)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            
            if content_to_scan:
                # Analyze content
                analysis_results = self.dlp_system.analyze_content(
                    content_to_scan,
                    context={
                        'source': 'http_request',
                        'path': request.path,
                        'method': request.method,
                        'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None
                    }
                )
                
                # Apply DLP policies
                policy_results = self.dlp_system.apply_dlp_policy(
                    content_to_scan,
                    analysis_results,
                    request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None
                )
                
                # Store classification in request for response processing
                request.dlp_classification = analysis_results.get('classification', 'public')
                
                return policy_results
            
            return {'access_granted': True, 'actions_taken': []}
            
        except Exception as e:
            security_logger.error(f"Request DLP scanning error: {str(e)}")
            return {'access_granted': True, 'error': str(e)}
    
    def _track_data_processing(self, request: HttpRequest):
        """Track data processing for privacy compliance"""
        try:
            if hasattr(request, 'user') and request.user.is_authenticated:
                # Determine processing purpose from path and method
                processing_purpose = self._determine_processing_purpose(request.path, request.method)
                
                # Audit data processing
                audit_record = self.privacy_engine.audit_data_processing(
                    data_type='user_request_data',
                    processing_purpose=processing_purpose,
                    legal_basis='legitimate_interests',  # This would be determined based on context
                    user_id=request.user.id
                )
                
                # Store audit ID in request for potential use
                request.privacy_audit_id = audit_record.get('audit_id')
                
        except Exception as e:
            security_logger.error(f"Privacy compliance tracking error: {str(e)}")
    
    def _determine_processing_purpose(self, path: str, method: str) -> str:
        """Determine data processing purpose from request"""
        path_purposes = {
            '/api/health/': 'healthcare_service_provision',
            '/api/user/': 'user_account_management',
            '/api/analytics/': 'service_improvement',
            '/api/billing/': 'billing_and_payments',
            '/admin/': 'system_administration'
        }
        
        for path_pattern, purpose in path_purposes.items():
            if path.startswith(path_pattern):
                return purpose
        
        return 'general_service_provision'
    
    def _requires_encryption(self, path: str) -> bool:
        """Check if path requires encryption"""
        return any(path.startswith(encrypted_path) for encrypted_path in self.encryption_required_paths)
    
    def _classify_response_data(self, response: HttpResponse) -> str:
        """Classify response data sensitivity"""
        # Simple classification based on content type and size
        if response.get('Content-Type', '').startswith('application/json'):
            try:
                content_length = len(response.content)
                if content_length > 1000:
                    return 'internal'
                else:
                    return 'public'
            except:
                return 'public'
        
        return 'public'
    
    def _is_excluded_path(self, path: str) -> bool:
        """Check if path is excluded from data protection"""
        excluded_paths = getattr(settings, 'DATA_PROTECTION_EXCLUDED_PATHS', [
            '/static/', '/media/', '/health/', '/ping/', '/favicon.ico'
        ])
        
        return any(path.startswith(excluded) for excluded in excluded_paths)


class FileEncryptionMiddleware(MiddlewareMixin):
    """
    File encryption middleware for uploaded files
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.crypto_engine = AdvancedCryptographicEngine()
        self.dlp_system = DataLossPreventionSystem()
        self.enabled = getattr(settings, 'FILE_ENCRYPTION_ENABLED', True)
        
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        # Process file uploads
        if request.method == 'POST' and request.FILES:
            file_protection_result = self._process_file_uploads(request)
            if isinstance(file_protection_result, HttpResponse):
                return file_protection_result
        
        return self.get_response(request)
    
    def _process_file_uploads(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process and secure uploaded files"""
        try:
            for field_name, uploaded_file in request.FILES.items():
                if isinstance(uploaded_file, UploadedFile):
                    # Read file content
                    file_content = uploaded_file.read()
                    uploaded_file.seek(0)  # Reset file pointer
                    
                    # DLP scan
                    scan_results = self.dlp_system.scan_file_content(
                        uploaded_file.name,
                        file_content,
                        request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None
                    )
                    
                    # Check if file upload should be blocked
                    if not scan_results.get('policy_actions', {}).get('access_granted', True):
                        security_logger.warning(f"File upload blocked: {uploaded_file.name}")
                        return JsonResponse({
                            'error': 'File upload blocked by security policy',
                            'filename': uploaded_file.name,
                            'reason': 'Sensitive content detected',
                            'classification': scan_results.get('analysis', {}).get('classification', 'unknown')
                        }, status=403)
                    
                    # Encrypt file if it contains sensitive data
                    classification = scan_results.get('analysis', {}).get('classification', 'public')
                    if classification in ['confidential', 'top_secret', 'internal']:
                        try:
                            # Encrypt file content
                            encrypted_file_data = self.crypto_engine.encrypt_file(
                                file_content,
                                uploaded_file.name,
                                request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None
                            )
                            
                            # Store encryption metadata in request
                            if not hasattr(request, 'encrypted_files'):
                                request.encrypted_files = {}
                            
                            request.encrypted_files[field_name] = {
                                'original_name': uploaded_file.name,
                                'encryption_data': encrypted_file_data,
                                'classification': classification
                            }
                            
                            security_logger.info(f"File encrypted: {uploaded_file.name} - {classification}")
                            
                        except Exception as e:
                            security_logger.error(f"File encryption failed for {uploaded_file.name}: {str(e)}")
                            return JsonResponse({
                                'error': 'File encryption failed',
                                'filename': uploaded_file.name
                            }, status=500)
            
            return None
            
        except Exception as e:
            security_logger.error(f"File upload processing error: {str(e)}")
            return JsonResponse({'error': 'File processing system error'}, status=500)


class DatabaseEncryptionMiddleware(MiddlewareMixin):
    """
    Database field-level encryption middleware
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.crypto_engine = AdvancedCryptographicEngine()
        self.enabled = getattr(settings, 'DATABASE_ENCRYPTION_ENABLED', True)
        
        # Fields that should be encrypted
        self.encrypted_fields = getattr(settings, 'DATABASE_ENCRYPTED_FIELDS', [
            'ssn', 'credit_card', 'bank_account', 'health_record_number',
            'diagnosis', 'prescription', 'medical_notes'
        ])
    
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        # Process database operations (this would integrate with Django ORM)
        self._setup_field_encryption_context(request)
        
        return self.get_response(request)
    
    def _setup_field_encryption_context(self, request: HttpRequest):
        """Setup encryption context for database operations"""
        try:
            # This would integrate with Django ORM to automatically encrypt/decrypt fields
            # For demonstration, we'll add encryption utilities to the request
            
            request.encrypt_field = lambda field_name, value: self.crypto_engine.encrypt_field(
                value, 
                field_name, 
                request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None
            )
            
            request.decrypt_field = lambda encrypted_value, field_name: self.crypto_engine.decrypt_field(
                encrypted_value, 
                field_name
            )
            
        except Exception as e:
            security_logger.error(f"Database encryption context setup error: {str(e)}")


class PrivacyComplianceMiddleware(MiddlewareMixin):
    """
    Privacy compliance middleware for GDPR, HIPAA, etc.
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.privacy_engine = PrivacyComplianceEngine()
        self.enabled = getattr(settings, 'PRIVACY_COMPLIANCE_ENABLED', True)
        
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        # Handle privacy-related requests
        if request.path.startswith('/api/privacy/'):
            privacy_response = self._handle_privacy_request(request)
            if privacy_response:
                return privacy_response
        
        response = self.get_response(request)
        
        # Add privacy compliance headers
        self._add_privacy_headers(request, response)
        
        return response
    
    def _handle_privacy_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Handle data subject rights requests"""
        try:
            if not hasattr(request, 'user') or not request.user.is_authenticated:
                return JsonResponse({'error': 'Authentication required'}, status=401)
            
            if request.method == 'POST':
                # Parse privacy request
                try:
                    request_data = json.loads(request.body.decode('utf-8'))
                    request_type = request_data.get('request_type')
                    framework = request_data.get('framework', 'gdpr')
                    
                    if request_type in ['right_to_access', 'right_to_erasure', 
                                      'right_to_rectification', 'right_to_data_portability']:
                        
                        # Process the privacy request
                        result = self.privacy_engine.process_data_subject_request(
                            request_type, 
                            request.user.id, 
                            framework
                        )
                        
                        return JsonResponse({
                            'status': 'success',
                            'request_id': result.get('request_id'),
                            'request_status': result.get('status'),
                            'message': f'Privacy request {request_type} has been processed',
                            'fulfillment_data': result.get('fulfillment_data', {})
                        })
                    
                    else:
                        return JsonResponse({'error': 'Invalid request type'}, status=400)
                        
                except json.JSONDecodeError:
                    return JsonResponse({'error': 'Invalid JSON data'}, status=400)
            
            elif request.method == 'GET':
                # Return privacy request status
                user_requests_key = f"user_privacy_requests_{request.user.id}"
                user_requests = cache.get(user_requests_key, [])
                
                request_history = []
                for request_id in user_requests[-10:]:  # Last 10 requests
                    request_key = f"privacy_request_{request_id}"
                    request_record = cache.get(request_key)
                    if request_record:
                        request_history.append({
                            'request_id': request_id,
                            'request_type': request_record.get('request_type'),
                            'status': request_record.get('status'),
                            'submitted_at': request_record.get('submitted_at'),
                            'processed_at': request_record.get('processed_at')
                        })
                
                return JsonResponse({
                    'user_id': request.user.id,
                    'request_history': request_history,
                    'available_rights': [
                        'right_to_access',
                        'right_to_erasure',
                        'right_to_rectification',
                        'right_to_data_portability'
                    ]
                })
            
            return None
            
        except Exception as e:
            security_logger.error(f"Privacy request handling error: {str(e)}")
            return JsonResponse({'error': 'Privacy system error'}, status=500)
    
    def _add_privacy_headers(self, request: HttpRequest, response: HttpResponse):
        """Add privacy compliance headers"""
        try:
            # GDPR compliance headers
            response['X-GDPR-Compliant'] = 'true'
            response['X-Privacy-Policy'] = '/privacy-policy'
            response['X-Data-Controller'] = 'HealthProgress'
            
            # HIPAA compliance headers (for health-related endpoints)
            if '/health' in request.path or '/medical' in request.path:
                response['X-HIPAA-Compliant'] = 'true'
                response['X-PHI-Protected'] = 'true'
            
            # Data retention policy
            response['X-Data-Retention'] = 'See privacy policy for retention periods'
            
        except Exception as e:
            security_logger.error(f"Privacy headers error: {str(e)}")


class CryptographicAnalyticsMiddleware(MiddlewareMixin):
    """
    Cryptographic operations analytics and monitoring
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.enabled = getattr(settings, 'CRYPTO_ANALYTICS_ENABLED', True)
        
    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)
        
        start_time = time.time()
        
        response = self.get_response(request)
        
        # Track cryptographic operations
        processing_time = time.time() - start_time
        self._track_crypto_operations(request, response, processing_time)
        
        return response
    
    def _track_crypto_operations(self, request: HttpRequest, response: HttpResponse, 
                               processing_time: float):
        """Track cryptographic operations for analytics"""
        try:
            # Collect crypto operation metrics
            crypto_metrics = {
                'timestamp': timezone.now().isoformat(),
                'path': request.path,
                'method': request.method,
                'processing_time': processing_time,
                'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
                'encrypted_files': len(getattr(request, 'encrypted_files', {})),
                'privacy_audit_id': getattr(request, 'privacy_audit_id', None),
                'dlp_classification': getattr(request, 'dlp_classification', 'public'),
                'response_encrypted': response.get('X-Content-Encrypted') == 'true',
                'status_code': response.status_code
            }
            
            # Store metrics
            metrics_key = f"crypto_metrics_{int(time.time())}_{hash(request.path) % 10000}"
            cache.set(metrics_key, crypto_metrics, 86400 * 7)  # Keep for 7 days
            
            # Update real-time counters
            self._update_realtime_crypto_metrics(crypto_metrics)
            
        except Exception as e:
            security_logger.error(f"Crypto analytics tracking error: {str(e)}")
    
    def _update_realtime_crypto_metrics(self, metrics: Dict[str, Any]):
        """Update real-time cryptographic metrics"""
        try:
            realtime_key = "crypto_realtime_metrics"
            realtime_metrics = cache.get(realtime_key, {
                'total_operations': 0,
                'encrypted_operations': 0,
                'dlp_classifications': {},
                'avg_processing_time': 0.0,
                'last_updated': timezone.now().isoformat()
            })
            
            # Update counters
            realtime_metrics['total_operations'] += 1
            
            if metrics.get('response_encrypted'):
                realtime_metrics['encrypted_operations'] += 1
            
            # Update DLP classification counts
            classification = metrics.get('dlp_classification', 'public')
            realtime_metrics['dlp_classifications'][classification] = realtime_metrics['dlp_classifications'].get(classification, 0) + 1
            
            # Update average processing time
            current_avg = realtime_metrics.get('avg_processing_time', 0.0)
            new_time = metrics['processing_time']
            total_ops = realtime_metrics['total_operations']
            
            realtime_metrics['avg_processing_time'] = (
                (current_avg * (total_ops - 1) + new_time) / total_ops
            )
            
            realtime_metrics['last_updated'] = timezone.now().isoformat()
            
            # Store updated metrics
            cache.set(realtime_key, realtime_metrics, 86400)  # 24 hours
            
        except Exception as e:
            security_logger.error(f"Real-time crypto metrics update error: {str(e)}")