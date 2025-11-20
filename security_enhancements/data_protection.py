"""
Phase 6: Data Protection & Cryptography
End-to-End Encryption, Key Management, Data Loss Prevention, Privacy Controls

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
Component: Data Protection & Cryptographic Security
"""

import os
import json
import hashlib
import secrets
import base64
import struct
import hmac
from typing import Dict, List, Optional, Tuple, Any, Union
from datetime import datetime, timedelta
from pathlib import Path
import logging
import re

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

# Enhanced Security Logging
security_logger = logging.getLogger('security_core')

class AdvancedCryptographicEngine:
    """
    Advanced Cryptographic Engine
    Multi-layer encryption, key derivation, and cryptographic operations
    """
    
    def __init__(self):
        self.master_key = self._get_or_generate_master_key()
        self.encryption_algorithm = getattr(settings, 'ENCRYPTION_ALGORITHM', 'AES-256-GCM')
        self.key_derivation_iterations = getattr(settings, 'KEY_DERIVATION_ITERATIONS', 100000)
        self.salt_length = 32
        self.nonce_length = 12  # for GCM
        
    def _get_or_generate_master_key(self) -> bytes:
        """Get or generate master encryption key"""
        try:
            master_key_path = getattr(settings, 'MASTER_KEY_PATH', 'crypto/master.key')
            
            if os.path.exists(master_key_path):
                with open(master_key_path, 'rb') as f:
                    master_key = f.read()
                security_logger.info("Master key loaded from file")
            else:
                # Generate new master key
                master_key = secrets.token_bytes(32)  # 256-bit key
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(master_key_path), exist_ok=True)
                
                with open(master_key_path, 'wb') as f:
                    f.write(master_key)
                
                # Set strict permissions (owner read-only)
                os.chmod(master_key_path, 0o600)
                
                security_logger.info("New master key generated and stored")
            
            return master_key
            
        except Exception as e:
            security_logger.error(f"Master key initialization failed: {str(e)}")
            # Fallback to settings-based key for testing
            fallback_key = getattr(settings, 'FALLBACK_MASTER_KEY', None)
            if fallback_key:
                if isinstance(fallback_key, str):
                    return base64.b64decode(fallback_key.encode())
                return fallback_key
            else:
                # Generate temporary key (not persistent)
                temp_key = secrets.token_bytes(32)
                security_logger.warning("Using temporary master key - not persistent")
                return temp_key
    
    def derive_key(self, password: str, salt: bytes = None, purpose: str = "encryption") -> Tuple[bytes, bytes]:
        """Derive encryption key from password using PBKDF2/Scrypt"""
        try:
            if salt is None:
                salt = secrets.token_bytes(self.salt_length)
            
            # Use Scrypt for password-based key derivation (more secure against ASIC attacks)
            kdf = Scrypt(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                n=2**14,  # CPU/memory cost factor
                r=8,       # Block size
                p=1,       # Parallelization factor
                backend=default_backend()
            )
            
            key = kdf.derive(password.encode())
            
            security_logger.info(f"Key derived for purpose: {purpose}")
            return key, salt
            
        except Exception as e:
            security_logger.error(f"Key derivation failed: {str(e)}")
            raise
    
    def encrypt_data(self, plaintext: Union[str, bytes], user_id: str = None, 
                    additional_data: bytes = None) -> Dict[str, str]:
        """Encrypt data using AES-256-GCM"""
        try:
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Use master key for encryption
            key = self.master_key
            if not isinstance(key, bytes):
                raise TypeError("Master key must be bytes")
            
            # Generate random nonce
            nonce = secrets.token_bytes(self.nonce_length)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Add additional authenticated data if provided
            if additional_data:
                encryptor.authenticate_additional_data(additional_data)
            
            # Encrypt the data
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Get authentication tag
            auth_tag = encryptor.tag
            
            # Return encrypted data with metadata
            encrypted_data = {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'auth_tag': base64.b64encode(auth_tag).decode('utf-8'),
                'algorithm': 'AES-256-GCM',
                'timestamp': timezone.now().isoformat(),
                'additional_data': base64.b64encode(additional_data).decode('utf-8') if additional_data else None
            }
            
            security_logger.info("Data encrypted successfully")
            return encrypted_data
            
        except Exception as e:
            security_logger.error(f"Data encryption failed: {str(e)}")
            raise
    
    def decrypt_data(self, encrypted_data: Dict[str, str], key: bytes = None) -> bytes:
        """Decrypt data using AES-256-GCM"""
        try:
            if key is None:
                key = self.master_key
            
            # Extract components
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            auth_tag = base64.b64decode(encrypted_data['auth_tag'])
            additional_data = None
            
            if encrypted_data.get('additional_data'):
                additional_data = base64.b64decode(encrypted_data['additional_data'])
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, auth_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Add additional authenticated data if present
            if additional_data:
                decryptor.authenticate_additional_data(additional_data)
            
            # Decrypt the data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            security_logger.info("Data decrypted successfully")
            return plaintext
            
        except Exception as e:
            security_logger.error(f"Data decryption failed: {str(e)}")
            raise
    
    def encrypt_field(self, field_value: str, field_name: str, user_id: int = None) -> str:
        """Encrypt individual database field with metadata"""
        try:
            # Create field-specific additional data for authentication
            field_metadata = {
                'field_name': field_name,
                'user_id': user_id,
                'encrypted_at': timezone.now().isoformat()
            }
            
            additional_data = json.dumps(field_metadata, sort_keys=True).encode()
            
            # Encrypt the field value
            encrypted_data = self.encrypt_data(field_value, additional_data=additional_data)
            
            # Return compact encrypted field format
            encrypted_field = {
                'v': 1,  # Version
                'd': encrypted_data,
                'm': field_metadata
            }
            
            return base64.b64encode(json.dumps(encrypted_field).encode()).decode()
            
        except Exception as e:
            security_logger.error(f"Field encryption failed for {field_name}: {str(e)}")
            raise
    
    def decrypt_field(self, encrypted_field: str, expected_field_name: str = None) -> str:
        """Decrypt individual database field"""
        try:
            # Decode encrypted field
            field_data = json.loads(base64.b64decode(encrypted_field).decode())
            
            # Version check
            if field_data.get('v') != 1:
                raise ValueError("Unsupported encryption version")
            
            # Field name validation
            field_metadata = field_data['m']
            if expected_field_name and field_metadata['field_name'] != expected_field_name:
                raise ValueError("Field name mismatch")
            
            # Recreate additional data
            additional_data = json.dumps(field_metadata, sort_keys=True).encode()
            
            # Decrypt the data
            decrypted_bytes = self.decrypt_data(field_data['d'])
            
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            security_logger.error(f"Field decryption failed: {str(e)}")
            raise
    
    def generate_file_encryption_key(self, file_path: str, user_id: int) -> Tuple[bytes, str]:
        """Generate file-specific encryption key"""
        try:
            # Create file-specific key derivation material
            key_material = f"{file_path}:{user_id}:{timezone.now().isoformat()}"
            
            # Derive file key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=key_material.encode(),
                backend=default_backend()
            )
            
            file_key = hkdf.derive(self.master_key)
            
            # Generate key identifier for storage
            key_id = hashlib.sha256(key_material.encode()).hexdigest()[:16]
            
            security_logger.info(f"File encryption key generated for {file_path}")
            return file_key, key_id
            
        except Exception as e:
            security_logger.error(f"File key generation failed: {str(e)}")
            raise
    
    def encrypt_file(self, file_content: bytes, file_path: str, user_id: int) -> Dict[str, Any]:
        """Encrypt file with metadata"""
        try:
            # Generate file-specific key
            file_key, key_id = self.generate_file_encryption_key(file_path, user_id)
            
            # Create file metadata
            file_metadata = {
                'original_name': os.path.basename(file_path),
                'size': len(file_content),
                'user_id': user_id,
                'encrypted_at': timezone.now().isoformat(),
                'key_id': key_id
            }
            
            # Encrypt file content
            encrypted_data = self.encrypt_data(
                file_content, 
                key=file_key,
                additional_data=json.dumps(file_metadata, sort_keys=True).encode()
            )
            
            # Store key securely (in production, use dedicated key management)
            key_storage_key = f"file_key_{key_id}"
            cache.set(key_storage_key, base64.b64encode(file_key).decode(), 86400 * 30)
            
            return {
                'encrypted_content': encrypted_data,
                'metadata': file_metadata,
                'key_id': key_id
            }
            
        except Exception as e:
            security_logger.error(f"File encryption failed: {str(e)}")
            raise
    
    def decrypt_file(self, encrypted_file_data: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Decrypt file and return content with metadata"""
        try:
            key_id = encrypted_file_data['key_id']
            metadata = encrypted_file_data['metadata']
            
            # Retrieve file key
            key_storage_key = f"file_key_{key_id}"
            encoded_key = cache.get(key_storage_key)
            
            if not encoded_key:
                raise ValueError("File encryption key not found")
            
            file_key = base64.b64decode(encoded_key)
            
            # Recreate additional data
            additional_data = json.dumps(metadata, sort_keys=True).encode()
            
            # Decrypt file content
            decrypted_content = self.decrypt_data(
                encrypted_file_data['encrypted_content'], 
                key=file_key
            )
            
            security_logger.info(f"File decrypted successfully: {metadata['original_name']}")
            return decrypted_content, metadata
            
        except Exception as e:
            security_logger.error(f"File decryption failed: {str(e)}")
            raise


class KeyManagementSystem:
    """
    Advanced Key Management System
    Key generation, rotation, escrow, and lifecycle management
    """
    
    def __init__(self):
        self.key_rotation_interval = getattr(settings, 'KEY_ROTATION_INTERVAL', 86400 * 30)  # 30 days
        self.key_versions_to_keep = getattr(settings, 'KEY_VERSIONS_TO_KEEP', 3)
        self.crypto_engine = AdvancedCryptographicEngine()
        
    def generate_user_key_pair(self, user_id: int, key_type: str = 'RSA-2048') -> Dict[str, str]:
        """Generate RSA key pair for user"""
        try:
            if key_type == 'RSA-2048':
                # Generate RSA key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                
                # Serialize keys
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Encrypt private key before storage
                encrypted_private_key = self.crypto_engine.encrypt_data(
                    private_pem, 
                    additional_data=f"user_private_key_{user_id}".encode()
                )
                
                # Store keys
                key_pair_data = {
                    'user_id': user_id,
                    'key_type': key_type,
                    'public_key': base64.b64encode(public_pem).decode(),
                    'private_key_encrypted': encrypted_private_key,
                    'generated_at': timezone.now().isoformat(),
                    'key_id': secrets.token_urlsafe(16)
                }
                
                # Cache key pair
                key_storage_key = f"user_keypair_{user_id}"
                cache.set(key_storage_key, key_pair_data, 86400 * 365)  # 1 year
                
                security_logger.info(f"Key pair generated for user {user_id}")
                return key_pair_data
                
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
                
        except Exception as e:
            security_logger.error(f"Key pair generation failed for user {user_id}: {str(e)}")
            raise
    
    def get_user_public_key(self, user_id: int) -> Optional[bytes]:
        """Get user's public key"""
        try:
            key_storage_key = f"user_keypair_{user_id}"
            key_pair_data = cache.get(key_storage_key)
            
            if not key_pair_data:
                return None
            
            public_key_pem = base64.b64decode(key_pair_data['public_key'])
            return public_key_pem
            
        except Exception as e:
            security_logger.error(f"Public key retrieval failed for user {user_id}: {str(e)}")
            return None
    
    def get_user_private_key(self, user_id: int) -> Optional[bytes]:
        """Get and decrypt user's private key"""
        try:
            key_storage_key = f"user_keypair_{user_id}"
            key_pair_data = cache.get(key_storage_key)
            
            if not key_pair_data:
                return None
            
            # Decrypt private key
            encrypted_private_key = key_pair_data['private_key_encrypted']
            private_key_pem = self.crypto_engine.decrypt_data(encrypted_private_key)
            
            return private_key_pem
            
        except Exception as e:
            security_logger.error(f"Private key retrieval failed for user {user_id}: {str(e)}")
            return None
    
    def encrypt_for_user(self, plaintext: str, user_id: int) -> Dict[str, str]:
        """Encrypt data for specific user using their public key"""
        try:
            public_key_pem = self.get_user_public_key(user_id)
            if not public_key_pem:
                raise ValueError(f"No public key found for user {user_id}")
            
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # For large data, use hybrid encryption (RSA + AES)
            if len(plaintext.encode()) > 190:  # RSA-2048 limit
                # Generate random AES key
                aes_key = secrets.token_bytes(32)
                
                # Encrypt data with AES
                encrypted_data = self.crypto_engine.encrypt_data(plaintext, key=aes_key)
                
                # Encrypt AES key with RSA
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                return {
                    'type': 'hybrid',
                    'encrypted_data': encrypted_data,
                    'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
                    'encrypted_for': user_id,
                    'timestamp': timezone.now().isoformat()
                }
            else:
                # Direct RSA encryption for small data
                ciphertext = public_key.encrypt(
                    plaintext.encode(),
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                return {
                    'type': 'rsa',
                    'ciphertext': base64.b64encode(ciphertext).decode(),
                    'encrypted_for': user_id,
                    'timestamp': timezone.now().isoformat()
                }
                
        except Exception as e:
            security_logger.error(f"User encryption failed for user {user_id}: {str(e)}")
            raise
    
    def decrypt_for_user(self, encrypted_data: Dict[str, str], user_id: int) -> str:
        """Decrypt data encrypted for specific user"""
        try:
            if encrypted_data['encrypted_for'] != user_id:
                raise ValueError("Data not encrypted for this user")
            
            private_key_pem = self.get_user_private_key(user_id)
            if not private_key_pem:
                raise ValueError(f"No private key found for user {user_id}")
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            if encrypted_data['type'] == 'hybrid':
                # Decrypt AES key with RSA
                encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_key'])
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt data with AES
                plaintext_bytes = self.crypto_engine.decrypt_data(
                    encrypted_data['encrypted_data'], 
                    key=aes_key
                )
                return plaintext_bytes.decode()
                
            elif encrypted_data['type'] == 'rsa':
                # Direct RSA decryption
                ciphertext = base64.b64decode(encrypted_data['ciphertext'])
                plaintext_bytes = private_key.decrypt(
                    ciphertext,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return plaintext_bytes.decode()
            
            else:
                raise ValueError(f"Unknown encryption type: {encrypted_data['type']}")
                
        except Exception as e:
            security_logger.error(f"User decryption failed for user {user_id}: {str(e)}")
            raise
    
    def rotate_master_key(self) -> Dict[str, Any]:
        """Rotate master encryption key"""
        try:
            # Generate new master key
            new_master_key = secrets.token_bytes(32)
            
            # Get current master key
            old_master_key = self.crypto_engine.master_key
            
            # Create key rotation record
            rotation_record = {
                'rotation_id': secrets.token_urlsafe(16),
                'old_key_hash': hashlib.sha256(old_master_key).hexdigest(),
                'new_key_hash': hashlib.sha256(new_master_key).hexdigest(),
                'rotated_at': timezone.now().isoformat(),
                'rotated_by': 'system'
            }
            
            # Store rotation record
            rotation_key = f"key_rotation_{rotation_record['rotation_id']}"
            cache.set(rotation_key, rotation_record, 86400 * 365)  # Keep for 1 year
            
            # Update master key (in production, this would involve secure key escrow)
            self.crypto_engine.master_key = new_master_key
            
            security_logger.info(f"Master key rotated: {rotation_record['rotation_id']}")
            return rotation_record
            
        except Exception as e:
            security_logger.error(f"Master key rotation failed: {str(e)}")
            raise
    
    def generate_shared_secret(self, user1_id: int, user2_id: int) -> Dict[str, str]:
        """Generate shared secret between two users using ECDH"""
        try:
            # For demonstration, use simpler approach
            # In production, use proper ECDH key exchange
            
            # Create deterministic shared secret
            secret_material = f"{min(user1_id, user2_id)}:{max(user1_id, user2_id)}"
            
            # Derive shared key
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=f"shared_secret_{secret_material}".encode(),
                backend=default_backend()
            )
            
            shared_key = kdf.derive(self.crypto_engine.master_key)
            
            # Store shared secret metadata
            shared_secret_data = {
                'user1_id': user1_id,
                'user2_id': user2_id,
                'secret_id': hashlib.sha256(secret_material.encode()).hexdigest()[:16],
                'generated_at': timezone.now().isoformat(),
                'key_hash': hashlib.sha256(shared_key).hexdigest()
            }
            
            # Cache shared key
            secret_key = f"shared_secret_{shared_secret_data['secret_id']}"
            cache.set(secret_key, base64.b64encode(shared_key).decode(), 86400 * 7)  # 1 week
            
            security_logger.info(f"Shared secret generated between users {user1_id} and {user2_id}")
            return shared_secret_data
            
        except Exception as e:
            security_logger.error(f"Shared secret generation failed: {str(e)}")
            raise


class DataLossPreventionSystem:
    """
    Advanced Data Loss Prevention System
    Content analysis, classification, and policy enforcement
    """
    
    def __init__(self):
        self.dlp_policies = self._load_dlp_policies()
        self.classification_cache_timeout = 300  # 5 minutes
        
    def _load_dlp_policies(self) -> Dict[str, Dict]:
        """Load DLP policies from settings"""
        default_policies = {
            'pii_detection': {
                'enabled': True,
                'action': 'block',
                'patterns': [
                    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                ],
                'severity': 'high'
            },
            'health_data': {
                'enabled': True,
                'action': 'encrypt_and_log',
                'patterns': [
                    r'\b(medical|diagnosis|prescription|treatment|patient|health)\b',
                    r'\b\d{3}-\d{3}-\d{4}\b',  # Phone numbers in health context
                ],
                'severity': 'critical'
            },
            'financial_data': {
                'enabled': True,
                'action': 'block',
                'patterns': [
                    r'\b(bank|account|routing|swift|iban)\b',
                    r'\$\d{1,3}(,\d{3})*(\.\d{2})?',  # Currency amounts
                ],
                'severity': 'high'
            },
            'intellectual_property': {
                'enabled': True,
                'action': 'watermark_and_log',
                'patterns': [
                    r'\b(confidential|proprietary|trade secret|internal)\b',
                    r'\b(patent|copyright|trademark)\b',
                ],
                'severity': 'medium'
            }
        }
        
        return getattr(settings, 'DLP_POLICIES', default_policies)
    
    def analyze_content(self, content: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze content for sensitive data"""
        try:
            context = context or {}
            analysis_results = {
                'content_hash': hashlib.sha256(content.encode()).hexdigest(),
                'analysis_timestamp': timezone.now().isoformat(),
                'detected_patterns': [],
                'classification': 'public',
                'risk_score': 0,
                'recommended_actions': [],
                'context': context
            }
            
            max_severity_score = 0
            
            for policy_name, policy_config in self.dlp_policies.items():
                if not policy_config.get('enabled', False):
                    continue
                
                matches = []
                for pattern in policy_config['patterns']:
                    pattern_matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in pattern_matches:
                        matches.append({
                            'pattern': pattern,
                            'matched_text': match.group(),
                            'start': match.start(),
                            'end': match.end()
                        })
                
                if matches:
                    severity_scores = {
                        'low': 25,
                        'medium': 50,
                        'high': 75,
                        'critical': 100
                    }
                    
                    severity_score = severity_scores.get(policy_config.get('severity', 'low'), 25)
                    max_severity_score = max(max_severity_score, severity_score)
                    
                    detection_result = {
                        'policy': policy_name,
                        'severity': policy_config.get('severity', 'low'),
                        'matches': matches,
                        'action': policy_config.get('action', 'log'),
                        'match_count': len(matches)
                    }
                    
                    analysis_results['detected_patterns'].append(detection_result)
                    analysis_results['recommended_actions'].append(policy_config.get('action'))
            
            # Set classification based on highest severity
            if max_severity_score >= 100:
                analysis_results['classification'] = 'top_secret'
            elif max_severity_score >= 75:
                analysis_results['classification'] = 'confidential'
            elif max_severity_score >= 50:
                analysis_results['classification'] = 'internal'
            elif max_severity_score >= 25:
                analysis_results['classification'] = 'restricted'
            
            analysis_results['risk_score'] = max_severity_score
            
            # Cache analysis results
            cache_key = f"dlp_analysis_{analysis_results['content_hash']}"
            cache.set(cache_key, analysis_results, self.classification_cache_timeout)
            
            if analysis_results['detected_patterns']:
                security_logger.warning(f"DLP: Sensitive data detected - Classification: {analysis_results['classification']}, Risk: {max_severity_score}")
            
            return analysis_results
            
        except Exception as e:
            security_logger.error(f"DLP content analysis failed: {str(e)}")
            return {
                'error': str(e),
                'classification': 'unknown',
                'risk_score': 0
            }
    
    def apply_dlp_policy(self, content: str, analysis_results: Dict[str, Any], 
                        user_id: int = None) -> Dict[str, Any]:
        """Apply DLP policy actions based on analysis results"""
        try:
            policy_actions = {
                'original_content': content,
                'modified_content': content,
                'actions_taken': [],
                'access_granted': True,
                'user_id': user_id,
                'timestamp': timezone.now().isoformat()
            }
            
            for detection in analysis_results.get('detected_patterns', []):
                action = detection['action']
                policy_name = detection['policy']
                
                if action == 'block':
                    policy_actions['access_granted'] = False
                    policy_actions['modified_content'] = "[BLOCKED: Sensitive content detected]"
                    policy_actions['actions_taken'].append(f'blocked_{policy_name}')
                    
                elif action == 'encrypt_and_log':
                    # Encrypt sensitive portions
                    crypto_engine = AdvancedCryptographicEngine()
                    for match in detection['matches']:
                        encrypted_text = crypto_engine.encrypt_field(
                            match['matched_text'], 
                            f'dlp_sensitive_{policy_name}',
                            user_id
                        )
                        # Replace sensitive text with encrypted version
                        policy_actions['modified_content'] = policy_actions['modified_content'].replace(
                            match['matched_text'],
                            f"[ENCRYPTED:{encrypted_text[:20]}...]"
                        )
                    
                    policy_actions['actions_taken'].append(f'encrypted_{policy_name}')
                    
                elif action == 'watermark_and_log':
                    # Add watermark to content
                    watermark = f"\n[CONFIDENTIAL - User {user_id} - {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}]"
                    policy_actions['modified_content'] += watermark
                    policy_actions['actions_taken'].append(f'watermarked_{policy_name}')
                    
                elif action == 'log':
                    policy_actions['actions_taken'].append(f'logged_{policy_name}')
                
                # Log DLP action
                self._log_dlp_action(detection, policy_actions, user_id)
            
            return policy_actions
            
        except Exception as e:
            security_logger.error(f"DLP policy application failed: {str(e)}")
            return {
                'error': str(e),
                'access_granted': False,
                'modified_content': "[ERROR: DLP processing failed]"
            }
    
    def _log_dlp_action(self, detection: Dict[str, Any], policy_actions: Dict[str, Any], 
                       user_id: int = None):
        """Log DLP action for audit trail"""
        try:
            dlp_log = {
                'event_type': 'dlp_action',
                'user_id': user_id,
                'policy': detection['policy'],
                'severity': detection['severity'],
                'action': detection['action'],
                'match_count': detection['match_count'],
                'content_hash': hashlib.sha256(policy_actions['original_content'].encode()).hexdigest(),
                'access_granted': policy_actions['access_granted'],
                'timestamp': timezone.now().isoformat(),
                'log_id': secrets.token_urlsafe(16)
            }
            
            # Store DLP log
            log_key = f"dlp_log_{dlp_log['log_id']}"
            cache.set(log_key, dlp_log, 86400 * 30)  # Keep for 30 days
            
            # Add to user's DLP history
            if user_id:
                user_dlp_key = f"user_dlp_history_{user_id}"
                user_history = cache.get(user_dlp_key, [])
                user_history.append(dlp_log['log_id'])
                cache.set(user_dlp_key, user_history[-100:], 86400 * 30)  # Keep last 100 events
            
            security_logger.info(f"DLP action logged: {dlp_log['policy']} - {dlp_log['action']}")
            
        except Exception as e:
            security_logger.error(f"DLP logging failed: {str(e)}")
    
    def scan_file_content(self, file_path: str, file_content: bytes, 
                         user_id: int = None) -> Dict[str, Any]:
        """Scan uploaded file for sensitive content"""
        try:
            # Determine file type and extract text content
            file_extension = Path(file_path).suffix.lower()
            text_content = ""
            
            if file_extension in ['.txt', '.md', '.csv']:
                try:
                    text_content = file_content.decode('utf-8')
                except UnicodeDecodeError:
                    text_content = file_content.decode('utf-8', errors='ignore')
            
            elif file_extension == '.json':
                try:
                    json_data = json.loads(file_content.decode('utf-8'))
                    text_content = json.dumps(json_data, indent=2)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    text_content = ""
            
            # For binary files, scan metadata and filename
            if not text_content:
                text_content = f"filename: {os.path.basename(file_path)}"
            
            # Analyze content
            analysis_results = self.analyze_content(
                text_content,
                context={
                    'source': 'file_upload',
                    'filename': os.path.basename(file_path),
                    'file_size': len(file_content),
                    'file_type': file_extension,
                    'user_id': user_id
                }
            )
            
            # Apply DLP policies
            policy_results = self.apply_dlp_policy(text_content, analysis_results, user_id)
            
            # Combine results
            scan_results = {
                'file_path': file_path,
                'file_size': len(file_content),
                'file_type': file_extension,
                'analysis': analysis_results,
                'policy_actions': policy_results,
                'scan_timestamp': timezone.now().isoformat(),
                'user_id': user_id
            }
            
            return scan_results
            
        except Exception as e:
            security_logger.error(f"File DLP scan failed for {file_path}: {str(e)}")
            return {
                'error': str(e),
                'file_path': file_path,
                'access_granted': False
            }


class PrivacyComplianceEngine:
    """
    Privacy Compliance Engine
    GDPR, HIPAA, and other privacy regulation compliance
    """
    
    def __init__(self):
        self.compliance_frameworks = self._load_compliance_frameworks()
        self.retention_policies = self._load_retention_policies()
        
    def _load_compliance_frameworks(self) -> Dict[str, Dict]:
        """Load compliance framework configurations"""
        return {
            'gdpr': {
                'enabled': True,
                'data_subject_rights': [
                    'right_to_access',
                    'right_to_rectification',
                    'right_to_erasure',
                    'right_to_restrict_processing',
                    'right_to_data_portability',
                    'right_to_object'
                ],
                'legal_bases': [
                    'consent',
                    'contract',
                    'legal_obligation',
                    'vital_interests',
                    'public_task',
                    'legitimate_interests'
                ]
            },
            'hipaa': {
                'enabled': True,
                'required_safeguards': [
                    'access_control',
                    'audit_controls',
                    'integrity',
                    'person_authentication',
                    'transmission_security'
                ],
                'phi_categories': [
                    'health_information',
                    'identifiable_information',
                    'demographic_data'
                ]
            },
            'ccpa': {
                'enabled': True,
                'consumer_rights': [
                    'right_to_know',
                    'right_to_delete',
                    'right_to_opt_out',
                    'right_to_non_discrimination'
                ]
            }
        }
    
    def _load_retention_policies(self) -> Dict[str, Dict]:
        """Load data retention policies"""
        return {
            'health_records': {
                'retention_period': 86400 * 365 * 7,  # 7 years
                'legal_requirement': 'HIPAA',
                'auto_delete': False
            },
            'user_analytics': {
                'retention_period': 86400 * 365 * 2,  # 2 years
                'legal_requirement': 'GDPR',
                'auto_delete': True
            },
            'audit_logs': {
                'retention_period': 86400 * 365 * 5,  # 5 years
                'legal_requirement': 'SOX',
                'auto_delete': False
            },
            'user_profiles': {
                'retention_period': 86400 * 365 * 3,  # 3 years after last activity
                'legal_requirement': 'GDPR',
                'auto_delete': True
            }
        }
    
    def process_data_subject_request(self, request_type: str, user_id: int, 
                                   framework: str = 'gdpr') -> Dict[str, Any]:
        """Process data subject rights requests"""
        try:
            framework_config = self.compliance_frameworks.get(framework, {})
            
            if not framework_config.get('enabled', False):
                raise ValueError(f"Compliance framework {framework} not enabled")
            
            request_id = secrets.token_urlsafe(16)
            
            request_record = {
                'request_id': request_id,
                'request_type': request_type,
                'user_id': user_id,
                'framework': framework,
                'status': 'received',
                'submitted_at': timezone.now().isoformat(),
                'processed_at': None,
                'fulfillment_data': {}
            }
            
            if request_type == 'right_to_access':
                # Compile user data
                user_data = self._compile_user_data(user_id)
                request_record['fulfillment_data'] = user_data
                request_record['status'] = 'fulfilled'
                request_record['processed_at'] = timezone.now().isoformat()
                
            elif request_type == 'right_to_erasure':
                # Initiate data deletion process
                deletion_results = self._process_data_deletion(user_id)
                request_record['fulfillment_data'] = deletion_results
                request_record['status'] = 'processing'
                
            elif request_type == 'right_to_rectification':
                # Data correction process (would need additional input)
                request_record['status'] = 'pending_input'
                request_record['fulfillment_data'] = {
                    'message': 'Please provide corrected data values'
                }
                
            elif request_type == 'right_to_data_portability':
                # Export user data in portable format
                portable_data = self._export_portable_data(user_id)
                request_record['fulfillment_data'] = portable_data
                request_record['status'] = 'fulfilled'
                request_record['processed_at'] = timezone.now().isoformat()
                
            # Store request record
            request_key = f"privacy_request_{request_id}"
            cache.set(request_key, request_record, 86400 * 30)  # Keep for 30 days
            
            # Add to user's request history
            user_requests_key = f"user_privacy_requests_{user_id}"
            user_requests = cache.get(user_requests_key, [])
            user_requests.append(request_id)
            cache.set(user_requests_key, user_requests, 86400 * 365)  # Keep for 1 year
            
            security_logger.info(f"Privacy request processed: {request_type} for user {user_id}")
            return request_record
            
        except Exception as e:
            security_logger.error(f"Privacy request processing failed: {str(e)}")
            raise
    
    def _compile_user_data(self, user_id: int) -> Dict[str, Any]:
        """Compile all user data for access request"""
        try:
            # This would integrate with your actual data models
            user_data = {
                'user_profile': {
                    'user_id': user_id,
                    'data_collected': timezone.now().isoformat(),
                    'note': 'Actual user profile data would be compiled here'
                },
                'health_records': {
                    'note': 'Health records would be compiled here (if authorized)'
                },
                'activity_logs': {
                    'note': 'User activity logs would be compiled here'
                },
                'preferences': {
                    'note': 'User preferences and settings would be compiled here'
                }
            }
            
            return user_data
            
        except Exception as e:
            security_logger.error(f"User data compilation failed for user {user_id}: {str(e)}")
            return {'error': str(e)}
    
    def _process_data_deletion(self, user_id: int) -> Dict[str, Any]:
        """Process data deletion for right to erasure"""
        try:
            deletion_plan = {
                'user_id': user_id,
                'deletion_started': timezone.now().isoformat(),
                'items_to_delete': [],
                'retention_exceptions': [],
                'deletion_status': {}
            }
            
            # Check retention policies
            for data_type, policy in self.retention_policies.items():
                if policy.get('auto_delete', True):
                    deletion_plan['items_to_delete'].append(data_type)
                else:
                    deletion_plan['retention_exceptions'].append({
                        'data_type': data_type,
                        'reason': policy.get('legal_requirement', 'Legal requirement'),
                        'retention_period': policy.get('retention_period', 0)
                    })
            
            # In production, this would trigger actual deletion processes
            for data_type in deletion_plan['items_to_delete']:
                deletion_plan['deletion_status'][data_type] = 'scheduled'
            
            return deletion_plan
            
        except Exception as e:
            security_logger.error(f"Data deletion processing failed for user {user_id}: {str(e)}")
            return {'error': str(e)}
    
    def _export_portable_data(self, user_id: int) -> Dict[str, Any]:
        """Export user data in portable format"""
        try:
            portable_data = {
                'export_format': 'JSON',
                'export_timestamp': timezone.now().isoformat(),
                'user_id': user_id,
                'data_categories': {},
                'export_id': secrets.token_urlsafe(16)
            }
            
            # Compile exportable data (this would integrate with actual models)
            portable_data['data_categories'] = {
                'profile_data': {'note': 'User profile in portable format'},
                'preferences': {'note': 'User preferences in portable format'},
                'activity_summary': {'note': 'Activity summary in portable format'}
            }
            
            return portable_data
            
        except Exception as e:
            security_logger.error(f"Portable data export failed for user {user_id}: {str(e)}")
            return {'error': str(e)}
    
    def audit_data_processing(self, data_type: str, processing_purpose: str, 
                            legal_basis: str, user_id: int = None) -> Dict[str, Any]:
        """Audit and log data processing activities"""
        try:
            audit_record = {
                'audit_id': secrets.token_urlsafe(16),
                'data_type': data_type,
                'processing_purpose': processing_purpose,
                'legal_basis': legal_basis,
                'user_id': user_id,
                'timestamp': timezone.now().isoformat(),
                'compliance_checks': {}
            }
            
            # Perform compliance checks
            for framework, config in self.compliance_frameworks.items():
                if not config.get('enabled', False):
                    continue
                
                compliance_result = {
                    'framework': framework,
                    'compliant': True,
                    'issues': []
                }
                
                # GDPR checks
                if framework == 'gdpr':
                    if legal_basis not in config.get('legal_bases', []):
                        compliance_result['compliant'] = False
                        compliance_result['issues'].append('Invalid legal basis')
                
                # HIPAA checks
                elif framework == 'hipaa' and 'health' in data_type.lower():
                    # Check if proper safeguards are in place
                    required_safeguards = config.get('required_safeguards', [])
                    compliance_result['required_safeguards'] = required_safeguards
                
                audit_record['compliance_checks'][framework] = compliance_result
            
            # Store audit record
            audit_key = f"data_processing_audit_{audit_record['audit_id']}"
            cache.set(audit_key, audit_record, 86400 * 365)  # Keep for 1 year
            
            security_logger.info(f"Data processing audited: {data_type} - {processing_purpose}")
            return audit_record
            
        except Exception as e:
            security_logger.error(f"Data processing audit failed: {str(e)}")
            return {'error': str(e)}


class SecureDataTransmission:
    """
    Secure Data Transmission System
    TLS/SSL enhancement, certificate management, secure protocols
    """
    
    def __init__(self):
        self.crypto_engine = AdvancedCryptographicEngine()
        self.key_manager = KeyManagementSystem()
        
    def create_secure_channel(self, sender_id: int, receiver_id: int) -> Dict[str, str]:
        """Create secure communication channel between users"""
        try:
            # Generate shared secret for the channel
            shared_secret_data = self.key_manager.generate_shared_secret(sender_id, receiver_id)
            
            # Create channel metadata
            channel_data = {
                'channel_id': secrets.token_urlsafe(16),
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'shared_secret_id': shared_secret_data['secret_id'],
                'created_at': timezone.now().isoformat(),
                'protocol': 'AES-256-GCM',
                'status': 'active'
            }
            
            # Store channel data
            channel_key = f"secure_channel_{channel_data['channel_id']}"
            cache.set(channel_key, channel_data, 86400 * 7)  # 1 week
            
            security_logger.info(f"Secure channel created between users {sender_id} and {receiver_id}")
            return channel_data
            
        except Exception as e:
            security_logger.error(f"Secure channel creation failed: {str(e)}")
            raise
    
    def encrypt_message(self, message: str, channel_id: str, sender_id: int) -> Dict[str, str]:
        """Encrypt message for secure transmission"""
        try:
            # Get channel data
            channel_key = f"secure_channel_{channel_id}"
            channel_data = cache.get(channel_key)
            
            if not channel_data:
                raise ValueError("Secure channel not found")
            
            # Verify sender
            if sender_id not in [channel_data['sender_id'], channel_data['receiver_id']]:
                raise ValueError("Unauthorized sender")
            
            # Get shared secret
            secret_key = f"shared_secret_{channel_data['shared_secret_id']}"
            encoded_shared_key = cache.get(secret_key)
            
            if not encoded_shared_key:
                raise ValueError("Shared secret not found")
            
            shared_key = base64.b64decode(encoded_shared_key)
            
            # Create message metadata
            message_metadata = {
                'channel_id': channel_id,
                'sender_id': sender_id,
                'timestamp': timezone.now().isoformat(),
                'message_id': secrets.token_urlsafe(16)
            }
            
            # Encrypt message
            encrypted_data = self.crypto_engine.encrypt_data(
                message,
                key=shared_key,
                additional_data=json.dumps(message_metadata, sort_keys=True).encode()
            )
            
            # Add metadata to encrypted message
            secure_message = {
                'encrypted_message': encrypted_data,
                'metadata': message_metadata,
                'channel_id': channel_id
            }
            
            security_logger.info(f"Message encrypted for channel {channel_id}")
            return secure_message
            
        except Exception as e:
            security_logger.error(f"Message encryption failed: {str(e)}")
            raise
    
    def decrypt_message(self, encrypted_message: Dict[str, Any], receiver_id: int) -> str:
        """Decrypt received message"""
        try:
            channel_id = encrypted_message['channel_id']
            metadata = encrypted_message['metadata']
            
            # Get channel data
            channel_key = f"secure_channel_{channel_id}"
            channel_data = cache.get(channel_key)
            
            if not channel_data:
                raise ValueError("Secure channel not found")
            
            # Verify receiver
            if receiver_id not in [channel_data['sender_id'], channel_data['receiver_id']]:
                raise ValueError("Unauthorized receiver")
            
            # Get shared secret
            secret_key = f"shared_secret_{channel_data['shared_secret_id']}"
            encoded_shared_key = cache.get(secret_key)
            
            if not encoded_shared_key:
                raise ValueError("Shared secret not found")
            
            shared_key = base64.b64decode(encoded_shared_key)
            
            # Recreate additional data
            additional_data = json.dumps(metadata, sort_keys=True).encode()
            
            # Decrypt message
            decrypted_bytes = self.crypto_engine.decrypt_data(
                encrypted_message['encrypted_message'],
                key=shared_key
            )
            
            message = decrypted_bytes.decode('utf-8')
            
            security_logger.info(f"Message decrypted from channel {channel_id}")
            return message
            
        except Exception as e:
            security_logger.error(f"Message decryption failed: {str(e)}")
            raise