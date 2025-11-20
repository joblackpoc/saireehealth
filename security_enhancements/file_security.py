"""
Advanced File Upload Security for HealthProgress
Protects against malicious file uploads, Zip Slip, and file-based attacks
"""
import os
import mimetypes
import magic
import zipfile
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from .security_core import SecurityLogger, InputSanitizer


class FileSecurityValidator:
    """Comprehensive File Security Validation"""
    
    # Allowed MIME types
    ALLOWED_MIME_TYPES = {
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/plain', 'text/csv',
    }
    
    # Executable signatures (magic bytes)
    EXECUTABLE_SIGNATURES = [
        b'MZ',  # Windows PE
        b'\x7fELF',  # Linux ELF
        b'\xca\xfe\xba\xbe',  # Mach-O
        b'#!',  # Shell script
        b'<script',  # HTML with script
        b'<?php',  # PHP script
    ]
    
    # Maximum file sizes (in bytes)
    MAX_FILE_SIZES = {
        'image': 5 * 1024 * 1024,  # 5MB
        'document': 10 * 1024 * 1024,  # 10MB
        'default': 10 * 1024 * 1024,  # 10MB
    }
    
    @classmethod
    def validate_file(cls, uploaded_file: UploadedFile, 
                     request=None) -> Tuple[bool, str]:
        """
        Comprehensive file validation
        Returns: (is_valid, error_message)
        """
        
        # 1. Check file size
        is_valid, error = cls._validate_size(uploaded_file)
        if not is_valid:
            cls._log_violation('file_size_exceeded', uploaded_file, request, error)
            return False, error
        
        # 2. Validate filename
        is_valid, error = cls._validate_filename(uploaded_file.name)
        if not is_valid:
            cls._log_violation('invalid_filename', uploaded_file, request, error)
            return False, error
        
        # 3. Validate file extension
        is_valid, error = cls._validate_extension(uploaded_file.name)
        if not is_valid:
            cls._log_violation('invalid_extension', uploaded_file, request, error)
            return False, error
        
        # 4. Validate MIME type
        is_valid, error = cls._validate_mime_type(uploaded_file)
        if not is_valid:
            cls._log_violation('invalid_mime_type', uploaded_file, request, error)
            return False, error
        
        # 5. Check for executable content
        is_valid, error = cls._check_executable_content(uploaded_file)
        if not is_valid:
            cls._log_violation('executable_content', uploaded_file, request, error)
            return False, error
        
        # 6. Scan for malicious patterns
        is_valid, error = cls._scan_malicious_patterns(uploaded_file)
        if not is_valid:
            cls._log_violation('malicious_patterns', uploaded_file, request, error)
            return False, error
        
        # 7. Special checks for specific file types
        ext = Path(uploaded_file.name).suffix.lower()
        if ext in ['.zip', '.rar', '.7z']:
            is_valid, error = cls._validate_archive(uploaded_file)
            if not is_valid:
                cls._log_violation('malicious_archive', uploaded_file, request, error)
                return False, error
        
        if ext == '.pdf':
            is_valid, error = cls._validate_pdf(uploaded_file)
            if not is_valid:
                cls._log_violation('malicious_pdf', uploaded_file, request, error)
                return False, error
        
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            is_valid, error = cls._validate_image(uploaded_file)
            if not is_valid:
                cls._log_violation('malicious_image', uploaded_file, request, error)
                return False, error
        
        return True, "File is valid"
    
    @classmethod
    def _validate_size(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Validate file size"""
        file_type = cls._get_file_category(uploaded_file.name)
        max_size = cls.MAX_FILE_SIZES.get(file_type, cls.MAX_FILE_SIZES['default'])
        
        if uploaded_file.size > max_size:
            return False, f"File size exceeds maximum allowed ({max_size / 1024 / 1024}MB)"
        
        return True, ""
    
    @classmethod
    def _validate_filename(cls, filename: str) -> Tuple[bool, str]:
        """Validate filename for malicious patterns"""
        # Sanitize filename
        sanitized = InputSanitizer.sanitize_filename(filename)
        
        if not sanitized:
            return False, "Invalid filename"
        
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False, "Filename contains path traversal characters"
        
        # Check for null bytes
        if '\x00' in filename:
            return False, "Filename contains null bytes"
        
        # Check for double extensions
        parts = filename.split('.')
        if len(parts) > 2:
            # Check for executable extensions before the real extension
            dangerous_extensions = ['exe', 'bat', 'cmd', 'sh', 'php', 'jsp', 'asp']
            for part in parts[:-1]:
                if part.lower() in dangerous_extensions:
                    return False, "Suspicious double extension detected"
        
        return True, ""
    
    @classmethod
    def _validate_extension(cls, filename: str) -> Tuple[bool, str]:
        """Validate file extension"""
        allowed_extensions = getattr(settings, 'ALLOWED_FILE_EXTENSIONS', [
            '.jpg', '.jpeg', '.png', '.gif', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.txt', '.csv'
        ])
        
        ext = Path(filename).suffix.lower()
        
        if not ext:
            return False, "File has no extension"
        
        if ext not in allowed_extensions:
            return False, f"File extension '{ext}' is not allowed"
        
        return True, ""
    
    @classmethod
    def _validate_mime_type(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Validate MIME type using python-magic"""
        try:
            # Read first chunk of file
            uploaded_file.seek(0)
            file_content = uploaded_file.read(2048)
            uploaded_file.seek(0)
            
            # Detect MIME type
            mime = magic.from_buffer(file_content, mime=True)
            
            if mime not in cls.ALLOWED_MIME_TYPES:
                return False, f"MIME type '{mime}' is not allowed"
            
            # Verify MIME type matches extension
            ext = Path(uploaded_file.name).suffix.lower()
            expected_mime = mimetypes.types_map.get(ext, '')
            
            if expected_mime and mime != expected_mime:
                # Allow some common mismatches
                allowed_mismatches = {
                    ('.jpg', 'image/jpeg'): ['image/jpg'],
                    ('.jpeg', 'image/jpeg'): ['image/jpg'],
                }
                
                if (ext, expected_mime) not in allowed_mismatches or \
                   mime not in allowed_mismatches.get((ext, expected_mime), []):
                    return False, f"MIME type mismatch: extension suggests '{expected_mime}' but file is '{mime}'"
            
        except Exception as e:
            return False, f"Error validating MIME type: {str(e)}"
        
        return True, ""
    
    @classmethod
    def _check_executable_content(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Check for executable content"""
        uploaded_file.seek(0)
        content = uploaded_file.read(1024)
        uploaded_file.seek(0)
        
        # Check for executable signatures
        for signature in cls.EXECUTABLE_SIGNATURES:
            if content.startswith(signature):
                return False, "File contains executable content"
        
        return True, ""
    
    @classmethod
    def _scan_malicious_patterns(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Scan file for malicious patterns"""
        try:
            uploaded_file.seek(0)
            content = uploaded_file.read()
            uploaded_file.seek(0)
            
            # Convert to string for text files
            try:
                text_content = content.decode('utf-8', errors='ignore')
                
                # Check for malicious patterns
                malicious_patterns = [
                    b'eval(', b'exec(', b'system(', b'shell_exec(',
                    b'<?php', b'<script', b'javascript:',
                    b'<iframe', b'<embed', b'<object',
                ]
                
                for pattern in malicious_patterns:
                    if pattern in content:
                        return False, f"Malicious pattern detected: {pattern.decode('utf-8', errors='ignore')}"
            
            except UnicodeDecodeError:
                pass  # Binary file, skip text-based checks
        
        except Exception as e:
            return False, f"Error scanning file: {str(e)}"
        
        return True, ""
    
    @classmethod
    def _validate_archive(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Validate archive files for Zip Slip vulnerability"""
        try:
            uploaded_file.seek(0)
            
            if uploaded_file.name.endswith('.zip'):
                with zipfile.ZipFile(uploaded_file, 'r') as zip_file:
                    # Check for Zip Slip
                    for member in zip_file.namelist():
                        # Check for path traversal
                        if member.startswith('/') or '..' in member:
                            return False, "Archive contains path traversal (Zip Slip attack detected)"
                        
                        # Check for absolute paths
                        if os.path.isabs(member):
                            return False, "Archive contains absolute paths"
                        
                        # Check for symlinks (can be used for directory traversal)
                        info = zip_file.getinfo(member)
                        if info.external_attr >> 16 == 0o120000:  # Symlink
                            return False, "Archive contains symlinks"
                    
                    # Check total uncompressed size to prevent zip bombs
                    total_size = sum(info.file_size for info in zip_file.infolist())
                    if total_size > 100 * 1024 * 1024:  # 100MB
                        return False, "Archive uncompressed size too large (potential zip bomb)"
            
            uploaded_file.seek(0)
        
        except zipfile.BadZipFile:
            return False, "Corrupted or invalid ZIP file"
        except Exception as e:
            return False, f"Error validating archive: {str(e)}"
        
        return True, ""
    
    @classmethod
    def _validate_pdf(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Validate PDF for malicious content"""
        try:
            uploaded_file.seek(0)
            content = uploaded_file.read()
            uploaded_file.seek(0)
            
            # Check for JavaScript in PDF
            if b'/JavaScript' in content or b'/JS' in content:
                return False, "PDF contains JavaScript"
            
            # Check for launch actions
            if b'/Launch' in content:
                return False, "PDF contains launch action"
            
            # Check for embedded files
            if b'/EmbeddedFile' in content:
                return False, "PDF contains embedded files"
        
        except Exception as e:
            return False, f"Error validating PDF: {str(e)}"
        
        return True, ""
    
    @classmethod
    def _validate_image(cls, uploaded_file: UploadedFile) -> Tuple[bool, str]:
        """Validate image for malicious content"""
        try:
            from PIL import Image
            
            uploaded_file.seek(0)
            img = Image.open(uploaded_file)
            
            # Verify image can be loaded
            img.verify()
            
            # Check for suspicious metadata
            if hasattr(img, '_getexif') and img._getexif():
                exif = img._getexif()
                # Check for script in metadata
                for tag, value in exif.items():
                    if isinstance(value, str):
                        if '<script' in value.lower() or 'javascript:' in value.lower():
                            return False, "Image metadata contains suspicious content"
            
            uploaded_file.seek(0)
        
        except Exception as e:
            return False, f"Invalid or corrupted image: {str(e)}"
        
        return True, ""
    
    @classmethod
    def _get_file_category(cls, filename: str) -> str:
        """Get file category based on extension"""
        ext = Path(filename).suffix.lower()
        
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            return 'image'
        elif ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.csv']:
            return 'document'
        
        return 'default'
    
    @classmethod
    def _log_violation(cls, violation_type: str, uploaded_file: UploadedFile, 
                       request, details: str):
        """Log file security violation"""
        SecurityLogger.log_security_event(
            f'file_security_{violation_type}',
            'high',
            {
                'filename': uploaded_file.name,
                'size': uploaded_file.size,
                'content_type': uploaded_file.content_type,
                'details': details
            },
            request=request,
            user=request.user if request and request.user.is_authenticated else None
        )
    
    @classmethod
    def calculate_file_hash(cls, uploaded_file: UploadedFile) -> str:
        """Calculate SHA-256 hash of file"""
        uploaded_file.seek(0)
        file_hash = hashlib.sha256()
        
        for chunk in uploaded_file.chunks():
            file_hash.update(chunk)
        
        uploaded_file.seek(0)
        return file_hash.hexdigest()
    
    @classmethod
    def quarantine_file(cls, uploaded_file: UploadedFile, reason: str) -> str:
        """Move suspicious file to quarantine"""
        quarantine_dir = Path(settings.MEDIA_ROOT) / 'quarantine'
        quarantine_dir.mkdir(exist_ok=True)
        
        # Generate safe filename
        file_hash = cls.calculate_file_hash(uploaded_file)
        quarantine_path = quarantine_dir / f"{file_hash}_{uploaded_file.name}"
        
        # Save file to quarantine
        uploaded_file.seek(0)
        with open(quarantine_path, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)
        
        # Log quarantine
        SecurityLogger.log_security_event(
            'file_quarantined',
            'high',
            {
                'filename': uploaded_file.name,
                'hash': file_hash,
                'reason': reason,
                'quarantine_path': str(quarantine_path)
            },
            request=None
        )
        
        return str(quarantine_path)