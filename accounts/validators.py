"""
File upload security validators for HealthProgress
Implements multi-layer security validation
"""
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile
from PIL import Image
import os
import secrets

# Security Configuration
MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2MB
ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif']
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif']


def validate_image_file(image: UploadedFile) -> UploadedFile:
    """
    Comprehensive image file validation
    Implements multi-layer security checks to prevent:
    - File upload RCE attacks
    - Path traversal attacks
    - XSS via SVG files
    - Oversized file uploads
    """
    
    # Layer 1: File size validation
    if image.size > MAX_UPLOAD_SIZE:
        raise ValidationError(
            f'ขนาดไฟล์เกินขนาดสูงสุดที่อนุญาต {MAX_UPLOAD_SIZE/1024/1024:.1f}MB '
            f'ไฟล์ของคุณ: {image.size/1024/1024:.1f}MB'
        )
    
    # Layer 2: File extension validation
    ext = os.path.splitext(image.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            f'นามสกุลไฟล์ไม่ถูกต้อง: {ext} '
            f'อนุญาตเฉพาะ: {", ".join(ALLOWED_EXTENSIONS)}'
        )
    
    # Layer 3: MIME type validation (requires python-magic)
    try:
        import magic
        image.seek(0)
        file_mime = magic.from_buffer(image.read(2048), mime=True)
        image.seek(0)
        
        if file_mime not in ALLOWED_IMAGE_TYPES:
            raise ValidationError(
                f'ประเภทไฟล์ไม่ถูกต้อง: {file_mime} '
                f'อนุญาตเฉพาะ: {", ".join(ALLOWED_IMAGE_TYPES)}'
            )
    except ImportError:
        # Fallback if python-magic not installed
        # Still validate with Pillow below
        pass
    except Exception as e:
        raise ValidationError(f'ไม่สามารถตรวจสอบประเภทไฟล์: {str(e)}')
    
    # Layer 4: Image content validation using Pillow
    try:
        image.seek(0)
        img = Image.open(image)
        img.verify()  # Verify it's a valid image
        image.seek(0)  # Reset after verify
        
        # Check image format
        if img.format.upper() not in ['JPEG', 'PNG', 'GIF']:
            raise ValidationError(f'รูปแบบรูปภาพไม่ถูกต้อง: {img.format}')
        
        # Check image dimensions (prevent huge images)
        max_dimension = 4096  # 4K max
        if img.width > max_dimension or img.height > max_dimension:
            raise ValidationError(
                f'ขนาดรูปภาพใหญ่เกินไป สูงสุด: {max_dimension}x{max_dimension}px'
            )
            
    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(f'ไฟล์รูปภาพเสียหายหรือไม่ถูกต้อง: {str(e)}')
    
    # Layer 5: Sanitize filename to prevent path traversal
    image.name = sanitize_filename(image.name)
    
    return image


def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent path traversal attacks
    Generates secure random filename to prevent:
    - Directory traversal (../)
    - Overwriting existing files
    - Filename guessing attacks
    """
    # Get file extension
    ext = os.path.splitext(filename)[1].lower()
    
    # Generate secure random filename
    secure_name = f"{secrets.token_hex(16)}{ext}"
    
    return secure_name


def validate_profile_picture_size(image: UploadedFile) -> UploadedFile:
    """
    Additional validation specifically for profile pictures
    """
    try:
        img = Image.open(image)
        
        # Profile pictures should be square or near-square
        aspect_ratio = img.width / img.height
        if not (0.8 <= aspect_ratio <= 1.2):
            raise ValidationError(
                'รูปโปรไฟล์ควรเป็นรูปสี่เหลียมจัตุรัส '
                f'อัตราส่วนปัจจุบัน: {aspect_ratio:.2f}'
            )
        
        # Minimum dimensions for profile pictures
        min_size = 100
        if img.width < min_size or img.height < min_size:
            raise ValidationError(
                f'รูปโปรไฟล์เล็กเกินไป ขนาดขั้นต่ำ: {min_size}x{min_size}px'
            )
            
    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(f'ไม่สามารถตรวจสอบขนาดรูปภาพ: {str(e)}')
    
    return image


def validate_file_content(file_obj):
    """
    Additional content-based validation
    Prevents malicious file uploads by checking file content
    """
    # Check for common malicious patterns
    malicious_patterns = [
        b'<?php',
        b'<script',
        b'javascript:',
        b'eval(',
        b'base64_decode',
        b'system(',
        b'exec(',
    ]
    
    file_obj.seek(0)
    content = file_obj.read(8192)  # Read first 8KB
    file_obj.seek(0)
    
    content_lower = content.lower()
    for pattern in malicious_patterns:
        if pattern in content_lower:
            raise ValidationError(
                'ตรวจพบเนื้อหาที่อาจเป็นอันตรายในไฟล์'
            )
    
    return file_obj
