"""
OWASP Secure Forms and CSRF Protection
Enhanced form security with comprehensive CSRF protection
"""

import hashlib
import secrets
import time
from typing import Dict, Any, List, Optional
from django import forms
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import get_user_model
from security_enhancements.validators import InputValidator, OWASPPasswordValidator
import logging
import re

logger = logging.getLogger('security_enhancements')
User = get_user_model()

class SecureFormMixin:
    """
    Mixin for adding security features to Django forms
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._add_security_fields()
        self._apply_security_widgets()
    
    def _add_security_fields(self):
        """Add security-related hidden fields"""
        # Add timestamp to prevent replay attacks
        self.fields['security_timestamp'] = forms.CharField(
            widget=forms.HiddenInput(),
            required=False,
            initial=str(int(time.time()))
        )
        
        # Add form fingerprint for integrity checking
        self.fields['form_fingerprint'] = forms.CharField(
            widget=forms.HiddenInput(),
            required=False,
            initial=self._generate_form_fingerprint()
        )
    
    def _apply_security_widgets(self):
        """Apply security-focused widgets"""
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.TextInput):
                # Add security attributes to text inputs
                field.widget.attrs.update({
                    'autocomplete': 'off',
                    'spellcheck': 'false',
                    'maxlength': getattr(field, 'max_length', 100),
                })
            
            elif isinstance(field.widget, forms.PasswordInput):
                # Enhanced password input security
                field.widget.attrs.update({
                    'autocomplete': 'new-password',
                    'spellcheck': 'false',
                    'data-toggle': 'password',
                })
    
    def _generate_form_fingerprint(self) -> str:
        """Generate form fingerprint for integrity verification"""
        form_data = f"{self.__class__.__name__}:{time.time()}"
        return hashlib.sha256(form_data.encode()).hexdigest()[:16]
    
    def clean(self):
        """Enhanced form validation with security checks"""
        cleaned_data = super().clean()
        
        # Validate form timestamp (prevent replay attacks)
        self._validate_timestamp(cleaned_data)
        
        # Validate form fingerprint
        self._validate_fingerprint(cleaned_data)
        
        # Perform input sanitization and validation
        self._validate_inputs(cleaned_data)
        
        return cleaned_data
    
    def _validate_timestamp(self, cleaned_data: Dict[str, Any]):
        """Validate form submission timestamp"""
        timestamp_str = cleaned_data.get('security_timestamp')
        if timestamp_str:
            try:
                timestamp = int(timestamp_str)
                current_time = int(time.time())
                
                # Form should not be older than 30 minutes
                if current_time - timestamp > 1800:
                    raise ValidationError("Form has expired. Please refresh and try again.")
                
                # Form should not be from the future (allow 60 seconds for clock skew)
                if timestamp > current_time + 60:
                    raise ValidationError("Invalid form timestamp.")
                    
            except ValueError:
                raise ValidationError("Invalid timestamp format.")
    
    def _validate_fingerprint(self, cleaned_data: Dict[str, Any]):
        """Validate form fingerprint"""
        fingerprint = cleaned_data.get('form_fingerprint')
        if fingerprint and len(fingerprint) != 16:
            raise ValidationError("Invalid form fingerprint.")
    
    def _validate_inputs(self, cleaned_data: Dict[str, Any]):
        """Validate all form inputs for security threats"""
        for field_name, value in cleaned_data.items():
            if isinstance(value, str) and value:
                # Skip security fields
                if field_name in ['security_timestamp', 'form_fingerprint', 'csrfmiddlewaretoken']:
                    continue
                
                # Validate for malicious patterns
                if not InputValidator.validate_input(value):
                    logger.warning(f"Malicious input detected in field {field_name}: {value[:50]}...")
                    raise ValidationError(f"Invalid input in {field_name} field.")
                
                # Sanitize input
                cleaned_data[field_name] = InputValidator.sanitize_input(value, max_length=1000)


class SecureLoginForm(SecureFormMixin, AuthenticationForm):
    """
    Enhanced login form with security features
    """
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
        
        # Add rate limiting token
        self.fields['rate_limit_token'] = forms.CharField(
            widget=forms.HiddenInput(),
            required=False,
            initial=self._generate_rate_limit_token()
        )
    
    def _generate_rate_limit_token(self) -> str:
        """Generate token for rate limiting"""
        return secrets.token_urlsafe(16)
    
    def clean(self):
        """Enhanced login validation"""
        cleaned_data = super().clean()
        
        if self.request:
            # Check for brute force attempts
            self._check_rate_limiting()
            
            # Validate request characteristics
            self._validate_request_characteristics()
        
        return cleaned_data
    
    def _check_rate_limiting(self):
        """Check for rate limiting violations"""
        from django.core.cache import cache
        
        ip_address = self._get_client_ip()
        rate_key = f"login_rate:{ip_address}"
        
        attempts = cache.get(rate_key, 0)
        if attempts >= 5:
            raise ValidationError("Too many login attempts. Please try again later.")
    
    def _validate_request_characteristics(self):
        """Validate request characteristics for suspicious activity"""
        if not self.request:
            return
        
        # Check User-Agent
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        if not user_agent or len(user_agent) < 10:
            logger.warning(f"Suspicious login attempt with invalid User-Agent from {self._get_client_ip()}")
        
        # Check for common bot patterns
        bot_patterns = ['bot', 'crawler', 'spider', 'scraper']
        if any(pattern in user_agent.lower() for pattern in bot_patterns):
            raise ValidationError("Automated requests are not allowed.")
    
    def _get_client_ip(self) -> str:
        """Get client IP address"""
        if not self.request:
            return 'unknown'
        
        forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        return self.request.META.get('REMOTE_ADDR', 'unknown')


class SecureRegistrationForm(SecureFormMixin, UserCreationForm):
    """
    Enhanced registration form with security validation
    """
    
    email = forms.EmailField(
        required=True,
        help_text="Required. Enter a valid email address."
    )
    
    first_name = forms.CharField(
        max_length=30,
        required=True,
        help_text="Required. Your first name."
    )
    
    last_name = forms.CharField(
        max_length=30,
        required=True,
        help_text="Required. Your last name."
    )
    
    terms_accepted = forms.BooleanField(
        required=True,
        help_text="You must accept the terms and conditions."
    )
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Add password strength meter
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control password-strength',
            'data-strength-meter': 'true'
        })
    
    def clean_email(self):
        """Enhanced email validation"""
        email = self.cleaned_data.get('email')
        
        if email:
            # Validate email format and security
            if not InputValidator.validate_email(email):
                raise ValidationError("Invalid email address.")
            
            # Check for existing email
            if User.objects.filter(email=email).exists():
                raise ValidationError("A user with this email already exists.")
            
            # Check for disposable email domains
            if self._is_disposable_email(email):
                raise ValidationError("Disposable email addresses are not allowed.")
        
        return email
    
    def clean_username(self):
        """Enhanced username validation"""
        username = self.cleaned_data.get('username')
        
        if username:
            # Additional username security checks
            if not InputValidator.validate_input(username):
                raise ValidationError("Username contains invalid characters.")
            
            # Check for reserved usernames
            reserved_usernames = [
                'admin', 'administrator', 'root', 'system', 'api', 'www', 'mail', 'ftp', 'support', 'help', 'test', 'demo']            
            if username.lower() in reserved_usernames:
                raise ValidationError("This username is reserved.")


class SecureContactForm(SecureFormMixin, forms.Form):
    """Secure contact form with validation"""
    name = forms.CharField(max_length=100,  widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Your Name'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Your Email'}))
    subject = forms.CharField(max_length=200, widget=forms.TextInput(attrs={'class': 'form-control',  'placeholder': 'Subject'}))    
    message = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Your Message',  'rows': 5}))
    
    def clean_email(self):
        """Validate email address"""
        email = self.cleaned_data.get('email')     
        if email and not InputValidator.validate_email(email):            
            raise ValidationError("Please enter a valid email address.")
        return email
    
    def clean_message(self):       
        """Validate message content"""        
        message = self.cleaned_data.get('message')       
        if message: # Check message length\n            
            if len(message) < 10:
                raise ValidationError("Message must be at least 10 characters long.")  # Check for spam patterns\n            
            if self._is_spam_content(message):                
                raise ValidationError("Message content is not allowed.")
            return message
        
        def _is_spam_content(self, content: str) -> bool:        
            """Check for spam patterns in content"""
            spam_patterns = [ r'http[s]?://[^\\s]+',  # URLs           
                             r'\\b(?:buy|sell|cheap|free|money|cash|loan)\\b',  # Commercial terms
                            r'\\b(?:viagra|cialis|pharmacy)\\b',  # Pharmaceutical spam          
                            r'[A-Z]{10,}',  # Excessive capitals
            ]
            
            for pattern in spam_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True       
                return False



class CSRFEnhancedForm(forms.Form):
        """Form with enhanced CSRF protection"""
        def __init__(self, *args, **kwargs):
            self.request = kwargs.pop('request', None) 
            super().__init__(*args, **kwargs)   # Add additional CSRF validation
            if self.request:
                self.fields['csrf_validation_token'] = forms.CharField( widget=forms.HiddenInput(), initial=self._generate_csrf_validation_token())
                
        def _generate_csrf_validation_token(self) -> str:
            """Generate additional CSRF validation token"""
            if not self.request:            
                return '' # Create token based on session and timestamp        
            session_key = self.request.session.session_key or ''       
            timestamp = str(int(time.time()))          
            token_data = f"{session_key}:{timestamp}"       
            return hashlib.sha256(token_data.encode()).hexdigest()[:32]        
        def clean(self):
            """Validate CSRF token"""       
            cleaned_data = super().clean()             
            if self.request:        
                self._validate_csrf_token(cleaned_data)               
                return cleaned_data\
                    
        def _validate_csrf_token(self, cleaned_data: Dict[str, Any]):       
            """Validate additional CSRF token"""      
            token = cleaned_data.get('csrf_validation_token')        
            if token: # Validate token format            
                if len(token) != 32 or not token.isalnum():
                    raise ValidationError("Invalid CSRF token format.") # Log CSRF validatio           
                logger.debug(f"CSRF token validated for form {self.__class__.__name__}")
                
                
class SecureFileUploadForm(SecureFormMixin, forms.Form):
        """Secure file upload form with comprehensive validation"""
        file = forms.FileField(help_text="Select a file to upload (max 5MB)")
        description = forms.CharField(max_length=200, required=False, widget=forms.Textarea(attrs={'rows': 3}))
        
        def clean_file(self):
            """Comprehensive file validation"""
            uploaded_file = self.cleaned_data.get('file')
            
            if uploaded_file:
                from security_enhancements.validators import FileValidator
                
                # Validate file
                validation_result = FileValidator.validate_file(uploaded_file, 'image')
                
                if not validation_result['valid']:
                    raise ValidationError(validation_result['errors'][0])
                
                # Additional filename validation
                if not InputValidator.validate_filename(uploaded_file.name):
                    raise ValidationError("Invalid filename.")
            
            return uploaded_file