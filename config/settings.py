"""
Django settings for HealthProgress V11.1 (Security Hardened Edition)
CRITICAL: This version includes comprehensive security fixes
"""

from pathlib import Path
from decouple import config, Csv
import os

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY must be set via environment variable in production
# Generate key: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
# Validate SECRET_KEY in production
DEBUG = config('DEBUG', default=False, cast=bool)

try:
    SECRET_KEY = config('SECRET_KEY')
except Exception:
    if not DEBUG:
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured(
            'SECRET_KEY environment variable is required in production! '
            'Generate one with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
        )
    # Only for local development - generate temporary key
    import os
    SECRET_KEY = 'dev-only-' + os.urandom(32).hex()
    print("⚠️  Using temporary SECRET_KEY for development. Set SECRET_KEY in .env for persistence.")

# Security warning if DEBUG is enabled
if DEBUG:
    import warnings
    warnings.warn(
        "⚠️  DEBUG mode is enabled! This should NEVER be enabled in production!",
        RuntimeWarning
    )

if not DEBUG:
    if 'DEVELOPMENT' in SECRET_KEY or 'insecure' in SECRET_KEY:
        raise ValueError(
            'Invalid SECRET_KEY detected in production! '
            'Set SECRET_KEY environment variable with a secure random key.'
        )
    if len(SECRET_KEY) < 50:
        raise ValueError(
            'SECRET_KEY too short! Must be at least 50 characters.'
        )

# SECURITY: ALLOWED_HOSTS must be explicitly configured
ALLOWED_HOSTS = config(
    'ALLOWED_HOSTS',
    default='localhost,127.0.0.1,[::1]',
    cast=Csv()
)

# Production validation
if not DEBUG:
    if '*' in ALLOWED_HOSTS:
        raise ValueError(
            'Wildcard (*) in ALLOWED_HOSTS is not allowed in production!'
        )

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'crispy_forms',
    'crispy_bootstrap5',
    'accounts',
    'health_app',
    'security_enhancements',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Static file serving for PythonAnywhere
    'security_enhancements.owasp_security.OWASPSecurityMiddleware',  # Comprehensive OWASP security
    'security_enhancements.owasp_security.InputSanitizationMiddleware',  # Input sanitization
    'security_enhancements.owasp_security.AuthenticationSecurityMiddleware',  # Enhanced auth security
    'security_enhancements.owasp_security.DataProtectionMiddleware',  # Data protection
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Database Configuration
# PythonAnywhere supports MySQL and PostgreSQL
DATABASE_URL = config('DATABASE_URL', default='')
if DATABASE_URL:
    try:
        import dj_database_url
        DATABASES = {
            'default': dj_database_url.parse(DATABASE_URL)
        }
    except (ImportError, ModuleNotFoundError):
        print("⚠️  dj_database_url not installed. Install with: pip install dj-database-url")
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': BASE_DIR / 'db.sqlite3',
            }
        }
else:
    # Default configuration - update for PythonAnywhere MySQL
    if not DEBUG:
        # Production database configuration
        # For PythonAnywhere, update these settings:
        # DATABASES = {
        #     'default': {
        #         'ENGINE': 'django.db.backends.mysql',
        #         'NAME': config('DB_NAME', default='your_username$healthprogress'),
        #         'USER': config('DB_USER', default='your_username'),
        #         'PASSWORD': config('DB_PASSWORD', default=''),
        #         'HOST': config('DB_HOST', default='your_username.mysql.pythonanywhere-services.com'),
        #         'PORT': config('DB_PORT', default='3306'),
        #         'OPTIONS': {
        #             'charset': 'utf8mb4',
        #             'sql_mode': 'STRICT_TRANS_TABLES',
        #             'init_command': "SET innodb_strict_mode=1",
        #         },
        #     }
        # }
        
        # For now, use SQLite even in production mode for testing
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': BASE_DIR / 'db.sqlite3',
            }
        }
    else:
        # Development SQLite
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': BASE_DIR / 'db.sqlite3',
            }
        }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
    {'NAME': 'security_enhancements.validators.OWASPPasswordValidator', 'OPTIONS': {'min_length': 12, 'max_length': 128}},
]

LANGUAGE_CODE = 'th'
TIME_ZONE = 'Asia/Bangkok'
USE_I18N = True
USE_TZ = True

# Static files configuration for PythonAnywhere
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# PythonAnywhere static files path
if not DEBUG:
    STATIC_ROOT = '/home/yourusername/yourdomain.com/static'  # Update with your actual paths
    MEDIA_ROOT = '/home/yourusername/yourdomain.com/media'   # Update with your actual paths
else:
    STATIC_ROOT = BASE_DIR / 'staticfiles'
    MEDIA_ROOT = BASE_DIR / 'media'

MEDIA_URL = '/media/'

# WhiteNoise configuration for static files
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = DEBUG
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# SECURITY SETTINGS
if not DEBUG:
    # SSL/HTTPS settings for PythonAnywhere
    SECURE_SSL_REDIRECT = config('FORCE_HTTPS', default=True, cast=bool)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    
    # PythonAnywhere specific proxy settings
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    USE_X_FORWARDED_HOST = True
    USE_X_FORWARDED_PORT = True
    
    # Additional security headers for production
    SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
    SECURE_PERMISSIONS_POLICY = {
        'geolocation': [],
        'microphone': [],
        'camera': [],
        'payment': [],
        'usb': [],
    }

# Session Security
SESSION_COOKIE_AGE = 3600
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

# Rate Limiting Configuration
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_ENABLE = True

# Cache Configuration (Required for rate limiting)
# PythonAnywhere doesn't support Redis on free tier, use database cache
if not DEBUG:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
            'LOCATION': 'cache_table',
            'TIMEOUT': 300,
            'OPTIONS': {
                'MAX_ENTRIES': 1000,
                'CULL_FREQUENCY': 3,
            }
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'unique-snowflake',
            'TIMEOUT': 300,
            'OPTIONS': {
                'MAX_ENTRIES': 1000,
                'CULL_FREQUENCY': 3,
            }
        }
    }

# CSRF Protection
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript to read CSRF token
CSRF_COOKIE_SECURE = True if not DEBUG else False
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_USE_SESSIONS = False
CSRF_COOKIE_AGE = 31449600  # 1 year

# Content Security Policy (CSP)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = (
    "'self'",
    "'unsafe-inline'",  # Required for inline scripts
    "https://cdn.jsdelivr.net",
    "https://cdnjs.cloudflare.com",
)
CSP_STYLE_SRC = (
    "'self'",
    "'unsafe-inline'",  # Required for inline styles
    "https://cdn.jsdelivr.net",
    "https://cdnjs.cloudflare.com",
    "https://fonts.googleapis.com",
)
CSP_IMG_SRC = (
    "'self'",
    "data:",  # For base64 images
    "https:",
)
CSP_FONT_SRC = (
    "'self'",
    "data:",
    "https://fonts.gstatic.com",
    "https://cdnjs.cloudflare.com",
)
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)  # Prevent clickjacking
CSP_BASE_URI = ("'self'",)
CSP_FORM_ACTION = ("'self'",)
CSP_UPGRADE_INSECURE_REQUESTS = True if not DEBUG else False

# File Upload Security
FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
FILE_UPLOAD_PERMISSIONS = 0o644
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755

PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]

LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/health/dashboard/'
LOGOUT_REDIRECT_URL = '/accounts/login/'

MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_TIMEOUT = 300
MFA_MAX_ATTEMPTS = 3
MFA_LOCKOUT_DURATION = 900

handler404 = 'config.views.custom_404'
handler500 = 'config.views.custom_500'
handler403 = 'config.views.custom_403'

# Crispy Forms Configuration
CRISPY_TEMPLATE_PACK = 'bootstrap5'
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
handler400 = 'config.views.custom_400'

# OWASP Authentication Backend
AUTHENTICATION_BACKENDS = [
    'security_enhancements.secure_auth.SecureAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# OWASP Security Configuration
MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCKOUT_TIME = 1800  # 30 minutes
MAX_IP_ATTEMPTS = 10
IP_LOCKOUT_TIME = 3600  # 1 hour
PASSWORD_AGE_LIMIT_DAYS = 90
SESSION_MAX_AGE_HOURS = 24
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
TOTP_ISSUER = 'HealthProgress Security'

# Enhanced File Upload Security
FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
FILE_UPLOAD_PERMISSIONS = 0o644
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755
ALLOWED_UPLOAD_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt']
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB

# Logging Configuration - PythonAnywhere optimized
log_dir = BASE_DIR / 'logs' if DEBUG else Path('/home/yourusername/logs')  # Update path

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {asctime} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': log_dir / 'django.log',
            'maxBytes': 1024*1024*10,  # 10MB (smaller for PythonAnywhere)
            'backupCount': 5,  # Fewer backups to save space
            'formatter': 'verbose',
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': log_dir / 'security.log',
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['security_file', 'console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'accounts': {
            'handlers': ['file', 'security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'health_app': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
        'security_enhancements': {
            'handlers': ['security_file', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
}

# Email Configuration
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
if not DEBUG:
    EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
    EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
    EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
    EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
    EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
    DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@healthprogress.com')

# Ensure logs directory exists
if DEBUG:
    os.makedirs(BASE_DIR / 'logs', exist_ok=True)
else:
    os.makedirs('/home/yourusername/logs', exist_ok=True)  # Update with your username

# PythonAnywhere Production Settings
if not DEBUG:
    # Disable Django's own error emails in production
    ADMINS = [('Admin', config('ADMIN_EMAIL', default='admin@yourdomain.com'))]
    MANAGERS = ADMINS
    
    # Server email configuration
    SERVER_EMAIL = config('SERVER_EMAIL', default='server@yourdomain.com')
    
    # Time zone for PythonAnywhere servers (UTC)
    USE_TZ = True
    
    # Optimize for production
    CONN_MAX_AGE = 60  # Database connection pooling
    
    # Session optimization
    SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'
    SESSION_CACHE_ALIAS = 'default'
    
    # File upload optimization for PythonAnywhere
    FILE_UPLOAD_HANDLERS = [
        'django.core.files.uploadhandler.TemporaryFileUploadHandler',
    ]
    
    # Compress static files
    STATICFILES_FINDERS = [
        'django.contrib.staticfiles.finders.FileSystemFinder',
        'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    ]
