"""
WSGI config for HealthProgress on PythonAnywhere

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

For PythonAnywhere deployment:
1. Update the paths below with your username
2. Set environment variables in PythonAnywhere web app configuration
3. Set PYTHONANYWHERE_SITE environment variable
"""

import os
import sys

# >>> UPDATE THESE PATHS FOR PYTHONANYWHERE <<<
# Replace 'yourusername' with your actual PythonAnywhere username
path = '/home/yourusername/HealthProgressV15'  # Your project path
if path not in sys.path:
    sys.path.insert(0, path)

# Virtual environment (if using one on PythonAnywhere)
# venv_path = '/home/yourusername/.virtualenvs/healthprogress/lib/python3.10/site-packages'
# if venv_path not in sys.path:
#     sys.path.insert(0, venv_path)

# Set environment variables for PythonAnywhere
os.environ['PYTHONANYWHERE_SITE'] = 'yourusername.pythonanywhere.com'
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = os.path.join(path, '.env')
    load_dotenv(env_path)
except ImportError:
    # python-dotenv not available, use python-decouple instead
    pass

# Optional: Set up logging for debugging
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/home/yourusername/logs/wsgi.log'),  # Update path
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.info('WSGI application starting...')

# Initialize Django application
try:
    from django.core.wsgi import get_wsgi_application
    application = get_wsgi_application()
    logger.info('Django application initialized successfully')
except Exception as e:
    logger.error(f'Error initializing Django application: {e}')
    raise

# Optional: Add WhiteNoise for static files (if not using PythonAnywhere static files)
try:
    from whitenoise import WhiteNoise
    application = WhiteNoise(application)
    logger.info('WhiteNoise middleware added')
except ImportError:
    logger.info('WhiteNoise not available, using Django static files')
