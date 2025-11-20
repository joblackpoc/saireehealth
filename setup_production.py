#!/usr/bin/env python
"""
Production setup script for PythonAnywhere deployment
Run this after initial deployment to set up cache table and verify configuration
"""

import os
import sys
import django
from django.core.management import execute_from_command_line, call_command
from django.conf import settings

def setup_production():
    """Set up production environment"""
    
    print("🚀 Setting up HealthProgress for Production...")
    
    # Set Django settings module
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()
    
    try:
        # Create cache table
        print("📊 Creating cache table...")
        call_command('createcachetable')
        print("✅ Cache table created successfully")
        
        # Collect static files
        print("📁 Collecting static files...")
        call_command('collectstatic', '--noinput')
        print("✅ Static files collected")
        
        # Run system checks
        print("🔍 Running system checks...")
        call_command('check', '--deploy')
        print("✅ System checks passed")
        
        # Test database connection
        print("🔌 Testing database connection...")
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
        print("✅ Database connection successful")
        
        # Verify critical settings
        print("⚙️ Verifying production settings...")
        
        if settings.DEBUG:
            print("⚠️  WARNING: DEBUG is still enabled!")
        else:
            print("✅ DEBUG disabled")
            
        if '*' in settings.ALLOWED_HOSTS:
            print("⚠️  WARNING: Wildcard in ALLOWED_HOSTS!")
        else:
            print("✅ ALLOWED_HOSTS properly configured")
            
        if 'whitenoise' in str(settings.MIDDLEWARE):
            print("✅ WhiteNoise middleware enabled")
        else:
            print("⚠️  WARNING: WhiteNoise not found in middleware!")
            
        print("\n🎉 Production setup completed successfully!")
        print("\n📋 Next steps:")
        print("1. Create superuser: python manage.py createsuperuser")
        print("2. Configure your domain in PythonAnywhere Web tab")
        print("3. Set up static files mapping")
        print("4. Test your application")
        
    except Exception as e:
        print(f"❌ Error during setup: {e}")
        return False
        
    return True

if __name__ == '__main__':
    success = setup_production()
    sys.exit(0 if success else 1)