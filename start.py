#!/usr/bin/env python
"""
Safe Django Startup Script
Handles library loading issues and provides graceful degradation
"""
import os
import sys

def check_environment():
    """Check and prepare the environment"""
    print("🔍 Checking environment...")
    
    # Ensure we're in the right directory
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(BASE_DIR)
    
    # Check for .env file
    if not os.path.exists('.env'):
        print("⚠️  WARNING: .env file not found!")
        print("   Creating from .env.example...")
        if os.path.exists('.env.example'):
            import shutil
            shutil.copy('.env.example', '.env')
            print("   ✓ .env file created. Please update SECRET_KEY and other settings.")
        else:
            print("   ❌ .env.example not found. Please create .env file manually.")
            return False
    
    # Check for logs directory
    if not os.path.exists('logs'):
        print("📁 Creating logs directory...")
        os.makedirs('logs', exist_ok=True)
    
    # Check for media directory
    if not os.path.exists('media'):
        print("📁 Creating media directory...")
        os.makedirs('media', exist_ok=True)
    
    return True

def check_database():
    """Check if database is initialized"""
    if not os.path.exists('db.sqlite3'):
        print("\n⚠️  Database not found!")
        print("   Run these commands:")
        print("   1. python manage.py makemigrations")
        print("   2. python manage.py migrate")
        print("   3. python manage.py createsuperuser")
        print("   4. python manage.py createcachetable")
        return False
    return True

def main():
    """Main startup function"""
    print("=" * 60)
    print("🏥 HealthProgress Application Startup")
    print("=" * 60)
    
    # Check environment
    if not check_environment():
        sys.exit(1)
    
    # Set environment variable
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    
    # Try to import Django
    try:
        import django
        print(f"✓ Django {django.get_version()} loaded successfully")
    except ImportError as exc:
        print(f"❌ Error: Django not found - {exc}")
        sys.exit(1)
    
    # Setup Django
    try:
        django.setup()
        print("✓ Django setup completed")
    except Exception as e:
        print(f"❌ Error during Django setup: {e}")
        sys.exit(1)
    
    # Check database
    check_database()
    
    # Import and run management command
    try:
        from django.core.management import execute_from_command_line
        
        # Get command line arguments
        if len(sys.argv) > 1:
            # User provided command
            print(f"\n🚀 Executing: {' '.join(sys.argv[1:])}")
            execute_from_command_line(sys.argv)
        else:
            # Default to runserver
            print("\n🚀 Starting development server...")
            print("   Access at: http://127.0.0.1:8000")
            print("   Press CTRL+C to stop")
            print("-" * 60)
            execute_from_command_line(['manage.py', 'runserver'])
            
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
