# Quick Deployment Guide

## 🖥️ Running on Localhost

### 1. First Time Setup

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Setup database
python manage.py makemigrations
python manage.py migrate
python manage.py createcachetable

# Create superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic --noinput
```

### 2. Start Server

**Option A: Using start script (Recommended)**
```bash
python start.py
```

**Option B: Using manage.py**
```bash
python manage.py runserver
```

**Option C: Custom port**
```bash
python manage.py runserver 0.0.0.0:8080
```

### 3. Access Application

- Main Site: http://127.0.0.1:8000
- Admin Panel: http://127.0.0.1:8000/admin
- Health Dashboard: http://127.0.0.1:8000/health/dashboard/

---

## 🌐 Deploying to PythonAnywhere

### Step 1: Prepare Your Files

1. **Update .env file** (don't upload, recreate on server):
```env
SECRET_KEY=<generate-new-key>
DEBUG=False
ALLOWED_HOSTS=yourusername.pythonanywhere.com
FORCE_HTTPS=True

# PythonAnywhere paths
PYTHONANYWHERE_SITE=yourusername.pythonanywhere.com
PYTHONANYWHERE_DOMAIN=yourusername.pythonanywhere.com
STATIC_ROOT=/home/yourusername/HealthProgressV15/staticfiles
MEDIA_ROOT=/home/yourusername/HealthProgressV15/media
LOG_DIR=/home/yourusername/logs

# Database (MySQL)
DB_NAME=yourusername$healthprogress
DB_USER=yourusername
DB_PASSWORD=<your-mysql-password>
DB_HOST=yourusername.mysql.pythonanywhere-services.com
DB_PORT=3306

# Email
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=<app-password>
```

### Step 2: Upload to PythonAnywhere

**Option A: Git (Recommended)**
```bash
# On your local machine
git add .
git commit -m "Prepare for deployment"
git push origin main

# On PythonAnywhere Bash console
cd ~
git clone https://github.com/yourusername/yourrepo.git HealthProgressV15
cd HealthProgressV15
```

**Option B: Upload Files**
- Use PythonAnywhere Files tab
- Upload project as ZIP and extract

### Step 3: Setup on PythonAnywhere

1. **Open Bash Console**

```bash
cd ~/HealthProgressV15

# Create virtual environment
mkvirtualenv --python=/usr/bin/python3.10 healthprogress

# Install dependencies (this may take time)
pip install -r requirements.txt

# Create directories
mkdir -p logs media/profiles

# Create .env file
nano .env
# Paste your production .env content and save (Ctrl+X, Y, Enter)
```

2. **Setup Database**

```bash
# Create MySQL database in PythonAnywhere Databases tab first
# Then run migrations
python manage.py makemigrations
python manage.py migrate
python manage.py createcachetable
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic --noinput
```

### Step 4: Configure Web App

1. Go to **Web** tab in PythonAnywhere
2. Click **Add a new web app**
3. Choose **Manual configuration**
4. Select **Python 3.10**

5. **Update WSGI configuration file**:

Click on WSGI configuration file and replace content with:

```python
import os
import sys

# Update with your username
path = '/home/yourusername/HealthProgressV15'
if path not in sys.path:
    sys.path.insert(0, path)

# Virtual environment
venv_path = '/home/yourusername/.virtualenvs/healthprogress/lib/python3.10/site-packages'
if venv_path not in sys.path:
    sys.path.insert(0, venv_path)

os.environ['PYTHONANYWHERE_SITE'] = 'yourusername.pythonanywhere.com'
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

6. **Configure Static Files**:

In Web tab, under **Static files** section:
- URL: `/static/`
- Directory: `/home/yourusername/HealthProgressV15/staticfiles`

Add another:
- URL: `/media/`
- Directory: `/home/yourusername/HealthProgressV15/media`

7. **Set Virtual Environment**:
- Virtualenv path: `/home/yourusername/.virtualenvs/healthprogress`

8. **Click Reload** button

### Step 5: Test Deployment

Visit: `https://yourusername.pythonanywhere.com`

---

## 🔧 Troubleshooting

### Localhost Issues

**Segmentation Fault**:
```bash
# Try with start script
python start.py

# Or reinstall problematic libraries
pip uninstall tensorflow keras -y
pip install tensorflow keras --no-cache-dir
```

**Port Already in Use**:
```bash
# Use different port
python manage.py runserver 8080
```

**Database Locked**:
```bash
# Close all connections and restart
python manage.py migrate --run-syncdb
```

### PythonAnywhere Issues

**ImportError**:
```bash
# Reinstall in virtual environment
workon healthprogress
pip install -r requirements.txt --force-reinstall
```

**Static Files Not Loading**:
```bash
python manage.py collectstatic --noinput --clear
# Check Static Files configuration in Web tab
```

**Database Error**:
```bash
# Check MySQL credentials in .env
# Verify database exists in Databases tab
python manage.py dbshell  # Test connection
```

**500 Error**:
```bash
# Check error log
tail -f ~/logs/django.log
tail -f ~/logs/security.log

# Check PythonAnywhere error log in Web tab
```

---

## 📋 Quick Commands

### Development
```bash
# Start server
python start.py

# Run migrations
python manage.py makemigrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Shell
python manage.py shell

# Check for issues
python manage.py check --deploy
```

### Production (PythonAnywhere)
```bash
# Reload app (after code changes)
touch /var/www/yourusername_pythonanywhere_com_wsgi.py

# Or use Web tab Reload button

# View logs
tail -f ~/logs/django.log
tail -f ~/HealthProgressV15/logs/security.log

# Database backup
python manage.py dumpdata > backup.json

# Database restore
python manage.py loaddata backup.json
```

---

## ✅ Post-Deployment Checklist

- [ ] DEBUG=False in production
- [ ] SECRET_KEY is unique and secure
- [ ] ALLOWED_HOSTS configured correctly
- [ ] HTTPS enabled (FORCE_HTTPS=True)
- [ ] Database backed up
- [ ] Static files collected
- [ ] Media directory writable
- [ ] Logs directory created
- [ ] Admin user created
- [ ] Email configured and tested
- [ ] Security headers enabled
- [ ] Cache table created
- [ ] All migrations applied

---

## 📞 Support

- Check logs in `logs/` directory
- Review Django error pages (if DEBUG=True)
- Check PythonAnywhere error log
- Test with: `python manage.py check --deploy`
