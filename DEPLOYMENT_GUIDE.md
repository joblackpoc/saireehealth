# PythonAnywhere Deployment Guide for HealthProgress

## Pre-deployment Checklist

### 1. Update requirements.txt
Add MySQL support for PythonAnywhere:
```bash
pip install mysqlclient
pip freeze > requirements.txt
```

### 2. Update settings.py paths
Replace placeholders in settings.py with your actual PythonAnywhere username:
- `/home/yourusername/` → `/home/actualusername/`
- `yourusername.mysql.pythonanywhere-services.com` → `actualusername.mysql.pythonanywhere-services.com`

## Deployment Steps

### 1. Upload Code to PythonAnywhere
```bash
# From your local machine, create a zip of your project
# Upload via Files tab or git clone in PythonAnywhere console

git clone https://github.com/yourusername/healthprogress.git
```

### 2. Create Virtual Environment
```bash
# In PythonAnywhere console
mkvirtualenv --python=/usr/bin/python3.10 healthprogress
workon healthprogress
```

### 3. Install Dependencies
```bash
cd /home/yourusername/healthprogress
pip install -r requirements.txt
```

### 4. Configure Database
```bash
# Create MySQL database in PythonAnywhere dashboard
# Database name: yourusername$healthprogress
# Update .env file with database credentials
```

### 5. Environment Variables
```bash
# Copy .env.production to .env and update values
cp .env.production .env
nano .env  # Update with your actual values
```

### 6. Run Migrations
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py collectstatic --noinput
```

### 7. Create Cache Table
```bash
python manage.py createcachetable
```

### 8. Create Superuser
```bash
python manage.py createsuperuser
```

### 9. Configure Web App
In PythonAnywhere Web tab:
- Source code: `/home/yourusername/healthprogress`
- Working directory: `/home/yourusername/healthprogress`
- Virtualenv: `/home/yourusername/.virtualenvs/healthprogress`

### 10. WSGI Configuration
Edit `/var/www/yourusername_pythonanywhere_com_wsgi.py`:
```python
import os
import sys

# Add your project directory to Python path
path = '/home/yourusername/healthprogress'
if path not in sys.path:
    sys.path.append(path)

# Set Django settings module
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

### 11. Static Files Configuration
In PythonAnywhere Web tab, add static files mapping:
- URL: `/static/`
- Directory: `/home/yourusername/healthprogress/staticfiles/`

- URL: `/media/`
- Directory: `/home/yourusername/healthprogress/media/`

### 12. Security Check
```bash
python manage.py check --deploy
```

## Post-Deployment

### 1. Test Application
- Visit your domain to verify deployment
- Test login/logout functionality
- Check admin panel access
- Verify static files loading

### 2. Monitor Logs
```bash
# Check error logs
tail -f /var/log/yourusername.pythonanywhere.com.error.log

# Check server logs  
tail -f /var/log/yourusername.pythonanywhere.com.server.log
```

### 3. Regular Maintenance
- Monitor disk usage (PythonAnywhere has limits)
- Rotate logs periodically
- Keep dependencies updated
- Regular database backups

## Troubleshooting

### Common Issues:

1. **Static files not loading**
   - Run `python manage.py collectstatic`
   - Check static files mapping in Web tab

2. **Database connection errors**
   - Verify MySQL database exists
   - Check credentials in .env file

3. **Import errors**
   - Ensure virtual environment is activated
   - Check all dependencies installed

4. **Permission errors**
   - Check file permissions: `chmod 755 manage.py`
   - Ensure proper directory structure

### Environment Variables Verification:
```bash
python manage.py shell
>>> from django.conf import settings
>>> print(settings.DEBUG)  # Should be False
>>> print(settings.ALLOWED_HOSTS)  # Should include your domain
>>> print(settings.DATABASES['default']['ENGINE'])  # Should be mysql
```

## Security Notes

1. **Never commit .env file** - add to .gitignore
2. **Use strong SECRET_KEY** - generate with Django command
3. **Enable HTTPS** - use PythonAnywhere's free SSL
4. **Regular security updates** - keep Django and dependencies updated
5. **Monitor security logs** - check `/home/yourusername/logs/security.log`

## Performance Optimization

1. **Database optimization**
   - Use database connection pooling
   - Regular database maintenance

2. **Static files**
   - WhiteNoise compression enabled
   - Use CDN for better performance (optional)

3. **Caching**
   - Database cache configured
   - Consider Redis upgrade for better performance

## Backup Strategy

1. **Database backups**
   ```bash
   mysqldump -u yourusername -p yourusername$healthprogress > backup.sql
   ```

2. **Media files backup**
   - Regular backup of media directory
   - Consider external storage for large files

3. **Code backup**
   - Use git for version control
   - Regular pushes to remote repository