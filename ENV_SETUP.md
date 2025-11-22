# Environment Configuration Setup Guide

## Quick Start

### 1. Copy the Example Environment File

```bash
cp .env.example .env
```

### 2. Generate a New SECRET_KEY

Run this command to generate a secure secret key:

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Copy the output and paste it as the value for `SECRET_KEY` in your `.env` file.

### 3. Basic Development Configuration

For local development, the `.env` file has been pre-configured with:

```env
SECRET_KEY=<generated-key>
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,[::1]
DATABASE_URL=
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
FORCE_HTTPS=False
```

### 4. Initialize the Database

```bash
# Create cache table (required)
python manage.py createcachetable

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

### 5. Create Logs Directory

```bash
mkdir logs
```

### 6. Run the Development Server

```bash
python manage.py runserver
```

Visit: http://localhost:8000

---

## Production Configuration

### Required Steps for Production

1. **Set DEBUG to False**
   ```env
   DEBUG=False
   ```

2. **Generate a Strong SECRET_KEY**
   - Must be at least 50 characters
   - Use the generator command above
   - Never reuse development keys

3. **Configure ALLOWED_HOSTS**
   ```env
   ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,your-server-ip
   ```

4. **Enable HTTPS**
   ```env
   FORCE_HTTPS=True
   ```

5. **Configure Database** (if not using SQLite)
   
   **Option A: Using DATABASE_URL**
   ```env
   DATABASE_URL=postgresql://user:password@host:port/dbname
   ```
   
   **Option B: Individual settings**
   ```env
   DB_NAME=healthprogress
   DB_USER=your_username
   DB_PASSWORD=your_secure_password
   DB_HOST=localhost
   DB_PORT=5432
   ```

6. **Configure Email Settings**
   ```env
   EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USE_TLS=True
   EMAIL_HOST_USER=your-email@gmail.com
   EMAIL_HOST_PASSWORD=your-app-password
   DEFAULT_FROM_EMAIL=noreply@yourdomain.com
   ```

7. **Set Admin Email**
   ```env
   ADMIN_EMAIL=admin@yourdomain.com
   ```

8. **Update Static and Media Paths** (in settings.py)
   ```python
   STATIC_ROOT = '/path/to/static'
   MEDIA_ROOT = '/path/to/media'
   ```

---

## PythonAnywhere Deployment

### Configuration for PythonAnywhere

```env
DEBUG=False
SECRET_KEY=<your-long-random-secret-key>
ALLOWED_HOSTS=yourusername.pythonanywhere.com
FORCE_HTTPS=True

# MySQL Database
DB_NAME=yourusername$healthprogress
DB_USER=yourusername
DB_PASSWORD=your_mysql_password
DB_HOST=yourusername.mysql.pythonanywhere-services.com
DB_PORT=3306

# Email (Gmail example)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-specific-password
DEFAULT_FROM_EMAIL=noreply@healthprogress.com

ADMIN_EMAIL=admin@yourdomain.com
```

### Update settings.py for PythonAnywhere

In `config/settings.py`, update these paths:

```python
# Line 187-188
STATIC_ROOT = '/home/yourusername/yourdomain.com/static'
MEDIA_ROOT = '/home/yourusername/yourdomain.com/media'

# Line 369-370
log_dir = Path('/home/yourusername/logs')
os.makedirs('/home/yourusername/logs', exist_ok=True)
```

### Deployment Commands

```bash
# Collect static files
python manage.py collectstatic --noinput

# Create cache table
python manage.py createcachetable

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

---

## Environment Variables Reference

### Core Settings
- `SECRET_KEY` - Django secret key (50+ chars required)
- `DEBUG` - Debug mode (True/False)
- `ALLOWED_HOSTS` - Comma-separated list of allowed hosts
- `FORCE_HTTPS` - Force HTTPS redirect (True/False)

### Database
- `DATABASE_URL` - Full database URL
- `DB_NAME` - Database name
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `DB_HOST` - Database host
- `DB_PORT` - Database port

### Email
- `EMAIL_BACKEND` - Email backend class
- `EMAIL_HOST` - SMTP host
- `EMAIL_PORT` - SMTP port
- `EMAIL_USE_TLS` - Use TLS (True/False)
- `EMAIL_HOST_USER` - Email username
- `EMAIL_HOST_PASSWORD` - Email password
- `DEFAULT_FROM_EMAIL` - Default from email
- `ADMIN_EMAIL` - Admin notification email

### Security
- `MAX_LOGIN_ATTEMPTS` - Maximum login attempts
- `ACCOUNT_LOCKOUT_TIME` - Account lockout duration (seconds)
- `MFA_MAX_ATTEMPTS` - Maximum MFA attempts
- `MAX_UPLOAD_SIZE` - Maximum file upload size (bytes)

---

## Troubleshooting

### Error: SECRET_KEY not found
- Ensure `.env` file exists in project root
- Check that `SECRET_KEY=` line has a value
- Verify no extra spaces or quotes

### Error: Database connection failed
- Verify database credentials in `.env`
- Ensure database server is running
- Check network connectivity to database host

### Error: Email sending failed
- Verify SMTP credentials
- For Gmail, use App Password (not regular password)
- Check firewall/security settings

### Error: Static files not loading
- Run `python manage.py collectstatic`
- Check `STATIC_ROOT` path exists
- Verify web server configuration

---

## Security Best Practices

1. **Never commit `.env` to version control**
   - Already in `.gitignore`
   - Use `.env.example` for reference

2. **Use strong SECRET_KEY**
   - Minimum 50 characters
   - Random and unpredictable
   - Rotate periodically

3. **Rotate credentials regularly**
   - Database passwords
   - Email passwords
   - API keys

4. **Use environment-specific files**
   - `.env.development`
   - `.env.staging`
   - `.env.production`

5. **Restrict file permissions**
   ```bash
   chmod 600 .env
   ```

6. **Enable all security features in production**
   - `DEBUG=False`
   - `FORCE_HTTPS=True`
   - Enable all middleware
   - Configure CSP headers

---

## Support

For issues or questions:
1. Check `.env.example` for all available options
2. Review `config/settings.py` for configuration details
3. See `DEPLOYMENT_GUIDE.md` for deployment instructions
4. See `SECURITY_IMPLEMENTATION.md` for security features

---

**Last Updated:** November 21, 2025
