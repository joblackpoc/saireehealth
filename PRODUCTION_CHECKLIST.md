# PythonAnywhere Production Deployment Checklist

## ✅ Pre-Deployment Tasks

### 1. Code Preparation
- [ ] Update all placeholder paths in `settings.py` with your actual PythonAnywhere username
- [ ] Verify `requirements.txt` includes `mysqlclient==2.2.6`
- [ ] Create `.env` file from `.env.production` template
- [ ] Test application locally with `DEBUG=False`
- [ ] Run `python manage.py check --deploy` locally

### 2. Environment Variables Setup
- [ ] Set `SECRET_KEY` (generate new one for production)
- [ ] Set `DEBUG=False`
- [ ] Configure `ALLOWED_HOSTS` with your domain
- [ ] Set database credentials (MySQL)
- [ ] Configure email settings

### 3. Security Review
- [ ] Verify no sensitive data in git repository
- [ ] Check `.gitignore` covers all sensitive files
- [ ] Ensure strong passwords for all accounts
- [ ] Review security middleware configuration

## 🚀 Deployment Steps

### 1. PythonAnywhere Setup
- [ ] Create PythonAnywhere account
- [ ] Create MySQL database: `yourusername$healthprogress`
- [ ] Upload code via Git or file upload
- [ ] Create virtual environment

### 2. Application Configuration
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Copy and configure `.env` file
- [ ] Run migrations: `python manage.py migrate`
- [ ] Create cache table: `python manage.py createcachetable`
- [ ] Collect static files: `python manage.py collectstatic`
- [ ] Create superuser: `python manage.py createsuperuser`

### 3. Web App Configuration
- [ ] Configure source code path
- [ ] Set working directory
- [ ] Configure virtual environment path
- [ ] Update WSGI configuration
- [ ] Set up static files mapping (`/static/` and `/media/`)
- [ ] Enable HTTPS

### 4. Testing
- [ ] Run production setup script: `python setup_production.py`
- [ ] Test website accessibility
- [ ] Test user registration/login
- [ ] Test admin panel access
- [ ] Verify static files loading
- [ ] Test file uploads
- [ ] Check responsive design

## 🔧 Post-Deployment Tasks

### 1. Monitoring Setup
- [ ] Check error logs: `/var/log/yourusername.pythonanywhere.com.error.log`
- [ ] Monitor server logs: `/var/log/yourusername.pythonanywhere.com.server.log`
- [ ] Set up log rotation
- [ ] Configure email notifications for critical errors

### 2. Performance Optimization
- [ ] Monitor CPU and memory usage
- [ ] Optimize database queries
- [ ] Review and optimize static file serving
- [ ] Consider upgrading to paid plan for better performance

### 3. Security Hardening
- [ ] Review security headers
- [ ] Monitor security logs: `/home/yourusername/logs/security.log`
- [ ] Set up regular security audits
- [ ] Keep dependencies updated

### 4. Backup Strategy
- [ ] Set up database backup routine
- [ ] Backup media files
- [ ] Document recovery procedures
- [ ] Test backup restoration

## 📋 Maintenance Checklist

### Weekly Tasks
- [ ] Check error logs for issues
- [ ] Monitor disk usage
- [ ] Review security alerts
- [ ] Check application performance

### Monthly Tasks
- [ ] Update dependencies (security patches)
- [ ] Database maintenance and optimization
- [ ] Review and rotate logs
- [ ] Backup verification

### Quarterly Tasks
- [ ] Security audit and penetration testing
- [ ] Performance review and optimization
- [ ] Dependency security review
- [ ] Disaster recovery testing

## 🆘 Troubleshooting

### Common Issues:
1. **Static files not loading**
   - Check `collectstatic` was run
   - Verify static files mapping in Web tab
   - Check file permissions

2. **Database connection errors**
   - Verify MySQL database exists
   - Check credentials in `.env`
   - Test database connection

3. **500 Internal Server Error**
   - Check error logs
   - Verify WSGI configuration
   - Check virtual environment path

4. **CSRF errors**
   - Verify `CSRF_TRUSTED_ORIGINS` in settings
   - Check domain configuration

### Emergency Contacts:
- PythonAnywhere Support: help@pythonanywhere.com
- Django Documentation: https://docs.djangoproject.com/
- Security Issues: Immediate rollback and investigation

## 📞 Support Resources

- **PythonAnywhere Help**: https://help.pythonanywhere.com/
- **Django Deployment**: https://docs.djangoproject.com/en/stable/howto/deployment/
- **Security Guide**: https://docs.djangoproject.com/en/stable/topics/security/

---

**⚠️ Important Notes:**
- Always test changes in a staging environment first
- Keep regular backups of database and media files
- Monitor logs regularly for security issues
- Keep Django and dependencies updated for security patches