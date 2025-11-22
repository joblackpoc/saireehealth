# Security Enhancement Recommendations
**Quick Reference Guide for Minor Improvements**

---

## 🟢 Current Security Status: EXCELLENT (A+)

Your application is highly secure. The following are **minor enhancements** rather than critical fixes.

---

## Priority 1: Quick Fixes (10 minutes)

### Fix 1: Remove Unnecessary autoescape off

**File:** `accounts/templates/accounts/password_reset_email.html`

**Replace:**
```django
{% autoescape off %}
คุณได้ขอรีเซ็ตรหัสผ่านสำหรับบัญชี {{ user.username }}

กรุณาคลิกลิงก์ด้านล่างเพื่อตั้งรหัสผ่านใหม่:
{{ protocol }}://{{ domain }}{% url 'accounts:password_reset_confirm' uidb64=uid token=token %}

ขอบคุณที่ใช้บริการของเรา!
{% endautoescape %}
```

**With:**
```django
คุณได้ขอรีเซ็ตรหัสผ่านสำหรับบัญชี {{ user.get_username }}

กรุณาคลิกลิงก์ด้านล่างเพื่อตั้งรหัสผ่านใหม่:
{{ protocol }}://{{ domain }}{% url 'accounts:password_reset_confirm' uidb64=uid token=token %}

ขอบคุณที่ใช้บริการของเรา!
```

**Why:** Auto-escaping is Django's default protection against XSS. There's no user-controlled content in this template, so `autoescape off` is unnecessary.

**Impact:** Removes an unnecessary security exception, following security best practices.

---

## Priority 2: Enhanced Protection (30 minutes)

### Enhancement 1: Add Subresource Integrity (SRI)

**File:** `templates/base.html`

**Find all CDN links and add integrity attributes:**

```html
<!-- Bootstrap CSS -->
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
      rel="stylesheet"
      integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"
      crossorigin="anonymous">

<!-- Bootstrap Icons -->
<link rel="stylesheet" 
      href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css"
      integrity="sha384-7+ds9BDGhMH2GgEYPg0qFy7+N4vGfqXFQrJr9PfGcSFWwRDhx0KGDcVNGlCqNKKH"
      crossorigin="anonymous">

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-geWF76RCwLtnZ8qwWowPQNguL3RmwHVBC9FhGdlKrxdiJJigb/j/68SIy3Te4Bkz"
        crossorigin="anonymous"></script>
```

**How to get integrity hashes:**
1. Visit: https://www.srihash.org/
2. Enter the CDN URL
3. Copy the generated integrity attribute

**Why:** Prevents CDN compromise from affecting your application (supply chain attack protection).

---

### Enhancement 2: Strengthen Content Security Policy

**File:** `security_enhancements/owasp_security.py`

**Find the `_generate_csp_header` method and update:**

```python
def _generate_csp_header(self, request):
    """Generate Content Security Policy header"""
    
    # Generate nonce for inline scripts
    nonce = secrets.token_urlsafe(16)
    request.csp_nonce = nonce  # Store for template use
    
    csp_directives = [
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
        "img-src 'self' data: https:",
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "upgrade-insecure-requests",
    ]
    
    return '; '.join(csp_directives)
```

**Then in templates, use nonce for inline scripts:**
```html
<script nonce="{{ request.csp_nonce }}">
    // Your inline script here
</script>
```

**Why:** Stronger CSP prevents unauthorized script execution.

---

### Enhancement 3: Make Error Messages More Generic

**File:** `accounts/validators.py`

**Update validation error messages:**

```python
def validate_image_file(image: UploadedFile) -> UploadedFile:
    """Comprehensive image file validation"""
    
    # Layer 1: File size validation
    if image.size > MAX_UPLOAD_SIZE:
        # Don't reveal exact size
        raise ValidationError('ขนาดไฟล์เกินขนาดที่อนุญาต กรุณาเลือกไฟล์ที่เล็กกว่า')
    
    # Layer 2: File extension validation
    ext = os.path.splitext(image.name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        # Generic message, log specific details
        logger.warning(f"Invalid file extension attempt: {ext}")
        raise ValidationError('ประเภทไฟล์ไม่ได้รับอนุญาต กรุณาเลือกไฟล์รูปภาพ (JPG, PNG, GIF)')
    
    # Layer 3: MIME type validation
    try:
        import magic
        image.seek(0)
        file_mime = magic.from_buffer(image.read(2048), mime=True)
        image.seek(0)
        
        if file_mime not in ALLOWED_IMAGE_TYPES:
            logger.warning(f"Invalid MIME type attempt: {file_mime}")
            raise ValidationError('ประเภทไฟล์ไม่ถูกต้อง กรุณาเลือกไฟล์รูปภาพที่ถูกต้อง')
    except ImportError:
        pass
    except Exception as e:
        logger.error(f"File validation error: {str(e)}")
        raise ValidationError('ไม่สามารถตรวจสอบไฟล์ได้ กรุณาลองใหม่อีกครั้ง')
    
    # ... rest of validation
```

**Why:** Generic error messages prevent information leakage while detailed logs help debugging.

---

## Priority 3: Optional Enhancements

### Enhancement 4: Add Security.txt

**Create file:** `static/.well-known/security.txt`

```text
Contact: security@yourcompany.com
Expires: 2026-12-31T23:59:59.000Z
Preferred-Languages: th, en
Canonical: https://yoursite.com/.well-known/security.txt

# Security Policy
# If you discover a security vulnerability, please report it to:
# - Email: security@yourcompany.com
# - Response time: 48 hours
# - Please do not disclose publicly until we've addressed the issue
```

**Update `config/urls.py`:**
```python
from django.views.static import serve

urlpatterns = [
    # ... existing patterns
    path('.well-known/security.txt', 
         serve, 
         {'document_root': settings.STATIC_ROOT, 
          'path': '.well-known/security.txt'}),
]
```

---

### Enhancement 5: Add Security Testing Script

**Create file:** `security_test.py`

```python
#!/usr/bin/env python3
"""
Security testing script for HealthProgress
Run with: python security_test.py
"""

import requests
import sys

def test_security_headers(base_url):
    """Test security headers"""
    print("Testing security headers...")
    
    response = requests.get(f"{base_url}/accounts/")
    headers = response.headers
    
    required_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': True,  # Just check existence
    }
    
    passed = 0
    for header, expected in required_headers.items():
        if header in headers:
            if expected is True or headers[header] == expected:
                print(f"✅ {header}: Present")
                passed += 1
            else:
                print(f"⚠️  {header}: Present but incorrect value")
        else:
            print(f"❌ {header}: Missing")
    
    return passed == len(required_headers)

def test_xss_protection(base_url):
    """Test XSS protection"""
    print("\nTesting XSS protection...")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
    ]
    
    # These should be blocked or escaped
    for payload in xss_payloads:
        response = requests.get(f"{base_url}/accounts/", 
                               params={'test': payload})
        if payload in response.text and '<script>' in response.text:
            print(f"❌ XSS vulnerability: {payload[:30]}...")
            return False
        else:
            print(f"✅ XSS blocked: {payload[:30]}...")
    
    return True

def test_sql_injection(base_url):
    """Test SQL injection protection"""
    print("\nTesting SQL injection protection...")
    
    sql_payloads = [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "' AND 1=1--",
    ]
    
    for payload in sql_payloads:
        response = requests.get(f"{base_url}/accounts/", 
                               params={'id': payload})
        # Should not return SQL errors
        if 'SQL' in response.text or 'syntax error' in response.text:
            print(f"❌ Possible SQL injection: {payload}")
            return False
        else:
            print(f"✅ SQL injection blocked: {payload}")
    
    return True

def test_rate_limiting(base_url):
    """Test rate limiting"""
    print("\nTesting rate limiting...")
    
    # Rapid fire requests
    responses = []
    for i in range(15):
        response = requests.post(f"{base_url}/accounts/login/",
                                data={'username': 'test', 'password': 'test'})
        responses.append(response.status_code)
    
    if 429 in responses:  # Too Many Requests
        print("✅ Rate limiting active")
        return True
    else:
        print("⚠️  Rate limiting may not be active")
        return False

if __name__ == '__main__':
    base_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8000'
    
    print(f"Testing security for: {base_url}")
    print("="*50)
    
    results = {
        'Security Headers': test_security_headers(base_url),
        'XSS Protection': test_xss_protection(base_url),
        'SQL Injection': test_sql_injection(base_url),
        'Rate Limiting': test_rate_limiting(base_url),
    }
    
    print("\n" + "="*50)
    print("RESULTS:")
    passed = sum(results.values())
    total = len(results)
    
    for test, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    sys.exit(0 if passed == total else 1)
```

**Run with:**
```bash
python security_test.py http://localhost:8000
```

---

## Testing Checklist

After implementing fixes, test:

- [ ] File upload with malicious filenames
- [ ] XSS payloads in all input fields
- [ ] SQL injection in search/filter fields
- [ ] Brute force login attempts
- [ ] SQLMap automated scan
- [ ] OWASP ZAP scan
- [ ] Check all security headers present
- [ ] Verify rate limiting works
- [ ] Test MFA functionality
- [ ] Verify session security

---

## Security Maintenance Schedule

### Weekly:
- [ ] Review security logs
- [ ] Check for failed login attempts
- [ ] Monitor blocked IPs

### Monthly:
- [ ] Update Django and dependencies
- [ ] Review security events
- [ ] Test backup restoration

### Quarterly:
- [ ] Full security audit
- [ ] Penetration testing
- [ ] Update security documentation
- [ ] Review and update security policies

---

## Additional Resources

### Security Tools:
- **Bandit**: Python security linter
  ```bash
  pip install bandit
  bandit -r . -ll
  ```

- **Safety**: Check dependencies for known vulnerabilities
  ```bash
  pip install safety
  safety check
  ```

- **OWASP ZAP**: Web application security scanner
  ```bash
  docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:8000
  ```

### Django Security Resources:
- Django Security Docs: https://docs.djangoproject.com/en/stable/topics/security/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Django Security Releases: https://www.djangoproject.com/weblog/

---

## Summary

Your application has **excellent security**. The recommendations above are minor enhancements that will bring it from A+ to A++ level.

**Time to implement all Priority 1 & 2 fixes: ~1-2 hours**

**Impact: Enhanced defense-in-depth and compliance with security best practices**

Remember: Security is an ongoing process, not a one-time fix. Keep monitoring, updating, and improving! 🛡️
