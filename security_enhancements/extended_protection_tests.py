"""
Extended Security Protection Tests
Comprehensive test suite for additional attack vector protections
"""

import os
import time
import tempfile
from io import BytesIO
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase, RequestFactory, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile, InMemoryUploadedFile
from django.core.cache import cache
from django.contrib.auth.models import User
from django.http import HttpRequest
from django.core.exceptions import SuspiciousOperation

from .extended_attack_protection import (
    SQLMapProtection,
    BruteForceProtection, 
    FileUploadProtection,
    ORMInjectionProtection,
    TemplateInjectionProtection,
    ExtendedSecurityMiddleware
)

class TestExtendedAttackProtection(TestCase):
    """Test extended attack protection mechanisms"""
    
    def setUp(self):
        """Set up test environment"""
        self.factory = RequestFactory()
        self.middleware = ExtendedSecurityMiddleware(get_response=Mock())
        cache.clear()
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def tearDown(self):
        """Clean up after tests"""
        cache.clear()
    
    def test_sqlmap_user_agent_detection(self):
        """Test SQLMap user agent detection"""
        # Test SQLMap user agent signatures
        sqlmap_agents = [
            'sqlmap/1.4.7#stable (http://sqlmap.org)',
            'sqlmap/1.5.2#dev',
            'Mozilla/5.0 (compatible; sqlmap/1.4.7)',
        ]
        
        for agent in sqlmap_agents:
            request = self.factory.get('/', HTTP_USER_AGENT=agent)
            is_attack, details = SQLMapProtection.detect_sqlmap_attack(request)
            self.assertTrue(is_attack, f"Should detect SQLMap user agent: {agent}")
            self.assertIn("SQLMap User-Agent detected", details)
    
    def test_sqlmap_payload_detection(self):
        """Test SQLMap payload detection"""
        # Test various SQLMap payloads
        sqlmap_payloads = [
            "id=1' UNION ALL SELECT NULL,NULL,NULL--",
            "id=1 AND 1=1-- ",
            "id=1' OR '1'='1",
            "id=1'; WAITFOR DELAY '00:00:05'--",
            "id=1 AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
            "id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
            "id=1%27%20UNION%20ALL%20SELECT%20NULL--",
        ]
        
        for payload in sqlmap_payloads:
            request = self.factory.get(f'/?{payload}')
            is_attack, details = SQLMapProtection.detect_sqlmap_attack(request)
            self.assertTrue(is_attack, f"Should detect SQLMap payload: {payload}")
    
    def test_sqlmap_evasion_detection(self):
        """Test SQLMap evasion technique detection"""
        evasion_payloads = [
            "id=1/*comment*/UNION/*comment*/SELECT/*comment*/NULL",
            "id=1%20UNION%20SELECT%20NULL",
            "id=REVERSE('TCELES')",
            "id=1%2f*comment*%2fUNION%2f*comment*%2fSELECT",
        ]
        
        for payload in evasion_payloads:
            request = self.factory.get(f'/?{payload}')
            is_attack, details = SQLMapProtection.detect_sqlmap_attack(request)
            self.assertTrue(is_attack, f"Should detect SQLMap evasion: {payload}")
    
    def test_brute_force_rate_limiting(self):
        """Test brute force rate limiting detection"""
        client_ip = '192.168.1.100'
        
        # Simulate rapid login attempts
        for i in range(12):  # Exceed threshold of 10
            request = self.factory.post('/login/', 
                                      {'username': 'admin', 'password': f'pass{i}'},
                                      REMOTE_ADDR=client_ip)
            
            is_attack, attack_type, details = BruteForceProtection.detect_brute_force(request, 'login')
            
            if i >= 10:  # Should trigger after 10 attempts
                self.assertTrue(is_attack)
                self.assertEqual(attack_type, 'rapid_requests')
    
    def test_brute_force_user_enumeration(self):
        """Test user enumeration detection"""
        client_ip = '192.168.1.101'
        
        # Try many different usernames
        usernames = [f'user{i}' for i in range(15)]
        
        for username in usernames:
            request = self.factory.post('/login/', 
                                      {'username': username, 'password': 'password'},
                                      REMOTE_ADDR=client_ip)
            
            is_attack, attack_type, details = BruteForceProtection.detect_brute_force(request, 'login')
        
        # Last request should trigger user enumeration detection
        self.assertTrue(is_attack)
        self.assertEqual(attack_type, 'user_enumeration')
    
    def test_brute_force_password_spraying(self):
        """Test password spraying detection"""
        client_ip = '192.168.1.102'
        
        # Use same password multiple times
        for i in range(25):  # Exceed threshold of 20
            request = self.factory.post('/login/', 
                                      {'username': f'user{i}', 'password': 'password123'},
                                      REMOTE_ADDR=client_ip)
            
            is_attack, attack_type, details = BruteForceProtection.detect_brute_force(request, 'login')
        
        # Should detect password spraying
        self.assertTrue(is_attack)
        self.assertEqual(attack_type, 'password_spraying')
    
    def test_brute_force_credential_stuffing(self):
        """Test credential stuffing detection"""
        client_ip = '192.168.1.103'
        
        # Try many different credential combinations
        for i in range(55):  # Exceed threshold of 50
            request = self.factory.post('/login/', 
                                      {'username': f'user{i}', 'password': f'pass{i}'},
                                      REMOTE_ADDR=client_ip)
            
            is_attack, attack_type, details = BruteForceProtection.detect_brute_force(request, 'login')
        
        # Should detect credential stuffing
        self.assertTrue(is_attack)
        self.assertEqual(attack_type, 'credential_stuffing')
    
    def test_file_upload_dangerous_extensions(self):
        """Test dangerous file extension detection"""
        dangerous_files = [
            ('malicious.php', b'<?php system($_GET["cmd"]); ?>', 'text/plain'),
            ('exploit.jsp', b'<%@ page import="java.io.*" %>', 'text/plain'),
            ('backdoor.asp', b'<%eval request("cmd")%>', 'text/plain'),
            ('trojan.exe', b'MZ\x90\x00', 'application/octet-stream'),
            ('script.js', b'eval(atob("malicious"));', 'text/javascript'),
            ('shell.py', b'import os; os.system("rm -rf /")', 'text/plain'),
        ]
        
        for filename, content, content_type in dangerous_files:
            uploaded_file = SimpleUploadedFile(
                filename, content, content_type=content_type
            )
            
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            self.assertFalse(is_valid, f"Should reject dangerous file: {filename}")
            self.assertIn("Dangerous file extension", message)
    
    def test_file_upload_double_extensions(self):
        """Test double extension file detection"""
        double_ext_files = [
            'image.jpg.php',
            'document.pdf.jsp',
            'data.csv.asp',
            'backup.tar.exe',
        ]
        
        for filename in double_ext_files:
            uploaded_file = SimpleUploadedFile(
                filename, b'test content', content_type='text/plain'
            )
            
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            self.assertFalse(is_valid, f"Should reject double extension file: {filename}")
    
    def test_file_upload_mime_type_validation(self):
        """Test MIME type validation"""
        # Test invalid MIME types
        invalid_files = [
            ('test.txt', b'test', 'application/x-executable'),
            ('test.jpg', b'test', 'application/x-php'),
            ('test.pdf', b'test', 'text/x-script'),
        ]
        
        for filename, content, content_type in invalid_files:
            uploaded_file = SimpleUploadedFile(
                filename, content, content_type=content_type
            )
            
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            self.assertFalse(is_valid, f"Should reject invalid MIME type: {content_type}")
            self.assertIn("Invalid MIME type", message)
    
    def test_file_upload_malware_signatures(self):
        """Test malware signature detection"""
        malware_contents = [
            b'<?php eval($_POST["cmd"]); ?>',
            b'<script>eval(atob("payload"))</script>',
            b'#!/bin/bash\nrm -rf /',
            b'exec("malicious command")',
            b'system("rm -rf /")',
            b'<% eval request("backdoor") %>',
        ]
        
        for content in malware_contents:
            uploaded_file = SimpleUploadedFile(
                'test.txt', content, content_type='text/plain'
            )
            
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            self.assertFalse(is_valid, f"Should detect malware signature in: {content}")
            self.assertIn("malware detected", message)
    
    def test_file_upload_filename_validation(self):
        """Test filename validation"""
        invalid_filenames = [
            '../../../etc/passwd',
            'file\\with\\backslashes',
            'file\x00null.txt',
            'CON.txt',  # Windows reserved
            'PRN.jpg',  # Windows reserved
            'a' * 300,  # Too long
        ]
        
        for filename in invalid_filenames:
            uploaded_file = SimpleUploadedFile(
                filename, b'test content', content_type='text/plain'
            )
            
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            self.assertFalse(is_valid, f"Should reject invalid filename: {filename}")
    
    @override_settings(MAX_UPLOAD_SIZE=1024)  # 1KB limit
    def test_file_upload_size_validation(self):
        """Test file size validation"""
        # Create a file larger than the limit
        large_content = b'x' * 2048  # 2KB
        uploaded_file = SimpleUploadedFile(
            'large.txt', large_content, content_type='text/plain'
        )
        
        is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
        self.assertFalse(is_valid)
        self.assertIn("File size exceeds", message)
    
    def test_valid_file_uploads(self):
        """Test that valid files pass validation"""
        valid_files = [
            ('document.pdf', b'%PDF-1.4', 'application/pdf'),
            ('image.jpg', b'\xff\xd8\xff\xe0', 'image/jpeg'),
            ('text.txt', b'Hello world', 'text/plain'),
        ]
        
        for filename, content, content_type in valid_files:
            uploaded_file = SimpleUploadedFile(
                filename, content, content_type=content_type
            )
            
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            self.assertTrue(is_valid, f"Should accept valid file: {filename}")
    
    def test_orm_injection_field_names(self):
        """Test ORM injection in field names"""
        dangerous_queries = [
            {'user__name__raw("SELECT * FROM users")': 'test'},
            {'id__extra("malicious")': 1},
            {'field__regex': '; DROP TABLE users; --'},
            {'unsafe__lookup': 'value; DELETE FROM accounts'},
        ]
        
        for query in dangerous_queries:
            is_valid = ORMInjectionProtection.validate_orm_query(query)
            self.assertFalse(is_valid, f"Should reject dangerous ORM query: {query}")
    
    def test_orm_injection_field_values(self):
        """Test ORM injection in field values"""
        dangerous_values = [
            {'username': "'; DROP TABLE users; --"},
            {'id': "1 UNION SELECT * FROM passwords"},
            {'search': "test'; INSERT INTO admin VALUES('hacker','pass'); --"},
            {'filter': "value' OR '1'='1"},
        ]
        
        for query in dangerous_values:
            is_valid = ORMInjectionProtection.validate_orm_query(query)
            self.assertFalse(is_valid, f"Should reject dangerous ORM values: {query}")
    
    def test_valid_orm_queries(self):
        """Test that valid ORM queries pass validation"""
        valid_queries = [
            {'name__icontains': 'john'},
            {'age__gte': 18},
            {'created__date': '2024-01-01'},
            {'status__in': ['active', 'pending']},
            {'profile__user__email__endswith': '@example.com'},
        ]
        
        for query in valid_queries:
            is_valid = ORMInjectionProtection.validate_orm_query(query)
            self.assertTrue(is_valid, f"Should accept valid ORM query: {query}")
    
    def test_template_injection_detection(self):
        """Test template injection detection"""
        malicious_templates = [
            '{{ request.user.password }}',
            '{{ config.SECRET_KEY }}',
            '{{ self.__class__ }}',
            '{{ "".__class__.__mro__ }}',
            '{{ [].__class__.__base__.__subclasses__() }}',
            '{% load os %}{% os.system("rm -rf /") %}',
            '{{ range(1000) }}',
            '{{ cycler.__init__.__globals__ }}',
            '{{ lipsum.__globals__.os.system("evil") }}',
            '${java.lang.Runtime.getRuntime().exec("evil")}',
            '<% eval("malicious") %>',
            '{{ "".__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}',
        ]
        
        for template in malicious_templates:
            is_valid = TemplateInjectionProtection.validate_template_content(template)
            self.assertFalse(is_valid, f"Should detect template injection: {template}")
    
    def test_template_injection_sanitization(self):
        """Test template injection sanitization"""
        malicious_content = '{{ user.password }} and {% load os %} and normal text'
        sanitized = TemplateInjectionProtection.sanitize_template_input(malicious_content)
        
        # Should remove template constructs and escape HTML
        self.assertNotIn('{{', sanitized)
        self.assertNotIn('{%', sanitized)
        self.assertIn('normal text', sanitized)
    
    def test_safe_template_rendering(self):
        """Test safe template rendering"""
        # Valid template should render
        safe_template = "Hello {{ name }}!"
        context = {'name': '<script>alert("xss")</script>'}
        
        try:
            result = TemplateInjectionProtection.safe_template_render(safe_template, context)
            # Should escape HTML in context
            self.assertNotIn('<script>', result)
            self.assertIn('&lt;script&gt;', result)
        except ValueError:
            self.fail("Safe template should render successfully")
        
        # Malicious template should raise error
        malicious_template = "{{ request.user.password }}"
        with self.assertRaises(ValueError):
            TemplateInjectionProtection.safe_template_render(malicious_template, context)
    
    def test_middleware_sqlmap_detection(self):
        """Test middleware SQLMap detection"""
        request = self.factory.get('/', HTTP_USER_AGENT='sqlmap/1.4.7')
        
        with self.assertRaises(SuspiciousOperation) as cm:
            self.middleware.process_request(request)
        
        self.assertIn("SQLMap attack detected", str(cm.exception))
    
    def test_middleware_brute_force_detection(self):
        """Test middleware brute force detection"""
        client_ip = '192.168.1.200'
        
        # Make many rapid requests to trigger rate limiting
        for i in range(15):
            request = self.factory.post('/login/', 
                                      {'username': 'admin', 'password': f'pass{i}'},
                                      REMOTE_ADDR=client_ip)
            try:
                self.middleware.process_request(request)
            except SuspiciousOperation:
                # Expected on later requests
                self.assertGreaterEqual(i, 10, "Should trigger brute force detection")
                break
    
    def test_middleware_orm_injection_detection(self):
        """Test middleware ORM injection detection"""
        request = self.factory.get('/?field__raw=malicious')
        
        with self.assertRaises(SuspiciousOperation) as cm:
            self.middleware.process_request(request)
        
        self.assertIn("ORM injection attempt detected", str(cm.exception))
    
    def test_middleware_template_injection_detection(self):
        """Test middleware template injection detection"""
        request = self.factory.post('/', {'content': '{{ request.user.password }}'})
        
        with self.assertRaises(SuspiciousOperation) as cm:
            self.middleware.process_request(request)
        
        self.assertIn("Template injection attempt detected", str(cm.exception))
    
    def test_middleware_file_upload_validation(self):
        """Test middleware file upload validation"""
        # Create malicious file upload
        malicious_file = SimpleUploadedFile(
            'backdoor.php',
            b'<?php system($_GET["cmd"]); ?>',
            content_type='text/plain'
        )
        
        request = self.factory.post('/upload/', {'file': malicious_file})
        request.FILES = {'file': malicious_file}
        
        with self.assertRaises(SuspiciousOperation) as cm:
            self.middleware.process_view(request, Mock(), [], {})
        
        self.assertIn("File upload rejected", str(cm.exception))
    
    def test_middleware_skips_safe_paths(self):
        """Test that middleware skips security checks for safe paths"""
        safe_paths = [
            '/health/api/status/',
            '/static/css/style.css',
            '/media/images/logo.png',
            '/favicon.ico',
        ]
        
        for path in safe_paths:
            # Even with SQLMap user agent, should not trigger on safe paths
            request = self.factory.get(path, HTTP_USER_AGENT='sqlmap/1.4.7')
            
            # Should not raise exception
            result = self.middleware.process_request(request)
            self.assertIsNone(result)
    
    def test_comprehensive_attack_scenarios(self):
        """Test comprehensive attack scenarios"""
        
        # Scenario 1: Advanced SQLMap attack with evasion
        request = self.factory.get(
            '/?id=1%27%20UNION/*comment*/ALL/*comment*/SELECT/*comment*/NULL,NULL,database()--',
            HTTP_USER_AGENT='Mozilla/5.0 (compatible; sqlmap/1.4.7)'
        )
        
        with self.assertRaises(SuspiciousOperation):
            self.middleware.process_request(request)
        
        # Scenario 2: Coordinated brute force with file upload
        client_ip = '192.168.1.250'
        
        # First, trigger brute force detection
        for i in range(12):
            request = self.factory.post('/login/', 
                                      {'username': 'admin', 'password': f'pass{i}'},
                                      REMOTE_ADDR=client_ip)
            try:
                self.middleware.process_request(request)
            except SuspiciousOperation:
                break
        
        # Then try malicious file upload from same IP
        malicious_file = SimpleUploadedFile(
            'shell.jsp',
            b'<%@ page import="java.io.*" %><%=new java.util.Scanner(Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\A").next()%>',
            content_type='text/plain'
        )
        
        request = self.factory.post('/upload/', 
                                   {'file': malicious_file},
                                   REMOTE_ADDR=client_ip)
        request.FILES = {'file': malicious_file}
        
        with self.assertRaises(SuspiciousOperation):
            self.middleware.process_view(request, Mock(), [], {})
        
        # Scenario 3: Template injection with ORM manipulation
        request = self.factory.post('/', {
            'template': '{{ "".__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}',
            'filter__raw': 'SELECT * FROM django_session'
        })
        
        with self.assertRaises(SuspiciousOperation):
            self.middleware.process_request(request)