"""
Simple Extended Security Test Command
Test extended attack protections
"""

from django.core.management.base import BaseCommand
from django.test import RequestFactory
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation

class Command(BaseCommand):
    help = 'Test extended security protections'
    
    def handle(self, *args, **options):
        """Run extended security protection tests"""
        
        self.stdout.write(
            self.style.SUCCESS('🔒 Extended Security Protection Test Suite')
        )
        self.stdout.write('=' * 60)
        
        # Import protection classes
        try:
            from security_enhancements.extended_attack_protection import (
                SQLMapProtection,
                BruteForceProtection,
                FileUploadProtection,
                ORMInjectionProtection,
                TemplateInjectionProtection,
                ExtendedSecurityMiddleware
            )
        except ImportError as e:
            self.stdout.write(self.style.ERROR(f"Import error: {e}"))
            return
        
        factory = RequestFactory()
        cache.clear()
        
        # Track results
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        
        # Test SQLMap Protection
        self.stdout.write('\n📋 SQLMAP PROTECTION TESTS:')
        self.stdout.write('-' * 40)
        
        # Test 1: SQLMap User Agent Detection
        total_tests += 1
        try:
            request = factory.get('/', HTTP_USER_AGENT='sqlmap/1.4.7')
            is_attack, details = SQLMapProtection.detect_sqlmap_attack(request)
            if is_attack and "SQLMap User-Agent detected" in details:
                passed_tests += 1
                self.stdout.write("  ✅ SQLMap User Agent Detection")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ SQLMap User Agent Detection")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ SQLMap User Agent Detection: {e}")
        
        # Test 2: SQLMap Payload Detection
        total_tests += 1
        try:
            request = factory.get("/?id=1' UNION ALL SELECT NULL--")
            is_attack, details = SQLMapProtection.detect_sqlmap_attack(request)
            if is_attack:
                passed_tests += 1
                self.stdout.write("  ✅ SQLMap Payload Detection")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ SQLMap Payload Detection")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ SQLMap Payload Detection: {e}")
        
        # Test Brute Force Protection
        self.stdout.write('\n📋 BRUTE FORCE PROTECTION TESTS:')
        self.stdout.write('-' * 40)
        
        # Test 3: Rate Limiting
        total_tests += 1
        try:
            client_ip = '192.168.1.100'
            # Simulate rapid requests
            for i in range(12):
                request = factory.post('/login/', 
                                     {'username': 'admin', 'password': f'pass{i}'},
                                     REMOTE_ADDR=client_ip)
                is_attack, attack_type, details = BruteForceProtection.detect_brute_force(request, 'login')
                if i >= 10 and is_attack and attack_type == 'rapid_requests':
                    passed_tests += 1
                    self.stdout.write("  ✅ Brute Force Rate Limiting")
                    break
            else:
                failed_tests += 1
                self.stdout.write("  ❌ Brute Force Rate Limiting")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ Brute Force Rate Limiting: {e}")
        
        # Test File Upload Protection
        self.stdout.write('\n📋 FILE UPLOAD PROTECTION TESTS:')
        self.stdout.write('-' * 40)
        
        # Test 4: Dangerous File Extension
        total_tests += 1
        try:
            uploaded_file = SimpleUploadedFile(
                'malicious.php',
                b'<?php system($_GET["cmd"]); ?>',
                content_type='text/plain'
            )
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            if not is_valid and "Dangerous file extension" in message:
                passed_tests += 1
                self.stdout.write("  ✅ Dangerous File Extension Detection")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ Dangerous File Extension Detection")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ Dangerous File Extension Detection: {e}")
        
        # Test 5: Malware Signature Detection
        total_tests += 1
        try:
            uploaded_file = SimpleUploadedFile(
                'test.txt',
                b'<?php eval($_POST["cmd"]); ?>',
                content_type='text/plain'
            )
            is_valid, message = FileUploadProtection.validate_file_upload(uploaded_file)
            if not is_valid and "malware detected" in message:
                passed_tests += 1
                self.stdout.write("  ✅ Malware Signature Detection")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ Malware Signature Detection")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ Malware Signature Detection: {e}")
        
        # Test ORM Injection Protection
        self.stdout.write('\n📋 ORM INJECTION PROTECTION TESTS:')
        self.stdout.write('-' * 40)
        
        # Test 6: ORM Field Name Validation
        total_tests += 1
        try:
            dangerous_query = {'user__name__raw("SELECT * FROM users")': 'test'}
            is_valid = ORMInjectionProtection.validate_orm_query(dangerous_query)
            if not is_valid:
                passed_tests += 1
                self.stdout.write("  ✅ ORM Field Name Validation")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ ORM Field Name Validation")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ ORM Field Name Validation: {e}")
        
        # Test 7: ORM Field Value Validation
        total_tests += 1
        try:
            dangerous_query = {'username': "'; DROP TABLE users; --"}
            is_valid = ORMInjectionProtection.validate_orm_query(dangerous_query)
            if not is_valid:
                passed_tests += 1
                self.stdout.write("  ✅ ORM Field Value Validation")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ ORM Field Value Validation")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ ORM Field Value Validation: {e}")
        
        # Test Template Injection Protection
        self.stdout.write('\n📋 TEMPLATE INJECTION PROTECTION TESTS:')
        self.stdout.write('-' * 40)
        
        # Test 8: Template Injection Detection
        total_tests += 1
        try:
            malicious_template = '{{ request.user.password }}'
            is_valid = TemplateInjectionProtection.validate_template_content(malicious_template)
            if not is_valid:
                passed_tests += 1
                self.stdout.write("  ✅ Template Injection Detection")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ Template Injection Detection")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ Template Injection Detection: {e}")
        
        # Test 9: Template Sanitization
        total_tests += 1
        try:
            malicious_content = '{{ user.password }} and normal text'
            sanitized = TemplateInjectionProtection.sanitize_template_input(malicious_content)
            if '{{' not in sanitized and 'normal text' in sanitized:
                passed_tests += 1
                self.stdout.write("  ✅ Template Sanitization")
            else:
                failed_tests += 1
                self.stdout.write("  ❌ Template Sanitization")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ Template Sanitization: {e}")
        
        # Test Middleware Integration
        self.stdout.write('\n📋 MIDDLEWARE INTEGRATION TESTS:')
        self.stdout.write('-' * 40)
        
        # Test 10: Middleware SQLMap Detection
        total_tests += 1
        try:
            from unittest.mock import Mock
            middleware = ExtendedSecurityMiddleware(get_response=Mock())
            request = factory.get('/', HTTP_USER_AGENT='sqlmap/1.4.7')
            
            try:
                middleware.process_request(request)
                failed_tests += 1
                self.stdout.write("  ❌ Middleware SQLMap Detection")
            except SuspiciousOperation as e:
                if "SQLMap attack detected" in str(e):
                    passed_tests += 1
                    self.stdout.write("  ✅ Middleware SQLMap Detection")
                else:
                    failed_tests += 1
                    self.stdout.write("  ❌ Middleware SQLMap Detection")
        except Exception as e:
            failed_tests += 1
            self.stdout.write(f"  ❌ Middleware SQLMap Detection: {e}")
        
        # Clean up
        cache.clear()
        
        # Display results summary
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write('🎯 EXTENDED SECURITY TEST RESULTS:')
        self.stdout.write(f"📊 Total Tests: {total_tests}")
        self.stdout.write(f"✅ Passed: {passed_tests}")
        self.stdout.write(f"❌ Failed: {failed_tests}")
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        self.stdout.write(f"📈 Success Rate: {success_rate:.1f}%")
        
        if failed_tests == 0:
            self.stdout.write(
                self.style.SUCCESS('\n🎉 ALL EXTENDED SECURITY TESTS PASSED!')
            )
            self.stdout.write(
                self.style.SUCCESS('🛡️  Your application is protected against advanced attack vectors!')
            )
        else:
            self.stdout.write(
                self.style.WARNING(f'\n⚠️  {failed_tests} tests failed. Review security configuration.')
            )
        
        # Additional protection summary
        self.stdout.write('\n🔐 EXTENDED PROTECTION COVERAGE:')
        self.stdout.write('  • SQLMap automated SQL injection attacks')
        self.stdout.write('  • Brute force login attacks (rate limiting, enumeration, spraying)')
        self.stdout.write('  • Unrestricted file upload vulnerabilities')
        self.stdout.write('  • ORM injection attacks')
        self.stdout.write('  • Server-side template injection (SSTI)')
        self.stdout.write('  • Advanced evasion techniques')
        self.stdout.write('  • Multi-vector attack scenarios')
        
        return f"Extended security tests completed: {passed_tests}/{total_tests} passed"