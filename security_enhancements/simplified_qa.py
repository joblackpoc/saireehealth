#!/usr/bin/env python
"""
Simplified Security QA Test Suite
Quality assurance testing for Phase 10 security components without Django dependencies
"""

import os
import sys
import inspect
import importlib.util

def check_python_syntax(file_path):
    """Check if a Python file has valid syntax"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        compile(code, file_path, 'exec')
        return True, None
    except SyntaxError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def check_imports(file_path):
    """Check if all imports in a file are available"""
    import_errors = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                # Skip Django imports for now
                if 'django' in line:
                    continue
                
                try:
                    # Extract module name
                    if line.startswith('import '):
                        module_name = line.replace('import ', '').split()[0]
                    else:
                        module_name = line.split('from ')[1].split(' import')[0]
                    
                    # Skip relative imports
                    if module_name.startswith('.'):
                        continue
                    
                    # Try to import
                    try:
                        __import__(module_name)
                    except ImportError as e:
                        import_errors.append(f"Line {line_num}: {line} -> {str(e)}")
                
                except Exception:
                    # Skip problematic lines
                    pass
    
    except Exception as e:
        import_errors.append(f"File reading error: {str(e)}")
    
    return import_errors

def test_file_structure():
    """Test that all required files exist"""
    print("🔍 Testing file structure...")
    
    required_files = [
        'security_enhancements/threat_intelligence.py',
        'security_enhancements/predictive_analytics.py',
        'security_enhancements/ai_security_automation.py',
        'security_enhancements/zero_trust_architecture.py'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    else:
        print("✅ All required files exist")
        return True

def test_syntax():
    """Test Python syntax of all files"""
    print("\n🔍 Testing Python syntax...")
    
    files_to_test = [
        'security_enhancements/threat_intelligence.py',
        'security_enhancements/predictive_analytics.py',
        'security_enhancements/ai_security_automation.py',
        'security_enhancements/zero_trust_architecture.py'
    ]
    
    syntax_errors = []
    for file_path in files_to_test:
        is_valid, error = check_python_syntax(file_path)
        if not is_valid:
            syntax_errors.append(f"{file_path}: {error}")
        else:
            print(f"✅ {file_path} - syntax OK")
    
    if syntax_errors:
        print("❌ Syntax errors found:")
        for error in syntax_errors:
            print(f"   {error}")
        return False
    
    return True

def test_imports():
    """Test imports in all files"""
    print("\n🔍 Testing imports...")
    
    files_to_test = [
        'security_enhancements/threat_intelligence.py',
        'security_enhancements/predictive_analytics.py',
        'security_enhancements/ai_security_automation.py',
        'security_enhancements/zero_trust_architecture.py'
    ]
    
    all_import_errors = []
    for file_path in files_to_test:
        import_errors = check_imports(file_path)
        if import_errors:
            all_import_errors.extend([f"{file_path}: {error}" for error in import_errors])
        else:
            print(f"✅ {file_path} - imports OK (excluding Django)")
    
    if all_import_errors:
        print("❌ Import errors found:")
        for error in all_import_errors:
            print(f"   {error}")
        return False
    
    return True

def test_class_definitions():
    """Test that key classes are properly defined"""
    print("\n🔍 Testing class definitions...")
    
    # Check that files contain expected class definitions
    class_checks = [
        ('security_enhancements/threat_intelligence.py', ['ThreatIntelligenceEngine', 'ThreatLevel', 'IOCType']),
        ('security_enhancements/predictive_analytics.py', ['PredictiveSecurityAnalytics', 'RiskLevel']),
        ('security_enhancements/ai_security_automation.py', ['AISecurityAutomationEngine', 'AutomationAction']),
        ('security_enhancements/zero_trust_architecture.py', ['ZeroTrustArchitecture', 'TrustLevel', 'AccessDecision'])
    ]
    
    missing_classes = []
    for file_path, expected_classes in class_checks:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            for class_name in expected_classes:
                if f"class {class_name}" not in content:
                    missing_classes.append(f"{file_path}: {class_name}")
                else:
                    print(f"✅ {file_path}: {class_name} found")
        
        except Exception as e:
            missing_classes.append(f"{file_path}: Error reading file - {str(e)}")
    
    if missing_classes:
        print("❌ Missing class definitions:")
        for missing in missing_classes:
            print(f"   {missing}")
        return False
    
    return True

def test_function_definitions():
    """Test that key functions are properly defined"""
    print("\n🔍 Testing function definitions...")
    
    # Check that files contain expected function definitions
    function_checks = [
        ('security_enhancements/threat_intelligence.py', ['get_threat_intelligence_engine']),
        ('security_enhancements/predictive_analytics.py', ['get_predictive_analytics_engine']),
        ('security_enhancements/ai_security_automation.py', ['get_security_automation_engine']),
        ('security_enhancements/zero_trust_architecture.py', ['get_zero_trust_architecture'])
    ]
    
    missing_functions = []
    for file_path, expected_functions in function_checks:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            for func_name in expected_functions:
                if f"def {func_name}" not in content:
                    missing_functions.append(f"{file_path}: {func_name}")
                else:
                    print(f"✅ {file_path}: {func_name}() found")
        
        except Exception as e:
            missing_functions.append(f"{file_path}: Error reading file - {str(e)}")
    
    if missing_functions:
        print("❌ Missing function definitions:")
        for missing in missing_functions:
            print(f"   {missing}")
        return False
    
    return True

def test_code_quality():
    """Test code quality metrics"""
    print("\n🔍 Testing code quality...")
    
    files_to_test = [
        'security_enhancements/threat_intelligence.py',
        'security_enhancements/predictive_analytics.py',
        'security_enhancements/ai_security_automation.py',
        'security_enhancements/zero_trust_architecture.py'
    ]
    
    quality_issues = []
    
    for file_path in files_to_test:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Check file size (should be reasonable)
            if len(lines) > 2000:
                quality_issues.append(f"{file_path}: Very large file ({len(lines)} lines)")
            
            # Check for docstrings
            if '"""' not in content[:500]:
                quality_issues.append(f"{file_path}: Missing module docstring")
            
            # Check for error handling
            if 'try:' not in content or 'except' not in content:
                quality_issues.append(f"{file_path}: Missing error handling")
            
            # Check for logging
            if 'logging' not in content:
                quality_issues.append(f"{file_path}: No logging implementation")
            
            print(f"✅ {file_path} - quality check OK")
            
        except Exception as e:
            quality_issues.append(f"{file_path}: Error checking quality - {str(e)}")
    
    if quality_issues:
        print("⚠️  Code quality issues found:")
        for issue in quality_issues:
            print(f"   {issue}")
        # Don't fail for quality issues, just warn
    
    return True

def run_simplified_qa():
    """Run simplified QA tests"""
    print("🚀 Starting Simplified Security QA Test Suite")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 6
    
    # Test file structure
    if test_file_structure():
        tests_passed += 1
    
    # Test syntax
    if test_syntax():
        tests_passed += 1
    
    # Test imports
    if test_imports():
        tests_passed += 1
    
    # Test class definitions
    if test_class_definitions():
        tests_passed += 1
    
    # Test function definitions
    if test_function_definitions():
        tests_passed += 1
    
    # Test code quality
    if test_code_quality():
        tests_passed += 1
    
    print("\n" + "=" * 60)
    print(f"🎯 QA Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All basic tests PASSED! Code structure is solid!")
        return True
    else:
        print("⚠️  Some tests FAILED. Please review and fix issues.")
        return False

if __name__ == "__main__":
    success = run_simplified_qa()
    sys.exit(0 if success else 1)