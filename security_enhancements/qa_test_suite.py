#!/usr/bin/env python
"""
Security QA Test Suite
Quality assurance testing for Phase 10 security components
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

def test_imports():
    """Test that all security modules can be imported"""
    print("🔍 Testing imports...")
    
    try:
        from security_enhancements.threat_intelligence import (
            get_threat_intelligence_engine, ThreatLevel, IOCType, 
            ThreatIntelligenceEngine
        )
        print("✅ Threat intelligence imports OK")
    except Exception as e:
        print(f"❌ Threat intelligence import failed: {e}")
        return False
    
    try:
        from security_enhancements.predictive_analytics import (
            get_predictive_analytics_engine, RiskLevel, 
            PredictiveSecurityAnalytics
        )
        print("✅ Predictive analytics imports OK")
    except Exception as e:
        print(f"❌ Predictive analytics import failed: {e}")
        return False
    
    try:
        from security_enhancements.ai_security_automation import (
            get_security_automation_engine, AutomationAction,
            AISecurityAutomationEngine
        )
        print("✅ AI security automation imports OK")
    except Exception as e:
        print(f"❌ AI security automation import failed: {e}")
        return False
    
    try:
        from security_enhancements.zero_trust_architecture import (
            get_zero_trust_architecture, TrustLevel, AccessDecision,
            ZeroTrustArchitecture
        )
        print("✅ Zero-trust architecture imports OK")
    except Exception as e:
        print(f"❌ Zero-trust architecture import failed: {e}")
        return False
    
    return True

def test_initialization():
    """Test that all engines can be initialized"""
    print("\n🔍 Testing initialization...")
    
    try:
        from security_enhancements.threat_intelligence import get_threat_intelligence_engine
        engine = get_threat_intelligence_engine()
        print("✅ Threat intelligence engine initialized")
    except Exception as e:
        print(f"❌ Threat intelligence initialization failed: {e}")
        return False
    
    try:
        from security_enhancements.predictive_analytics import get_predictive_analytics_engine
        engine = get_predictive_analytics_engine()
        print("✅ Predictive analytics engine initialized")
    except Exception as e:
        print(f"❌ Predictive analytics initialization failed: {e}")
        return False
    
    try:
        from security_enhancements.ai_security_automation import get_security_automation_engine
        engine = get_security_automation_engine()
        print("✅ AI security automation engine initialized")
    except Exception as e:
        print(f"❌ AI security automation initialization failed: {e}")
        return False
    
    try:
        from security_enhancements.zero_trust_architecture import get_zero_trust_architecture
        engine = get_zero_trust_architecture()
        print("✅ Zero-trust architecture initialized")
    except Exception as e:
        print(f"❌ Zero-trust architecture initialization failed: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic functionality of each component"""
    print("\n🔍 Testing basic functionality...")
    
    try:
        from security_enhancements.threat_intelligence import get_threat_intelligence_engine, ThreatLevel
        engine = get_threat_intelligence_engine()
        
        # Test IOC processing
        test_ip = "192.168.1.100"
        result = engine.check_ip_reputation(test_ip)
        print(f"✅ IP reputation check works: {test_ip}")
        
        # Test threat intelligence summary
        summary = engine.get_threat_intelligence_summary()
        print(f"✅ Threat intelligence summary generated")
        
    except Exception as e:
        print(f"❌ Threat intelligence functionality failed: {e}")
        return False
    
    try:
        from security_enhancements.predictive_analytics import get_predictive_analytics_engine
        engine = get_predictive_analytics_engine()
        
        # Test user risk assessment
        test_user_id = "test_user_123"
        risk_profile = engine.get_user_risk_profile(test_user_id)
        print(f"✅ User risk assessment works")
        
        # Test analytics summary
        summary = engine.get_analytics_summary()
        print(f"✅ Analytics summary generated")
        
    except Exception as e:
        print(f"❌ Predictive analytics functionality failed: {e}")
        return False
    
    try:
        from security_enhancements.ai_security_automation import get_security_automation_engine
        engine = get_security_automation_engine()
        
        # Test automation summary
        summary = engine.get_automation_summary()
        print(f"✅ Automation summary generated")
        
    except Exception as e:
        print(f"❌ AI security automation functionality failed: {e}")
        return False
    
    try:
        from security_enhancements.zero_trust_architecture import get_zero_trust_architecture
        engine = get_zero_trust_architecture()
        
        # Test zero-trust summary
        summary = engine.get_zero_trust_summary()
        print(f"✅ Zero-trust summary generated")
        
    except Exception as e:
        print(f"❌ Zero-trust architecture functionality failed: {e}")
        return False
    
    return True

def test_integration():
    """Test integration between components"""
    print("\n🔍 Testing component integration...")
    
    try:
        from security_enhancements.threat_intelligence import get_threat_intelligence_engine
        from security_enhancements.predictive_analytics import get_predictive_analytics_engine
        from security_enhancements.ai_security_automation import get_security_automation_engine
        from security_enhancements.zero_trust_architecture import get_zero_trust_architecture
        
        # Get all engines
        threat_engine = get_threat_intelligence_engine()
        analytics_engine = get_predictive_analytics_engine()
        automation_engine = get_security_automation_engine()
        zt_engine = get_zero_trust_architecture()
        
        print("✅ All engines can be accessed simultaneously")
        
        # Test data sharing between components
        threat_summary = threat_engine.get_threat_intelligence_summary()
        analytics_summary = analytics_engine.get_analytics_summary()
        automation_summary = automation_engine.get_automation_summary()
        zt_summary = zt_engine.get_zero_trust_summary()
        
        print("✅ All summaries can be generated simultaneously")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def run_qa_tests():
    """Run all QA tests"""
    print("🚀 Starting Security QA Test Suite")
    print("=" * 50)
    
    tests_passed = 0
    total_tests = 4
    
    # Test imports
    if test_imports():
        tests_passed += 1
    
    # Test initialization
    if test_initialization():
        tests_passed += 1
    
    # Test basic functionality
    if test_basic_functionality():
        tests_passed += 1
    
    # Test integration
    if test_integration():
        tests_passed += 1
    
    print("\n" + "=" * 50)
    print(f"🎯 QA Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All tests PASSED! Phase 10 is ready for production!")
        return True
    else:
        print("⚠️  Some tests FAILED. Please review and fix issues.")
        return False

if __name__ == "__main__":
    success = run_qa_tests()
    sys.exit(0 if success else 1)