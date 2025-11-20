"""
Phase 8: Security Event Stream Processing System
Real-time event streaming with WebSocket support and distributed processing

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: Event Stream Processing & Distribution
"""

import asyncio
import websockets
import json
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, AsyncGenerator, Callable, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import concurrent.futures
from collections import deque, defaultdict
import logging
import gzip
import pickle
import hashlib

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
import numpy as np

from .advanced_monitoring import SecurityEvent, EventPriority, get_security_monitor

# Event Stream Logger
stream_logger = logging.getLogger('event_stream')

class StreamStatus(Enum):
    """Event stream status"""
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    SHUTDOWN = "shutdown"

class SubscriptionType(Enum):
    """Event subscription types"""
    ALL_EVENTS = "all"
    SECURITY_ONLY = "security"
    HIGH_PRIORITY = "high_priority"
    CRITICAL_ONLY = "critical"
    CUSTOM_FILTER = "custom"

@dataclass
class StreamSubscription:
    """Event stream subscription"""
    subscription_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str = ""
    subscription_type: SubscriptionType = SubscriptionType.ALL_EVENTS
    filters: Dict[str, Any] = field(default_factory=dict)
    websocket: Optional[object] = None
    created_at: datetime = field(default_factory=timezone.now)
    last_activity: datetime = field(default_factory=timezone.now)
    events_sent: int = 0
    is_active: bool = True

@dataclass
class EventBatch:
    """Batch of events for processing"""
    batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    events: List[SecurityEvent] = field(default_factory=list)
    created_at: datetime = field(default_factory=timezone.now)
    priority: EventPriority = EventPriority.NORMAL
    processing_node: str = ""
    compressed: bool = False

class SecurityEventStreamer:
    """
    Real-time Security Event Streaming System
    
    Provides WebSocket-based event streaming, batch processing,
    and distributed event processing capabilities.
    """
    
    def __init__(self, port: int = 8765):
        self.port = port
        self.status = StreamStatus.ACTIVE
        self.subscriptions: Dict[str, StreamSubscription] = {}
        self.event_buffer = deque(maxlen=100000)  # Large buffer for high-throughput
        self.batch_processors: List[concurrent.futures.ThreadPoolExecutor] = []
        
        # Streaming configuration
        self.config = getattr(settings, 'EVENT_STREAMING_CONFIG', {
            'MAX_CONNECTIONS': 1000,
            'BATCH_SIZE': 100,
            'BATCH_TIMEOUT_SECONDS': 5,
            'COMPRESSION_ENABLED': True,
            'RATE_LIMIT_EVENTS_PER_SECOND': 1000,
            'WEBSOCKET_PING_INTERVAL': 30,
            'SUBSCRIPTION_TIMEOUT_MINUTES': 60,
            'ENABLE_EVENT_REPLAY': True,
            'BUFFER_PERSISTENCE_ENABLED': True,
        })
        
        # Performance metrics
        self.metrics = {
            'total_events_streamed': 0,
            'active_subscriptions': 0,
            'events_per_second': 0.0,
            'bytes_transferred': 0,
            'connection_errors': 0,
            'processing_latency_ms': 0.0,
            'buffer_utilization': 0.0,
        }
        
        # Background tasks
        self.background_tasks = []
        self.event_processors = []
        
        # Initialize components
        self._initialize_streaming_system()
        
        stream_logger.info(f"Security Event Streamer initialized on port {self.port}")
    
    def _initialize_streaming_system(self):
        """Initialize event streaming system components"""
        try:
            # Initialize batch processors
            processor_count = self.config.get('BATCH_PROCESSORS', 4)
            for i in range(processor_count):
                executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=2,
                    thread_name_prefix=f"BatchProcessor-{i}"
                )
                self.batch_processors.append(executor)
            
            # Start background tasks
            self._start_background_tasks()
            
            stream_logger.info("Event streaming system initialized successfully")
            
        except Exception as e:
            stream_logger.error(f"Failed to initialize streaming system: {str(e)}")
            self.status = StreamStatus.ERROR
            raise
    
    def _start_background_tasks(self):
        """Start background processing tasks"""
        # Event buffer management
        buffer_task = threading.Thread(
            target=self._buffer_management_loop,
            name="BufferManager",
            daemon=True
        )
        buffer_task.start()
        self.background_tasks.append(buffer_task)
        
        # Subscription cleanup
        cleanup_task = threading.Thread(
            target=self._subscription_cleanup_loop,
            name="SubscriptionCleanup",
            daemon=True
        )
        cleanup_task.start()
        self.background_tasks.append(cleanup_task)
        
        # Metrics collection
        metrics_task = threading.Thread(
            target=self._metrics_collection_loop,
            name="StreamMetrics",
            daemon=True
        )
        metrics_task.start()
        self.background_tasks.append(metrics_task)
        
        # Event batch processing
        batch_task = threading.Thread(
            target=self._batch_processing_loop,
            name="BatchProcessor",
            daemon=True
        )
        batch_task.start()
        self.background_tasks.append(batch_task)
    
    async def start_websocket_server(self):
        """Start WebSocket server for event streaming"""
        try:
            stream_logger.info(f"Starting WebSocket server on port {self.port}")
            
            async with websockets.serve(
                self._handle_websocket_connection,
                "0.0.0.0",
                self.port,
                ping_interval=self.config.get('WEBSOCKET_PING_INTERVAL', 30),
                max_size=1024*1024,  # 1MB max message size
                compression="deflate" if self.config.get('COMPRESSION_ENABLED', True) else None
            ):
                stream_logger.info(f"WebSocket server running on ws://0.0.0.0:{self.port}")
                
                # Keep server running
                while self.status == StreamStatus.ACTIVE:
                    await asyncio.sleep(1)
                    
        except Exception as e:
            stream_logger.error(f"WebSocket server error: {str(e)}")
            self.status = StreamStatus.ERROR
    
    async def _handle_websocket_connection(self, websocket, path):
        """Handle individual WebSocket connection"""
        client_id = str(uuid.uuid4())
        subscription = None
        
        try:
            # Check connection limit
            if len(self.subscriptions) >= self.config.get('MAX_CONNECTIONS', 1000):
                await websocket.close(code=1013, reason="Server overloaded")
                return
            
            stream_logger.info(f"New WebSocket connection from {websocket.remote_address}, client ID: {client_id}")
            
            # Send welcome message
            welcome_msg = {
                'type': 'welcome',
                'client_id': client_id,
                'server_time': timezone.now().isoformat(),
                'capabilities': [
                    'event_streaming',
                    'real_time_alerts',
                    'event_replay',
                    'custom_filters'
                ]
            }
            await websocket.send(json.dumps(welcome_msg))
            
            # Handle client messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    response = await self._handle_client_message(client_id, data, websocket)
                    
                    if response:
                        await websocket.send(json.dumps(response))
                        
                    # Update subscription if needed
                    if data.get('type') == 'subscribe' and client_id in self.subscriptions:
                        subscription = self.subscriptions[client_id]
                        subscription.websocket = websocket
                        
                except json.JSONDecodeError:
                    error_msg = {'type': 'error', 'message': 'Invalid JSON format'}
                    await websocket.send(json.dumps(error_msg))
                except Exception as e:
                    error_msg = {'type': 'error', 'message': str(e)}
                    await websocket.send(json.dumps(error_msg))
        
        except websockets.exceptions.ConnectionClosed:
            stream_logger.info(f"WebSocket connection closed for client {client_id}")
        except Exception as e:
            stream_logger.error(f"WebSocket connection error for client {client_id}: {str(e)}")
        finally:
            # Cleanup subscription
            if client_id in self.subscriptions:
                del self.subscriptions[client_id]
                stream_logger.info(f"Subscription removed for client {client_id}")
    
    async def _handle_client_message(self, client_id: str, data: Dict[str, Any], websocket) -> Optional[Dict[str, Any]]:
        """Handle client message"""
        message_type = data.get('type')
        
        if message_type == 'subscribe':
            return await self._handle_subscription(client_id, data, websocket)
        elif message_type == 'unsubscribe':
            return await self._handle_unsubscription(client_id)
        elif message_type == 'get_events':
            return await self._handle_event_request(client_id, data)
        elif message_type == 'ping':
            return {'type': 'pong', 'timestamp': timezone.now().isoformat()}
        elif message_type == 'get_metrics':
            return {'type': 'metrics', 'data': self.metrics.copy()}
        else:
            return {'type': 'error', 'message': f'Unknown message type: {message_type}'}
    
    async def _handle_subscription(self, client_id: str, data: Dict[str, Any], websocket) -> Dict[str, Any]:
        """Handle event subscription request"""
        try:
            subscription_type_str = data.get('subscription_type', 'all')
            subscription_type = SubscriptionType(subscription_type_str)
            
            filters = data.get('filters', {})
            
            # Validate filters
            if not self._validate_filters(filters):
                return {'type': 'error', 'message': 'Invalid filters'}
            
            # Create subscription
            subscription = StreamSubscription(
                client_id=client_id,
                subscription_type=subscription_type,
                filters=filters,
                websocket=websocket
            )
            
            self.subscriptions[client_id] = subscription
            
            stream_logger.info(f"Client {client_id} subscribed with type {subscription_type.value}")
            
            # Send historical events if requested
            if data.get('include_recent_events', False):
                await self._send_recent_events(client_id, data.get('recent_count', 100))
            
            return {
                'type': 'subscription_confirmed',
                'subscription_id': subscription.subscription_id,
                'subscription_type': subscription_type.value,
                'filters': filters
            }
            
        except ValueError as e:
            return {'type': 'error', 'message': f'Invalid subscription type: {str(e)}'}
        except Exception as e:
            return {'type': 'error', 'message': f'Subscription failed: {str(e)}'}
    
    async def _handle_unsubscription(self, client_id: str) -> Dict[str, Any]:
        """Handle unsubscription request"""
        if client_id in self.subscriptions:
            del self.subscriptions[client_id]
            return {'type': 'unsubscribed', 'client_id': client_id}
        else:
            return {'type': 'error', 'message': 'No active subscription found'}
    
    async def _handle_event_request(self, client_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle request for specific events"""
        try:
            start_time = data.get('start_time')
            end_time = data.get('end_time')
            event_types = data.get('event_types', [])
            limit = min(data.get('limit', 100), 1000)  # Max 1000 events
            
            # Get events from buffer or cache
            events = await self._get_events_by_criteria(start_time, end_time, event_types, limit)
            
            return {
                'type': 'events_response',
                'events': [event.to_dict() for event in events],
                'total_count': len(events)
            }
            
        except Exception as e:
            return {'type': 'error', 'message': f'Event request failed: {str(e)}'}
    
    def _validate_filters(self, filters: Dict[str, Any]) -> bool:
        """Validate subscription filters"""
        allowed_filter_keys = [
            'severity_min', 'severity_max', 'event_types', 
            'sources', 'destinations', 'metadata_filters'
        ]
        
        for key in filters.keys():
            if key not in allowed_filter_keys:
                return False
        
        # Validate severity ranges
        if 'severity_min' in filters:
            if not isinstance(filters['severity_min'], int) or filters['severity_min'] < 1:
                return False
        
        if 'severity_max' in filters:
            if not isinstance(filters['severity_max'], int) or filters['severity_max'] > 5:
                return False
        
        return True
    
    async def _send_recent_events(self, client_id: str, count: int):
        """Send recent events to client"""
        try:
            subscription = self.subscriptions.get(client_id)
            if not subscription or not subscription.websocket:
                return
            
            # Get recent events from buffer
            recent_events = list(self.event_buffer)[-count:]
            
            for event in recent_events:
                if await self._event_matches_subscription(event, subscription):
                    event_msg = {
                        'type': 'event',
                        'data': event.to_dict(),
                        'timestamp': timezone.now().isoformat()
                    }
                    
                    await subscription.websocket.send(json.dumps(event_msg))
                    subscription.events_sent += 1
        
        except Exception as e:
            stream_logger.error(f"Failed to send recent events to client {client_id}: {str(e)}")
    
    async def stream_event(self, event: SecurityEvent):
        """Stream event to all active subscriptions"""
        if self.status != StreamStatus.ACTIVE:
            return
        
        # Add to buffer
        self.event_buffer.append(event)
        
        # Stream to all matching subscriptions
        dead_subscriptions = []
        
        for client_id, subscription in self.subscriptions.items():
            try:
                if await self._event_matches_subscription(event, subscription):
                    await self._send_event_to_client(event, subscription)
                    
            except websockets.exceptions.ConnectionClosed:
                dead_subscriptions.append(client_id)
            except Exception as e:
                stream_logger.error(f"Failed to stream event to client {client_id}: {str(e)}")
                dead_subscriptions.append(client_id)
        
        # Remove dead subscriptions
        for client_id in dead_subscriptions:
            if client_id in self.subscriptions:
                del self.subscriptions[client_id]
        
        # Update metrics
        self.metrics['total_events_streamed'] += 1
    
    async def _event_matches_subscription(self, event: SecurityEvent, subscription: StreamSubscription) -> bool:
        """Check if event matches subscription criteria"""
        # Check subscription type
        if subscription.subscription_type == SubscriptionType.SECURITY_ONLY:
            if 'security' not in event.event_type.lower():
                return False
        elif subscription.subscription_type == SubscriptionType.HIGH_PRIORITY:
            if event.priority.value < EventPriority.HIGH.value:
                return False
        elif subscription.subscription_type == SubscriptionType.CRITICAL_ONLY:
            if event.priority.value < EventPriority.CRITICAL.value:
                return False
        
        # Check custom filters
        filters = subscription.filters
        
        if 'severity_min' in filters and event.severity < filters['severity_min']:
            return False
        
        if 'severity_max' in filters and event.severity > filters['severity_max']:
            return False
        
        if 'event_types' in filters:
            if event.event_type not in filters['event_types']:
                return False
        
        if 'sources' in filters:
            if event.source not in filters['sources']:
                return False
        
        if 'destinations' in filters:
            if event.destination not in filters['destinations']:
                return False
        
        # Check metadata filters
        if 'metadata_filters' in filters:
            for key, value in filters['metadata_filters'].items():
                if event.metadata.get(key) != value:
                    return False
        
        return True
    
    async def _send_event_to_client(self, event: SecurityEvent, subscription: StreamSubscription):
        """Send event to specific client"""
        if not subscription.websocket or not subscription.is_active:
            return
        
        # Prepare event message
        event_msg = {
            'type': 'event',
            'subscription_id': subscription.subscription_id,
            'data': event.to_dict(),
            'stream_timestamp': timezone.now().isoformat()
        }
        
        # Compress large events if enabled
        message_data = json.dumps(event_msg)
        if self.config.get('COMPRESSION_ENABLED', True) and len(message_data) > 1024:
            # WebSocket compression handles this automatically
            pass
        
        await subscription.websocket.send(message_data)
        
        # Update subscription metrics
        subscription.events_sent += 1
        subscription.last_activity = timezone.now()
        
        # Update global metrics
        self.metrics['bytes_transferred'] += len(message_data.encode('utf-8'))
    
    async def _get_events_by_criteria(self, start_time: Optional[str], end_time: Optional[str], 
                                    event_types: List[str], limit: int) -> List[SecurityEvent]:
        """Get events matching specified criteria"""
        matching_events = []
        
        # Parse time filters
        start_dt = datetime.fromisoformat(start_time) if start_time else None
        end_dt = datetime.fromisoformat(end_time) if end_time else None
        
        # Search in buffer
        for event in self.event_buffer:
            # Time filtering
            if start_dt and event.timestamp < start_dt:
                continue
            if end_dt and event.timestamp > end_dt:
                continue
            
            # Event type filtering
            if event_types and event.event_type not in event_types:
                continue
            
            matching_events.append(event)
            
            if len(matching_events) >= limit:
                break
        
        return matching_events
    
    def _buffer_management_loop(self):
        """Background buffer management"""
        while self.status == StreamStatus.ACTIVE:
            try:
                # Update buffer utilization metric
                if hasattr(self.event_buffer, 'maxlen'):
                    self.metrics['buffer_utilization'] = len(self.event_buffer) / self.event_buffer.maxlen
                
                # Persist buffer if configured
                if self.config.get('BUFFER_PERSISTENCE_ENABLED', True):
                    self._persist_event_buffer()
                
                time.sleep(60)  # Run every minute
                
            except Exception as e:
                stream_logger.error(f"Buffer management error: {str(e)}")
                time.sleep(60)
    
    def _persist_event_buffer(self):
        """Persist event buffer to cache"""
        try:
            # Store last 1000 events in cache
            recent_events = list(self.event_buffer)[-1000:]
            serialized_events = [event.to_dict() for event in recent_events]
            
            cache.set('event_stream_buffer', serialized_events, 3600)  # 1 hour
            
        except Exception as e:
            stream_logger.warning(f"Buffer persistence failed: {str(e)}")
    
    def _subscription_cleanup_loop(self):
        """Clean up inactive subscriptions"""
        while self.status == StreamStatus.ACTIVE:
            try:
                timeout_minutes = self.config.get('SUBSCRIPTION_TIMEOUT_MINUTES', 60)
                cutoff_time = timezone.now() - timedelta(minutes=timeout_minutes)
                
                inactive_clients = []
                for client_id, subscription in self.subscriptions.items():
                    if subscription.last_activity < cutoff_time:
                        inactive_clients.append(client_id)
                
                # Remove inactive subscriptions
                for client_id in inactive_clients:
                    del self.subscriptions[client_id]
                    stream_logger.info(f"Removed inactive subscription for client {client_id}")
                
                # Update metrics
                self.metrics['active_subscriptions'] = len(self.subscriptions)
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                stream_logger.error(f"Subscription cleanup error: {str(e)}")
                time.sleep(300)
    
    def _metrics_collection_loop(self):
        """Collect streaming metrics"""
        last_event_count = 0
        last_time = time.time()
        
        while self.status == StreamStatus.ACTIVE:
            try:
                current_time = time.time()
                current_count = self.metrics['total_events_streamed']
                
                # Calculate events per second
                if current_time > last_time:
                    events_diff = current_count - last_event_count
                    time_diff = current_time - last_time
                    self.metrics['events_per_second'] = events_diff / time_diff
                
                last_event_count = current_count
                last_time = current_time
                
                # Update active subscriptions count
                self.metrics['active_subscriptions'] = len(self.subscriptions)
                
                # Store metrics in cache
                cache.set('event_streaming_metrics', self.metrics, 300)
                
                time.sleep(10)  # Update every 10 seconds
                
            except Exception as e:
                stream_logger.error(f"Metrics collection error: {str(e)}")
                time.sleep(10)
    
    def _batch_processing_loop(self):
        """Process events in batches for efficiency"""
        batch_buffer = []
        last_batch_time = time.time()
        
        while self.status == StreamStatus.ACTIVE:
            try:
                batch_size = self.config.get('BATCH_SIZE', 100)
                batch_timeout = self.config.get('BATCH_TIMEOUT_SECONDS', 5)
                
                # Check if we should process a batch
                current_time = time.time()
                should_process = (
                    len(batch_buffer) >= batch_size or 
                    (batch_buffer and (current_time - last_batch_time) >= batch_timeout)
                )
                
                if should_process and batch_buffer:
                    # Process batch
                    batch = EventBatch(
                        events=batch_buffer.copy(),
                        created_at=timezone.now()
                    )
                    
                    self._process_event_batch(batch)
                    
                    batch_buffer.clear()
                    last_batch_time = current_time
                
                time.sleep(0.1)  # Small delay to prevent busy waiting
                
            except Exception as e:
                stream_logger.error(f"Batch processing error: {str(e)}")
                time.sleep(1)
    
    def _process_event_batch(self, batch: EventBatch):
        """Process a batch of events"""
        try:
            start_time = time.time()
            
            # Submit batch to processor
            if self.batch_processors:
                processor = self.batch_processors[0]  # Use first available processor
                future = processor.submit(self._execute_batch_processing, batch)
                
                # Don't wait for completion to maintain throughput
                
            processing_time = (time.time() - start_time) * 1000
            self.metrics['processing_latency_ms'] = processing_time
            
        except Exception as e:
            stream_logger.error(f"Batch processing failed: {str(e)}")
    
    def _execute_batch_processing(self, batch: EventBatch):
        """Execute batch processing in thread pool"""
        try:
            # Perform batch analytics
            self._analyze_event_batch(batch)
            
            # Store batch for historical analysis
            self._store_event_batch(batch)
            
        except Exception as e:
            stream_logger.error(f"Batch execution failed: {str(e)}")
    
    def _analyze_event_batch(self, batch: EventBatch):
        """Analyze batch for patterns and anomalies"""
        try:
            if len(batch.events) < 2:
                return
            
            # Severity distribution analysis
            severity_counts = defaultdict(int)
            for event in batch.events:
                severity_counts[event.severity] += 1
            
            # Time clustering analysis
            timestamps = [event.timestamp for event in batch.events]
            if len(timestamps) > 1:
                time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                             for i in range(len(timestamps)-1)]
                avg_time_diff = sum(time_diffs) / len(time_diffs)
                
                # Detect rapid event bursts
                if avg_time_diff < 1.0:  # Events within 1 second
                    stream_logger.warning(f"Rapid event burst detected in batch {batch.batch_id}")
            
            # Source analysis
            sources = defaultdict(int)
            for event in batch.events:
                sources[event.source] += 1
            
            # Detect potential DDoS or coordinated attacks
            max_source_count = max(sources.values()) if sources else 0
            if max_source_count > len(batch.events) * 0.8:  # 80% from single source
                stream_logger.warning(f"Potential coordinated attack detected in batch {batch.batch_id}")
            
        except Exception as e:
            stream_logger.error(f"Batch analysis failed: {str(e)}")
    
    def _store_event_batch(self, batch: EventBatch):
        """Store event batch for historical analysis"""
        try:
            # Compress batch if enabled
            if self.config.get('COMPRESSION_ENABLED', True):
                batch.compressed = True
                batch_data = gzip.compress(pickle.dumps(batch))
            else:
                batch_data = pickle.dumps(batch)
            
            # Store in cache with expiration
            cache_key = f"event_batch_{batch.batch_id}"
            cache.set(cache_key, batch_data, 86400)  # 24 hours
            
        except Exception as e:
            stream_logger.error(f"Batch storage failed: {str(e)}")
    
    def get_streaming_status(self) -> Dict[str, Any]:
        """Get current streaming system status"""
        return {
            'status': self.status.value,
            'active_subscriptions': len(self.subscriptions),
            'buffer_size': len(self.event_buffer),
            'buffer_utilization': self.metrics.get('buffer_utilization', 0.0),
            'metrics': self.metrics.copy(),
            'configuration': self.config,
            'background_tasks': len(self.background_tasks),
            'batch_processors': len(self.batch_processors)
        }
    
    def shutdown(self):
        """Graceful shutdown of streaming system"""
        stream_logger.info("Shutting down event streaming system...")
        self.status = StreamStatus.SHUTDOWN
        
        # Close all WebSocket connections
        for subscription in self.subscriptions.values():
            if subscription.websocket:
                try:
                    asyncio.create_task(subscription.websocket.close())
                except Exception:
                    pass
        
        # Shutdown batch processors
        for processor in self.batch_processors:
            processor.shutdown(wait=True)
        
        stream_logger.info("Event streaming system shutdown complete")


class DistributedEventProcessor:
    """
    Distributed Event Processing System
    
    Handles event distribution across multiple processing nodes
    for horizontal scaling and fault tolerance.
    """
    
    def __init__(self):
        self.node_id = str(uuid.uuid4())
        self.processing_nodes = {}
        self.load_balancer = EventLoadBalancer()
        self.fault_detector = NodeFaultDetector()
        
        # Configuration
        self.config = getattr(settings, 'DISTRIBUTED_PROCESSING_CONFIG', {
            'ENABLE_LOAD_BALANCING': True,
            'ENABLE_FAULT_TOLERANCE': True,
            'NODE_HEALTH_CHECK_INTERVAL': 30,
            'MAX_PROCESSING_NODES': 10,
            'REPLICATION_FACTOR': 2,
        })
        
        self._initialize_distributed_processing()
    
    def _initialize_distributed_processing(self):
        """Initialize distributed processing components"""
        try:
            # Register local node
            local_node = {
                'node_id': self.node_id,
                'address': 'localhost',
                'capabilities': ['event_processing', 'streaming', 'correlation'],
                'status': 'active',
                'load': 0.0,
                'last_heartbeat': timezone.now()
            }
            
            self.processing_nodes[self.node_id] = local_node
            
            # Start node monitoring
            if self.config.get('ENABLE_FAULT_TOLERANCE', True):
                self._start_node_monitoring()
            
            stream_logger.info(f"Distributed processing initialized - Node ID: {self.node_id}")
            
        except Exception as e:
            stream_logger.error(f"Distributed processing initialization failed: {str(e)}")
    
    def _start_node_monitoring(self):
        """Start monitoring of processing nodes"""
        monitor_thread = threading.Thread(
            target=self._node_monitoring_loop,
            name="NodeMonitor",
            daemon=True
        )
        monitor_thread.start()
    
    def _node_monitoring_loop(self):
        """Monitor health of processing nodes"""
        while True:
            try:
                interval = self.config.get('NODE_HEALTH_CHECK_INTERVAL', 30)
                
                # Check node health
                unhealthy_nodes = []
                for node_id, node in self.processing_nodes.items():
                    if node_id == self.node_id:
                        continue  # Skip self
                    
                    # Check last heartbeat
                    last_heartbeat = node.get('last_heartbeat')
                    if last_heartbeat:
                        time_since_heartbeat = timezone.now() - last_heartbeat
                        if time_since_heartbeat.total_seconds() > interval * 2:
                            unhealthy_nodes.append(node_id)
                
                # Remove unhealthy nodes
                for node_id in unhealthy_nodes:
                    del self.processing_nodes[node_id]
                    stream_logger.warning(f"Removed unhealthy node: {node_id}")
                
                time.sleep(interval)
                
            except Exception as e:
                stream_logger.error(f"Node monitoring error: {str(e)}")
                time.sleep(30)
    
    def distribute_event_processing(self, events: List[SecurityEvent]) -> Dict[str, List[SecurityEvent]]:
        """Distribute events across processing nodes"""
        if not self.config.get('ENABLE_LOAD_BALANCING', True):
            return {self.node_id: events}
        
        return self.load_balancer.distribute_events(events, self.processing_nodes)
    
    def register_processing_node(self, node_info: Dict[str, Any]) -> bool:
        """Register new processing node"""
        try:
            node_id = node_info['node_id']
            
            if len(self.processing_nodes) >= self.config.get('MAX_PROCESSING_NODES', 10):
                stream_logger.warning("Maximum processing nodes reached")
                return False
            
            self.processing_nodes[node_id] = node_info
            stream_logger.info(f"Registered processing node: {node_id}")
            return True
            
        except Exception as e:
            stream_logger.error(f"Node registration failed: {str(e)}")
            return False


class EventLoadBalancer:
    """Load balancer for distributing events across nodes"""
    
    def distribute_events(self, events: List[SecurityEvent], nodes: Dict[str, Any]) -> Dict[str, List[SecurityEvent]]:
        """Distribute events using round-robin with load consideration"""
        if not nodes:
            return {}
        
        # Sort nodes by current load
        sorted_nodes = sorted(nodes.items(), key=lambda x: x[1].get('load', 0.0))
        
        # Distribute events
        distribution = defaultdict(list)
        node_index = 0
        
        for event in events:
            if sorted_nodes:
                node_id = sorted_nodes[node_index % len(sorted_nodes)][0]
                distribution[node_id].append(event)
                node_index += 1
        
        return distribution


class NodeFaultDetector:
    """Detect and handle node faults"""
    
    def __init__(self):
        self.fault_history = defaultdict(list)
        self.fault_threshold = 3  # Number of consecutive faults before marking as failed
    
    def report_node_fault(self, node_id: str, fault_type: str):
        """Report a node fault"""
        self.fault_history[node_id].append({
            'fault_type': fault_type,
            'timestamp': timezone.now()
        })
        
        # Keep only recent faults (last hour)
        cutoff_time = timezone.now() - timedelta(hours=1)
        self.fault_history[node_id] = [
            fault for fault in self.fault_history[node_id]
            if fault['timestamp'] > cutoff_time
        ]
        
        stream_logger.warning(f"Node fault reported: {node_id} - {fault_type}")
    
    def is_node_healthy(self, node_id: str) -> bool:
        """Check if node is healthy based on fault history"""
        recent_faults = len(self.fault_history.get(node_id, []))
        return recent_faults < self.fault_threshold


# Global streaming instance
_global_streamer = None

def get_event_streamer() -> SecurityEventStreamer:
    """Get global event streamer instance"""
    global _global_streamer
    if _global_streamer is None:
        _global_streamer = SecurityEventStreamer()
    return _global_streamer