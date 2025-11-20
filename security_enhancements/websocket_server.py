"""
Phase 8: WebSocket Server Management Script
Standalone WebSocket server for real-time security event streaming

Author: ETH Blue Team Engineer
Created: 2025-11-15
Security Level: CRITICAL
Component: WebSocket Server Management
"""

import os
import sys
import django
import asyncio
import logging
import signal
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from security_enhancements.event_streaming import get_event_streamer, SecurityEventStreamer
from security_enhancements.advanced_monitoring import get_security_monitor
from django.conf import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/websocket_server.log')
    ]
)

logger = logging.getLogger('websocket_server')

class WebSocketServerManager:
    """
    WebSocket Server Manager
    
    Manages the WebSocket server lifecycle for real-time event streaming
    """
    
    def __init__(self):
        self.streamer = None
        self.security_monitor = None
        self.server_task = None
        self.monitor_task = None
        self.running = False
        
        # Get configuration
        self.config = getattr(settings, 'EVENT_STREAMING_CONFIG', {})
        self.port = self.config.get('WEBSOCKET_PORT', 8765)
        
    async def start_server(self):
        """Start WebSocket server and monitoring"""
        try:
            logger.info("Starting WebSocket server manager...")
            
            # Initialize components
            self.streamer = get_event_streamer()
            self.security_monitor = get_security_monitor()
            
            # Start security monitoring
            if not self.security_monitor.is_running():
                self.security_monitor.start_monitoring()
                logger.info("Security monitoring started")
            
            # Start WebSocket server
            logger.info(f"Starting WebSocket server on port {self.port}")
            self.server_task = asyncio.create_task(
                self.streamer.start_websocket_server()
            )
            
            # Start monitoring integration
            self.monitor_task = asyncio.create_task(
                self._monitoring_integration_loop()
            )
            
            self.running = True
            logger.info(f"WebSocket server started successfully on ws://0.0.0.0:{self.port}")
            
            # Wait for tasks
            await asyncio.gather(
                self.server_task,
                self.monitor_task,
                return_exceptions=True
            )
            
        except Exception as e:
            logger.error(f"Failed to start WebSocket server: {str(e)}")
            raise
    
    async def _monitoring_integration_loop(self):
        """Integrate with security monitoring system"""
        logger.info("Starting monitoring integration loop...")
        
        try:
            # Subscribe to security monitor events
            while self.running:
                try:
                    # Get recent events from security monitor
                    recent_events = self.security_monitor.get_recent_events(limit=100)
                    
                    # Stream events to WebSocket clients
                    for event in recent_events:
                        if self.streamer:
                            await self.streamer.stream_event(event)
                    
                    # Small delay to prevent overwhelming
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.error(f"Monitoring integration error: {str(e)}")
                    await asyncio.sleep(5)
                    
        except asyncio.CancelledError:
            logger.info("Monitoring integration stopped")
        except Exception as e:
            logger.error(f"Monitoring integration failed: {str(e)}")
    
    async def stop_server(self):
        """Stop WebSocket server gracefully"""
        logger.info("Stopping WebSocket server...")
        
        self.running = False
        
        # Cancel tasks
        if self.server_task and not self.server_task.done():
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
        
        if self.monitor_task and not self.monitor_task.done():
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        # Shutdown streamer
        if self.streamer:
            self.streamer.shutdown()
        
        logger.info("WebSocket server stopped")
    
    def get_server_status(self) -> dict:
        """Get server status information"""
        status = {
            'running': self.running,
            'port': self.port,
            'tasks': {
                'server_task': self.server_task is not None and not self.server_task.done(),
                'monitor_task': self.monitor_task is not None and not self.monitor_task.done(),
            }
        }
        
        if self.streamer:
            status['streaming'] = self.streamer.get_streaming_status()
        
        if self.security_monitor:
            status['monitoring'] = self.security_monitor.get_system_status()
        
        return status


# Global server manager
server_manager = WebSocketServerManager()

async def main():
    """Main server function"""
    logger.info("WebSocket Server Manager starting...")
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating shutdown...")
        asyncio.create_task(server_manager.stop_server())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start server
        await server_manager.start_server()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
    finally:
        await server_manager.stop_server()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutdown complete")
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        sys.exit(1)