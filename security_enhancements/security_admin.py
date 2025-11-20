"""
Security Admin Views and Management Commands for HealthProgress
"""
from django.shortcuts import render
from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.core.management.base import BaseCommand
import json
from datetime import datetime, timedelta
from security_enhancements.monitoring_and_jwt import SecurityMonitor, SecurityAlerting
from security_enhancements.security_core import SecurityLogger, SecurityCore


# ============================================================================
# ADMIN VIEWS
# ============================================================================

@staff_member_required
def security_dashboard_view(request):
    """Security monitoring dashboard"""
    dashboard_data = SecurityMonitor.get_security_dashboard()
    
    context = {
        'dashboard_data': dashboard_data,
        'page_title': 'Security Dashboard',
    }
    
    return render(request, 'security/dashboard.html', context)


@staff_member_required
def security_events_api(request):
    """API endpoint for security events (for AJAX requests)"""
    hours = int(request.GET.get('hours', 24))
    events = SecurityLogger.get_recent_events(hours=hours)
    
    return JsonResponse({
        'events': events,
        'count': len(events)
    })


@staff_member_required
def security_metrics_api(request):
    """API endpoint for security metrics"""
    days = int(request.GET.get('days', 7))
    metrics = SecurityCore.get_security_metrics(days=days)
    
    return JsonResponse({'metrics': metrics})


@staff_member_required
def security_report_view(request):
    """Generate and download security report"""
    days = int(request.GET.get('days', 7))
    report = SecurityMonitor.generate_security_report(days=days)
    
    # Return as JSON download
    response = HttpResponse(
        json.dumps(report, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="security_report_{datetime.now().strftime("%Y%m%d")}.json"'
    
    return response


@staff_member_required
def block_ip_view(request):
    """Manually block an IP address"""
    if request.method == 'POST':
        ip = request.POST.get('ip')
        duration = int(request.POST.get('duration', 3600))  # Default 1 hour
        
        from django.core.cache import cache
        cache.set(f"blocked_ip:{ip}", True, timeout=duration)
        
        SecurityLogger.log_security_event(
            'ip_blocked_manually',
            'high',
            {'ip': ip, 'duration': duration, 'admin': request.user.username},
            request=request,
            user=request.user
        )
        
        return JsonResponse({'status': 'success', 'message': f'IP {ip} blocked for {duration} seconds'})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
def unblock_ip_view(request):
    """Manually unblock an IP address"""
    if request.method == 'POST':
        ip = request.POST.get('ip')
        
        from django.core.cache import cache
        cache.delete(f"blocked_ip:{ip}")
        
        SecurityLogger.log_security_event(
            'ip_unblocked_manually',
            'low',
            {'ip': ip, 'admin': request.user.username},
            request=request,
            user=request.user
        )
        
        return JsonResponse({'status': 'success', 'message': f'IP {ip} unblocked'})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@staff_member_required
@require_http_methods(["GET"])
def blocked_ips_list(request):
    """List all currently blocked IPs"""
    from django.core.cache import cache
    
    # Get all blocked IPs (this is a simplified version)
    # In production, you'd want to store this in a more queryable way
    blocked_ips = cache.get('blocked_ips_list', [])
    
    return JsonResponse({'blocked_ips': blocked_ips})


# ============================================================================
# MANAGEMENT COMMANDS
# ============================================================================

class Command(BaseCommand):
    """Security management commands"""
    
    help = 'Security management utilities'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            type=str,
            choices=['dashboard', 'report', 'check-alerts', 'clear-logs', 'test-alert'],
            help='Action to perform'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days for reports'
        )
    
    def handle(self, *args, **options):
        action = options['action']
        
        if action == 'dashboard':
            self._show_dashboard()
        
        elif action == 'report':
            self._generate_report(options['days'])
        
        elif action == 'check-alerts':
            self._check_alerts()
        
        elif action == 'clear-logs':
            self._clear_old_logs(options['days'])
        
        elif action == 'test-alert':
            self._test_alert()
    
    def _show_dashboard(self):
        """Display security dashboard in console"""
        self.stdout.write(self.style.SUCCESS('\n=== Security Dashboard ===\n'))
        
        dashboard = SecurityMonitor.get_security_dashboard()
        
        # Summary
        summary = dashboard['summary']
        self.stdout.write(f"Total Events (24h): {summary['total_events_24h']}")
        self.stdout.write(self.style.ERROR(f"Critical Events: {summary['critical_events']}"))
        self.stdout.write(self.style.WARNING(f"High Priority Events: {summary['high_events']}"))
        self.stdout.write(f"Blocked IPs: {summary['blocked_ips']}\n")
        
        # Top attacks
        self.stdout.write(self.style.SUCCESS('Top Attack Types:'))
        for attack, count in dashboard['top_attacks'][:5]:
            self.stdout.write(f"  {attack}: {count}")
        
        # Top attacking IPs
        self.stdout.write(self.style.SUCCESS('\nTop Attacking IPs:'))
        for ip, count in dashboard['top_attacking_ips'][:5]:
            self.stdout.write(f"  {ip}: {count}")
    
    def _generate_report(self, days):
        """Generate security report"""
        self.stdout.write(self.style.SUCCESS(f'\n=== Generating Security Report ({days} days) ===\n'))
        
        report = SecurityMonitor.generate_security_report(days=days)
        
        # Save to file
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.stdout.write(self.style.SUCCESS(f'Report saved to: {filename}'))
        
        # Display summary
        self.stdout.write(f"\nTotal Events: {report['total_events']}")
        self.stdout.write("\nSeverity Breakdown:")
        for severity, count in report['severity_breakdown'].items():
            self.stdout.write(f"  {severity}: {count}")
    
    def _check_alerts(self):
        """Check for conditions requiring alerts"""
        self.stdout.write(self.style.SUCCESS('\n=== Checking Security Alerts ===\n'))
        
        SecurityAlerting.check_and_alert()
        
        self.stdout.write(self.style.SUCCESS('Alert check completed'))
    
    def _clear_old_logs(self, days):
        """Clear old security logs"""
        self.stdout.write(self.style.WARNING(f'\n=== Clearing logs older than {days} days ===\n'))
        
        from django.core.cache import cache
        
        cutoff_date = datetime.now() - timedelta(days=days)
        cleared_count = 0
        
        # Clear old cache entries
        for i in range(days, days + 30):  # Check extra 30 days
            date = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
            cache_key = f"security_events:{date}"
            if cache.delete(cache_key):
                cleared_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'Cleared {cleared_count} old log entries'))
    
    def _test_alert(self):
        """Send test security alert"""
        self.stdout.write(self.style.SUCCESS('\n=== Sending Test Alert ===\n'))
        
        SecurityAlerting.send_alert(
            'test_alert',
            'medium',
            {
                'message': 'This is a test security alert',
                'timestamp': datetime.now().isoformat(),
                'source': 'management_command'
            }
        )
        
        self.stdout.write(self.style.SUCCESS('Test alert sent'))


