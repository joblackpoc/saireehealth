"""
Management command to populate security dashboard data
"""
from django.core.management.base import BaseCommand
from security_enhancements.dashboard_data_handler import SecurityDashboardDataHandler


class Command(BaseCommand):
    help = 'Populate security dashboard with real-time data'

    def handle(self, *args, **options):
        self.stdout.write('Populating security dashboard data...')
        
        try:
            success = SecurityDashboardDataHandler.populate_realtime_security_data()
            if success:
                self.stdout.write(
                    self.style.SUCCESS('Successfully populated security dashboard data')
                )
            else:
                self.stdout.write(
                    self.style.ERROR('Failed to populate security dashboard data')
                )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error: {str(e)}')
            )