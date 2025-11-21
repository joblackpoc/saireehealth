"""
Security Testing Management Command
Run comprehensive security protection tests
"""

from django.core.management.base import BaseCommand
from security_enhancements.advanced_protection_tests import run_security_tests


class Command(BaseCommand):
    help = 'Run comprehensive security protection tests'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )
    
    def handle(self, *args, **options):
        """Run the security tests"""
        self.stdout.write(
            self.style.SUCCESS('🔐 Starting Advanced Security Protection Tests...')
        )
        
        try:
            # Run comprehensive security tests
            all_passed = run_security_tests()
            
            if all_passed:
                self.stdout.write(
                    self.style.SUCCESS(
                        '\n🏆 ALL SECURITY TESTS PASSED! '
                        'Your application is protected against advanced attacks.'
                    )
                )
            else:
                self.stdout.write(
                    self.style.ERROR(
                        '\n⚠️  SOME SECURITY TESTS FAILED! '
                        'Please review the results above and fix any issues.'
                    )
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error running security tests: {str(e)}')
            )