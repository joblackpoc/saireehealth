"""
Django Management Command: Setup RBAC Permissions
Creates necessary permissions for Role-Based Access Control system

Author: ETH Blue Team Engineer
Created: 2025-11-14
Security Level: CRITICAL
Component: RBAC Permission Setup
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission, Group
from django.contrib.contenttypes.models import ContentType
from django.apps import apps


class Command(BaseCommand):
    help = 'Setup RBAC permissions for the health progress application'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--recreate',
            action='store_true',
            help='Recreate all permissions (delete existing first)',
        )
    
    def handle(self, *args, **options):
        self.stdout.write('Setting up RBAC permissions...')
        
        # Define custom permissions for health progress system
        permissions = [
            # Analytics permissions
            ('view_analytics', 'Can view analytics data'),
            ('view_reports', 'Can view reports'),
            ('create_reports', 'Can create reports'),
            ('export_analytics', 'Can export analytics data'),
            
            # Health data permissions
            ('view_health_record', 'Can view health records'),
            ('edit_health_record', 'Can edit health records'),
            ('delete_health_record', 'Can delete health records'),
            ('view_sensitive_health_data', 'Can view sensitive health data'),
            
            # User management permissions
            ('manage_users', 'Can manage users'),
            ('view_user_profiles', 'Can view user profiles'),
            ('edit_user_profiles', 'Can edit user profiles'),
            ('delete_users', 'Can delete users'),
            
            # Admin functions
            ('admin_functions', 'Can access admin functions'),
            ('system_configuration', 'Can configure system settings'),
            ('security_management', 'Can manage security settings'),
            ('audit_access', 'Can access audit logs'),
            
            # Billing permissions
            ('billing_access', 'Can access billing information'),
            ('process_payments', 'Can process payments'),
            ('view_financial_reports', 'Can view financial reports'),
        ]
        
        # Get or create content type for custom permissions
        content_type, created = ContentType.objects.get_or_create(
            app_label='security_enhancements',
            model='rbacpermission'
        )
        
        if created:
            self.stdout.write(
                self.style.SUCCESS('Created content type for RBAC permissions')
            )
        
        # Create permissions
        created_count = 0
        for codename, name in permissions:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                content_type=content_type,
                defaults={'name': name}
            )
            
            if created:
                created_count += 1
                self.stdout.write(f'Created permission: {codename}')
            else:
                self.stdout.write(f'Permission already exists: {codename}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Created {created_count} new permissions')
        )
        
        # Create default roles
        self._create_default_roles()
        
        self.stdout.write(
            self.style.SUCCESS('RBAC permissions setup completed successfully!')
        )
    
    def _create_default_roles(self):
        """Create default roles with appropriate permissions"""
        
        roles_permissions = {
            'admin': [
                'manage_users', 'view_user_profiles', 'edit_user_profiles', 'delete_users',
                'admin_functions', 'system_configuration', 'security_management', 'audit_access',
                'view_analytics', 'view_reports', 'create_reports', 'export_analytics',
                'view_health_record', 'edit_health_record', 'delete_health_record', 'view_sensitive_health_data',
                'billing_access', 'process_payments', 'view_financial_reports'
            ],
            'healthcare_provider': [
                'view_health_record', 'edit_health_record', 'view_sensitive_health_data',
                'view_user_profiles', 'view_analytics', 'view_reports'
            ],
            'health_analyst': [
                'view_analytics', 'view_reports', 'create_reports', 'export_analytics',
                'view_health_record'
            ],
            'billing_manager': [
                'billing_access', 'process_payments', 'view_financial_reports',
                'view_user_profiles'
            ],
            'patient': [
                'view_health_record'  # Only their own records (handled by resource-level access)
            ],
            'support_staff': [
                'view_user_profiles', 'view_health_record'
            ]
        }
        
        for role_name, permission_codenames in roles_permissions.items():
            # Create or get the group
            group, created = Group.objects.get_or_create(name=role_name)
            
            if created:
                self.stdout.write(f'Created role: {role_name}')
            else:
                self.stdout.write(f'Role already exists: {role_name}')
            
            # Add permissions to the group
            permissions = Permission.objects.filter(
                codename__in=permission_codenames,
                content_type__app_label='security_enhancements'
            )
            
            group.permissions.set(permissions)
            self.stdout.write(f'Assigned {permissions.count()} permissions to {role_name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Created/updated {len(roles_permissions)} default roles')
        )