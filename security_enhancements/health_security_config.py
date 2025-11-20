"""
Security Configuration for Health Progress Admin Reports
Optimized to reduce false positives while maintaining security
"""

# Whitelist patterns for legitimate health report functionality
HEALTH_REPORT_WHITELIST_PATTERNS = [
    # Admin health report form fields
    r'firstname',
    r'lastname', 
    r'gender',
    r'age_min',
    r'age_max',
    r'date_from',
    r'date_to',
    r'health_index',
    
    # Health metrics and database fields
    r'bmi',
    r'fat_percent',
    r'visceral_fat',
    r'muscle_percent', 
    r'blood_pressure',
    r'cholesterol',
    r'triglycerides',
    r'recorded_at',
    r'user__profile',
    
    # Export and CRUD operations
    r'export=excel',
    r'section=',
    r'record_id',
    r'update_record',
    r'delete_record',
    
    # Django ORM and legitimate SQL context
    r'select_related',
    r'filter\(',
    r'order_by',
    r'Q\(',
    r'annotate',
    r'aggregate',
]

# Paths that should have reduced SQL injection sensitivity  
REDUCED_SENSITIVITY_PATHS = [
    r'/health/admin-report/',
    r'/health/record/\d+/update/',
    r'/health/record/\d+/delete/',
    r'/admin/',
    r'/health/report/',
    r'/health/status-report/',
]

# Override aggressive SQL patterns for health app context
HEALTH_APP_SQL_OVERRIDES = {
    # Allow legitimate Django ORM patterns
    'allow_select_related': True,
    'allow_filter_queries': True,
    'allow_health_metrics': True,
    'allow_export_params': True,
}