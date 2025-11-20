"""
Health App URL Configuration
"""
from django.urls import path
from . import views

app_name = 'health_app'

urlpatterns = [
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('add/', views.add_metric_view, name='add_metric'),
    path('history/', views.history_view, name='history'),
    path('record/<int:record_id>/update/', views.update_record_view, name='update_record'),
    path('report/', views.health_report_view, name='health_report'),
    path('status-report/', views.health_status_report_view, name='health_status_report'),
    path('admin-report/', views.admin_health_report_view, name='admin_health_report'),
    path('record/<int:record_id>/delete/', views.delete_record_view, name='delete_record'),
]
