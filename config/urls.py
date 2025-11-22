"""
URL configuration for healthprogressV6 project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('health/', include('health_app.urls')),
    
    path('', RedirectView.as_view(url='/accounts/', permanent=False)),
]

# Advanced Security Monitoring (optional - only if enabled)
if hasattr(settings, 'ENABLE_ADVANCED_SECURITY') and settings.ENABLE_ADVANCED_SECURITY:
    urlpatterns.append(path('security/', include('security_enhancements.urls')))

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
