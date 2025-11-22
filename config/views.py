"""
Custom error handlers for HealthProgress
"""
from django.shortcuts import render
from django.http import HttpResponseNotFound, HttpResponseServerError, HttpResponseForbidden, HttpResponseBadRequest


def custom_404(request, exception=None):
    """Custom 404 error page"""
    return HttpResponseNotFound(render(request, 'errors/404.html', status=404))


def custom_500(request):
    """Custom 500 error page"""
    return HttpResponseServerError(render(request, 'errors/500.html', status=500))


def custom_403(request, exception=None):
    """Custom 403 error page"""
    return HttpResponseForbidden(render(request, 'errors/403.html', status=403))


def custom_400(request, exception=None):
    """Custom 400 error page"""
    return HttpResponseBadRequest(render(request, 'errors/400.html', status=400))
