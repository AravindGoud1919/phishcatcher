from django.urls import path
from . import views

urlpatterns = [
    path('scan/', views.scan_url, name='scan_url'),              # For main app scans
    path('api/scan/', views.api_scan, name='api_scan'),          # For Chrome extension
    path('history/', views.view_history, name='view_history'),   # To view scan history
]
