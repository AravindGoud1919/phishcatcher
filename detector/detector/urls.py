from django.urls import path
from . import views

urlpatterns = [
    path('', views.scan_url, name='scan_url'),
    path('history/', views.view_history, name='view_history'),
    path('api/scan/', views.api_scan, name='api_scan'),  # for chrome extension
]
