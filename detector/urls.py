# detector/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.scan_url, name='scan_url'),
    path('api/scan/', views.api_scan, name='api_scan'),
    path('history/', views.view_history, name='view_history'),
    path('result/', views.view_result, name='view_result'),  # ✅ New route for shareable result
]
