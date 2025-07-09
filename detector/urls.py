from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # main page
    path('api/scan/', views.api_scan, name='api_scan'),
    path('scan/', views.scan_url, name='scan_url'),
    path('history/', views.view_history, name='view_history'),
    path('result/', views.view_result, name='view_result'),
]
