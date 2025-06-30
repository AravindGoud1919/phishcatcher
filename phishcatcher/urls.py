from django.contrib import admin
from django.urls import path
from detector import views
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
     path('', include('detector.urls')),
    path('', views.scan_url, name='home'),
    path('scan/', views.scan_url, name='scan'),
    #path('result/', views.result_view, name='result_view'),  # ✅ NEW
    path('api/scan/', views.api_scan, name='api_scan'),
    path('history/', views.view_history, name='view_history'),
]
