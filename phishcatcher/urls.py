from django.contrib import admin
from django.urls import path
from detector import views

urlpatterns = [
    path('admin/', admin.site.urls),

    # 🔐 User authentication routes
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),

    # 🌐 App pages
    path('', views.home, name='home'),
    path('history/', views.view_history, name='history'),
    path('result/', views.view_result, name='result'),
    path('scan/', views.scan_url, name='scan_url'),
    path('api/scan/', views.api_scan, name='api_scan'),
]
