from django.urls import path
from .views import register_user, verify_otp,custom_login_view

urlpatterns = [
    path('register/', register_user, name='register'),
    path('verify-otp/', verify_otp, name='verify-otp'),
    path('login/', custom_login_view, name='custom_login'),
  
]
