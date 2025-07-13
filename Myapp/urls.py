from django.urls import path
from .views import register_user, verify_otp,custom_login_view,submit_complaint,my_complaints

urlpatterns = [
    path('register/', register_user, name='register'),
    path('verify-otp/', verify_otp, name='verify-otp'),
    path('login/', custom_login_view, name='custom_login'),
    path('complaints/submit/', submit_complaint, name='submit_complaint'),
    path('mine/', my_complaints, name='my-complaints'),
  
]
