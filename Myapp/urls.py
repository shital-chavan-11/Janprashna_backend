from django.urls import path
from .views import register_user, verify_otp,custom_login_view,submit_complaint,my_complaints,update_complaint_status,logout_view,get_all_complaints

urlpatterns = [
    path('register/', register_user, name='register'),
    path('verify-otp/', verify_otp, name='verify-otp'),
    path('login/', custom_login_view, name='custom_login'),
    path('complaints/submit/', submit_complaint, name='submit_complaint'),
    path('mine/', my_complaints, name='my-complaints'),
     path('complaints/<int:complaint_id>/status/', update_complaint_status, name='update_complaint_status'),
      path('logout/', logout_view, name='logout'),
          path('complaints/', get_all_complaints, name='get_all_complaints'),
  
]
