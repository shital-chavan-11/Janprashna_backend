from turtle import title
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.core.mail import send_mail
from django.http import JsonResponse
import json
import random
from .models import User

@csrf_exempt
def register_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        required_fields = [
            'full_name', 'gender', 'mobile_number', 'email',
            'home_number', 'ward_number', 'password', 'confirm_password'
        ]

        for field in required_fields:
            if not data.get(field):
                return JsonResponse({field: "This field is required."}, status=400)

        if data['password'] != data['confirm_password']:
            return JsonResponse({"error": "Passwords do not match."}, status=400)

        if User.objects.filter(email=data['email']).exists():
            return JsonResponse({"error": "Email already registered."}, status=400)

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # Store data temporarily in cache for 60 seconds
        cache.set(data['email'], {**data, 'otp': otp}, timeout=600)

        # Send email
        send_mail(
            subject='Your OTP Verification Code',
            message=f"Hello {data['full_name']}, your OTP is: {otp}",
            from_email='abhisheksavalgi601@gmail.com',  # your email
            recipient_list=[data['email']],
            fail_silently=False,
        )

        return JsonResponse({"message": "OTP sent to your email."}, status=200)
    else:
        return JsonResponse({"error": "Only POST method is allowed."}, status=405)



@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        email = data.get('email')
        otp_input = data.get('otp')

        if not email or not otp_input:
            return JsonResponse({"error": "Email and OTP are required."}, status=400)

        cached_data = cache.get(email)

        if not cached_data:
            return JsonResponse({"error": "OTP expired. Please register again."}, status=400)

        if cached_data['otp'] != otp_input:
            return JsonResponse({"error": "Invalid OTP."}, status=400)

        # Create the user
        user = User.objects.create_user(
            email=cached_data['email'],
            password=cached_data['password'],
            full_name=cached_data['full_name'],
            gender=cached_data['gender'],
            mobile_number=cached_data['mobile_number'],
            home_number=cached_data['home_number'],
            ward_number=cached_data['ward_number'],
            live_location=cached_data.get('live_location', ''),
            is_verified=True
        )

        cache.delete(email)

        return JsonResponse({"message": "User registered successfully!"}, status=201)
    else:
        return JsonResponse({"error": "Only POST method is allowed."}, status=405)
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def custom_login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"error": "Email and password are required"}, status=400)

    try:
        user = User.objects.get(email=email)
        if not user.check_password(password):
            return Response({"error": "Invalid credentials"}, status=400)
    except User.DoesNotExist:
        return Response({"error": "Invalid credentials"}, status=400)

    refresh = RefreshToken.for_user(user)

    response = Response({
        "message": "Login successful",
        "is_superuser": user.is_superuser,
        "is_staff": user.is_staff,
        "access_token": str(refresh.access_token),
        "refresh_token": str(refresh),
    })

    response.set_cookie(
        key="access_token",
        value=str(refresh.access_token),
        httponly=True,
        secure=True,      # True for HTTPS
        samesite="None",  # None for cross-site
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=str(refresh),
        httponly=True,
        secure=True,
        samesite="None",
        path="/",
    )

    return response


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError

@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_access_token(request):
    # Get refresh token from cookies
    refresh_token = request.COOKIES.get("refresh_token")
    if not refresh_token:
        return Response({"error": "Refresh token not provided"}, status=400)

    try:
        refresh = RefreshToken(refresh_token)
        new_access_token = str(refresh.access_token)
    except TokenError as e:
        return Response({"error": "Invalid refresh token"}, status=400)

    # Set new access token in cookie
    response = Response({"access_token": new_access_token})
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=False,  # change to True in production with HTTPS
        samesite="Lax",
        path="/",
    )

    return response

# ================= Imports =================
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.core.mail import send_mail
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from .authentication import CookieJWTAuthentication
import random
import json

# ================= Models =================
User = get_user_model()

# ================= Constants =================
OTP_EXPIRY_SECONDS = 600  # 10 minutes

# ================= Helpers =================
def _norm_email(e: str) -> str:
    return (e or "").strip().lower()

def _otp_key(prefix: str, email: str) -> str:
    return f"{prefix}:{_norm_email(email)}"

# ================= Forgot Password =================

@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_request(request):
    """ Step 1: Request OTP for forgot password """
    email = request.data.get("email")
    if not email:
        return JsonResponse({"error": "Email is required"}, status=400)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return JsonResponse({"error": "Email not found"}, status=404)

    otp = str(random.randint(100000, 999999))
    cache.set(_otp_key("fp", email), {"otp": otp, "verified": False}, timeout=OTP_EXPIRY_SECONDS)

    send_mail(
        subject="Your Password Reset OTP",
        message=f"Hello {user.full_name}, your OTP to reset password is: {otp}",
        from_email="abhisheksavalgi601@gmail.com",
        recipient_list=[email],
        fail_silently=False,
    )

    return JsonResponse({"message": "OTP sent to your email."}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_verify_otp(request):
    """ Step 2: Verify OTP """
    email = request.data.get("email")
    otp_input = request.data.get("otp")

    if not email or not otp_input:
        return JsonResponse({"error": "Email and OTP are required"}, status=400)

    key = _otp_key("fp", email)
    cached_data = cache.get(key)
    if not cached_data:
        return JsonResponse({"error": "OTP expired. Please request again."}, status=400)

    if cached_data.get("otp") != otp_input:
        return JsonResponse({"error": "Invalid OTP"}, status=400)

    # Mark OTP as verified
    cache.set(key, {"otp": cached_data["otp"], "verified": True}, timeout=OTP_EXPIRY_SECONDS)
    return JsonResponse({"message": "OTP verified successfully!"}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_reset(request):
    """ Step 3: Reset password after OTP verification """
    email = request.data.get("email")
    new_password = request.data.get("new_password")
    confirm_password = request.data.get("confirm_password")

    if not all([email, new_password, confirm_password]):
        return JsonResponse({"error": "All fields are required."}, status=400)

    if new_password != confirm_password:
        return JsonResponse({"error": "Passwords do not match."}, status=400)

    key = _otp_key("fp", email)
    cached_data = cache.get(key)
    if not cached_data or not cached_data.get("verified"):
        return JsonResponse({"error": "OTP not verified or expired."}, status=400)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found."}, status=404)

    user.password = make_password(new_password)
    user.save()
    cache.delete(key)

    return JsonResponse({"message": "Password reset successfully!"}, status=200)

# ================= Email Change =================

@api_view(["POST"])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def request_email_change(request):
    """ Request OTP for changing email """
    user = request.user
    new_email = request.data.get("email")

    if not new_email:
        return Response({"error": "New email is required"}, status=400)

    if new_email == user.email:
        return Response({"error": "New email must be different from current email"}, status=400)

    if User.objects.filter(email=new_email).exists():
        return Response({"error": "This email is already in use"}, status=400)

    otp = str(random.randint(100000, 999999))
    cache.set(_otp_key("ec", new_email), {"otp": otp, "user_id": user.id, "verified": False}, timeout=OTP_EXPIRY_SECONDS)

    send_mail(
        subject="Email Change OTP",
        message=f"Hello {user.full_name}, your OTP to change email is: {otp}",
        from_email="abhisheksavalgi601@gmail.com",
        recipient_list=[new_email],
        fail_silently=False,
    )

    return Response({"message": "OTP sent to new email. Please verify to update email."}, status=200)


@api_view(["POST"])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_email_otp(request):
    """ Verify OTP and update user email """
    user = request.user
    otp_input = request.data.get("otp")
    new_email = request.data.get("email")

    if not otp_input or not new_email:
        return Response({"error": "Email and OTP are required"}, status=400)

    key = _otp_key("ec", new_email)
    cached_data = cache.get(key)
    if not cached_data or cached_data.get("user_id") != user.id:
        return Response({"error": "OTP expired or invalid."}, status=400)

    if cached_data.get("otp") != otp_input:
        return Response({"error": "Invalid OTP"}, status=400)

    user.email = new_email
    user.save()
    cache.delete(key)

    return Response({"message": "Email updated successfully"}, status=200)
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Complaint
from .authentication import CookieJWTAuthentication

@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def submit_complaint(request):
    category = request.data.get('category')
    description = request.data.get('description')
    image = request.FILES.get('image')  # optional
    ward_number = request.data.get('ward_number')
    live_location = request.data.get('live_location')

    if not all([category, description, ward_number, live_location]):
        return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        ward_number = int(ward_number)
    except:
        return Response({'error': 'Ward number must be integer'}, status=status.HTTP_400_BAD_REQUEST)

    complaint = Complaint.objects.create(
        user=request.user,
        category=category,
        description=description,
        image=image,
        ward_number=ward_number,
        live_location=live_location
    )

    return Response({'message': 'Complaint submitted successfully', 'complaint_id': complaint.id}, status=status.HTTP_201_CREATED)

from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Complaint
from .authentication import CookieJWTAuthentication

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def my_complaints(request):
    complaints = Complaint.objects.filter(user=request.user).order_by('-created_at')
    data = [
        {
            'id': c.id,
            'category': c.category,
            'description': c.description,
            'image': request.build_absolute_uri(c.image.url) if c.image else None,
            'ward_number': c.ward_number,
            'live_location': c.live_location,
            'status': c.status,
            'created_at': c.created_at.isoformat()
        }
        for c in complaints
    ]
    return Response(data)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny  # allow even expired tokens
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

@api_view(['POST'])
@permission_classes([AllowAny])
def logout_view(request):
    refresh_token = request.COOKIES.get('refresh_token')
    if not refresh_token:
        return Response({"error": "No refresh token found."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = RefreshToken(refresh_token)
        token.blacklist()
    except TokenError:
        return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

    response = Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
    # Delete the auth cookies
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return response

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from .models import Complaint
from .authentication import CookieJWTAuthentication

# ✅ Admin: Get all complaints
@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated, IsAdminUser])
def get_all_complaints(request):
    complaints = Complaint.objects.all().order_by('-created_at')
    data = [
        {
            'id': comp.id,
            'user': getattr(comp.user, 'full_name', str(comp.user)),
            'category': comp.category,
            'description': comp.description,
            'image': request.build_absolute_uri(comp.image.url) if comp.image else None,
            'ward_number': comp.ward_number,
            'live_location': comp.live_location,
            'status': comp.status,
            'created_at': comp.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        for comp in complaints
    ]
    return Response(data, status=status.HTTP_200_OK)

# ✅ Admin: Update complaint status
@api_view(['PATCH'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated, IsAdminUser])
def update_complaint_status(request, complaint_id):
    try:
        complaint = Complaint.objects.get(id=complaint_id)
        new_status = request.data.get('status')
        if new_status not in ['pending', 'working', 'resolved', 'rejected']:
            return Response({'error': 'Invalid status.'}, status=status.HTTP_400_BAD_REQUEST)
        complaint.status = new_status
        complaint.save()
        return Response({'message': f'Status updated to {new_status}.'}, status=status.HTTP_200_OK)
    except Complaint.DoesNotExist:
        return Response({'error': 'Complaint not found.'}, status=status.HTTP_404_NOT_FOUND)


# myapp/views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

User = get_user_model()

@api_view(['GET'])
@permission_classes([AllowAny])
def me_view(request):
    token = request.COOKIES.get('access_token')
    if not token:
        return Response({"detail": "Authentication credentials were not provided."}, status=401)

    try:
        access = AccessToken(token)
        user_id = access.get('user_id')
    except (TokenError, InvalidToken):
        return Response({"detail": "Invalid or expired token."}, status=401)

    user = User.objects.filter(id=user_id).first()
    if not user:
        return Response({"detail": "User not found."}, status=401)

    return Response({
        "email": getattr(user, 'email', ''),
        "full_name": getattr(user, 'full_name', getattr(user, 'email', '')),
        "is_superuser": getattr(user, 'is_superuser', False),
        "is_staff": getattr(user, 'is_staff', False),
    }, status=200)
# views.py
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count
from django.db.models.functions import ExtractMonth
from datetime import datetime
from .models import Complaint
from .authentication import CookieJWTAuthentication

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def complaints_chart_data(request):
    year = datetime.now().year
    queryset = Complaint.objects.filter(created_at__year=year)

    # Group by month and status
    data = queryset.annotate(month=ExtractMonth('created_at')) \
                   .values('month', 'status') \
                   .annotate(count=Count('id')) \
                   .order_by('month')

    chart_data = {status: [0]*12 for status in ['pending', 'working', 'resolved', 'rejected']}
    for item in data:
        month_index = item['month'] - 1
        chart_data[item['status']][month_index] = item['count']

    return Response(chart_data)
import os
from django.conf import settings
from django.core.mail import EmailMessage
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from .models import Announcement, User
from .authentication import CookieJWTAuthentication  # adjust import if needed


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])  # allow file upload
def create_announcement(request):
    # ✅ Only admin can create
    if not request.user.is_staff:
        return Response({'detail': 'You do not have permission to perform this action.'},
                        status=status.HTTP_403_FORBIDDEN)

    title = request.data.get('title')
    message = request.data.get('message')
    announcement_type = request.data.get('announcement_type')
    ward_number = request.data.get('ward_number')
    valid_until = request.data.get('valid_until')  # optional date
    uploaded_file = request.FILES.get('file')

    if not all([title, message, announcement_type, ward_number]):
        return Response({'detail': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # ✅ Create announcement
    announcement = Announcement.objects.create(
        title=title,
        message=message,
        announcement_type=announcement_type,
        ward_number=ward_number,
        valid_until=valid_until if valid_until else None,
        file=uploaded_file
    )

    # ✅ Send email to all users in that ward
    # ✅ Send email to all users in that ward
    users = User.objects.filter(ward_number=ward_number, is_active=True)
    for user in users:
        email_body = (
            f"Hello {user.full_name},\n\n"
            f"A new {announcement_type.lower()} opportunity has been announced in your ward.\n\n"
            f"📢 Title: {title}\n"
            f"📁 Category: {announcement_type.capitalize()}\n"
            f"📍 Ward: {ward_number}\n"
            f"{'📅 Valid Until: ' + valid_until + '\n' if valid_until else ''}\n"
            f"📝 Description:\n{message}\n\n"
            f"Issued by: Department of Commerce\n\n"
            f"Please see the attached document for complete details.\n\n"
            f"Regards,\n"
            f"Nagar Panchayati"
        )

        email = EmailMessage(
            subject=f"Hello {user.full_name}, New {announcement_type.capitalize()} Announcement!",
            body=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.content_subtype = "plain"  # plain text email

        # ✅ Attach file from disk if present
        if announcement.file:
            email.attach_file(announcement.file.path)

        email.send(fail_silently=True)


    return Response({'detail': 'Announcement created and sent successfully.'}, status=status.HTTP_201_CREATED)

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def list_announcements(request):
    # Get the logged-in user's ward
    user_ward = getattr(request.user, "ward_number", None)

    if not user_ward:
        return Response({"detail": "User does not have a ward assigned."}, status=status.HTTP_400_BAD_REQUEST)

    # ✅ Fetch only announcements for that ward
    announcements = Announcement.objects.filter(ward_number=user_ward).order_by('-id')

    data = []
    for ann in announcements:
        data.append({
            "id": ann.id,
            "title": ann.title,
            "message": ann.message,
            "announcement_type": ann.announcement_type,
            "ward_number": ann.ward_number,
            "valid_until": ann.valid_until,
            "file_url": request.build_absolute_uri(ann.file.url) if ann.file else None,
            "created_at": ann.created_at if hasattr(ann, "created_at") else None,
        })

    return Response(data, status=status.HTTP_200_OK)
import os
from django.conf import settings
from django.core.mail import EmailMessage
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from .models import Announcement, User
from .authentication import CookieJWTAuthentication  # adjust import if needed


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])  # allow file upload
def create_announcement(request):
    # ✅ Only admin can create
    if not request.user.is_staff:
        return Response({'detail': 'You do not have permission to perform this action.'},
                        status=status.HTTP_403_FORBIDDEN)

    title = request.data.get('title')
    message = request.data.get('message')
    announcement_type = request.data.get('announcement_type')
    ward_number = request.data.get('ward_number')
    valid_until = request.data.get('valid_until')  # optional date
    uploaded_file = request.FILES.get('file')

    if not all([title, message, announcement_type, ward_number]):
        return Response({'detail': 'All fields are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # ✅ Create announcement
    announcement = Announcement.objects.create(
        title=title,
        message=message,
        announcement_type=announcement_type,
        ward_number=ward_number,
        valid_until=valid_until if valid_until else None,
        file=uploaded_file
    )

    # ✅ Send email to all users in that ward
    # ✅ Send email to all users in that ward
    users = User.objects.filter(ward_number=ward_number, is_active=True)
    for user in users:
        email_body = (
            f"Hello {user.full_name},\n\n"
            f"A new {announcement_type.lower()} opportunity has been announced in your ward.\n\n"
            f"📢 Title: {title}\n"
            f"📁 Category: {announcement_type.capitalize()}\n"
            f"📍 Ward: {ward_number}\n"
            f"{'📅 Valid Until: ' + valid_until + '\n' if valid_until else ''}\n"
            f"📝 Description:\n{message}\n\n"
            f"Issued by: Department of Commerce\n\n"
            f"Please see the attached document for complete details.\n\n"
            f"Regards,\n"
            f"Nagar Panchayati"
        )

        email = EmailMessage(
            subject=f"Hello {user.full_name}, New {announcement_type.capitalize()} Announcement!",
            body=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.content_subtype = "plain"  # plain text email

        # ✅ Attach file from disk if present
        if announcement.file:
            email.attach_file(announcement.file.path)

        email.send(fail_silently=True)


    return Response({'detail': 'Announcement created and sent successfully.'}, status=status.HTTP_201_CREATED)

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def list_announcements(request):
    # Get the logged-in user's ward
    user_ward = getattr(request.user, "ward_number", None)

    if not user_ward:
        return Response({"detail": "User does not have a ward assigned."}, status=status.HTTP_400_BAD_REQUEST)

    # ✅ Fetch only announcements for that ward
    announcements = Announcement.objects.filter(ward_number=user_ward).order_by('-id')

    data = []
    for ann in announcements:
        data.append({
            "id": ann.id,
            "title": ann.title,
            "message": ann.message,
            "announcement_type": ann.announcement_type,
            "ward_number": ann.ward_number,
            "valid_until": ann.valid_until,
            "file_url": request.build_absolute_uri(ann.file.url) if ann.file else None,
            "created_at": ann.created_at if hasattr(ann, "created_at") else None,
        })

    return Response(data, status=status.HTTP_200_OK)
import os
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import Bill, User
from .authentication import CookieJWTAuthentication
from email.mime.image import MIMEImage


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def create_bill(request):
    if not request.user.is_staff:
        return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

    title = request.data.get('title')
    amount = request.data.get('amount')
    ward_number = request.data.get('ward_number')
    user_id = request.data.get('user_id')
    uploaded_file = request.FILES.get('bill_file')

    if not title or not amount or (not ward_number and not user_id):
        return Response({'detail': 'Title, amount, and either ward_number or user_id are required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Determine recipients
    if user_id:
        try:
            users = [User.objects.get(id=user_id, is_active=True)]
        except User.DoesNotExist:
            return Response({'detail': f'User with ID {user_id} does not exist.'}, status=status.HTTP_404_NOT_FOUND)
    else:
        users = User.objects.filter(ward_number=ward_number, is_active=True)
        if not users.exists():
            return Response({'detail': f'No active users found in ward {ward_number}.'}, status=status.HTTP_404_NOT_FOUND)

    # Send bills & emails
    for user in users:
        Bill.objects.create(
            user=user,
            title=title,
            amount=amount,
            ward_number=ward_number if ward_number else user.ward_number,
            bill_file=uploaded_file
        )

        # HTML email body
        html_body = (
            f"<p>Hello {user.full_name},</p>"
            f"<p>A new bill has been generated for you.</p>"
            f"<p>🧾 <b>Title:</b> {title}<br>"
            f"💰 <b>Amount:</b> ₹{amount}<br>"
            f"📍 <b>Ward:</b> {user.ward_number}</p>"
            f"<p>Please check your account for more details.</p>"
            f"<p>Regards,<br>Nagar Panchayati</p>"
        )

        email = EmailMultiAlternatives(
            subject=f"New Bill: {title} (Ward {user.ward_number})",
            body=f"Hello {user.full_name}, A new bill has been generated. Title: {title}, Amount: ₹{amount}",  # fallback
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.attach_alternative(html_body, "text/html")

        # Embed image inline
        if uploaded_file:
            uploaded_file.seek(0)
            image_content = uploaded_file.read()
            subtype = uploaded_file.content_type.split('/')[-1]  # e.g., png, jpeg
            image = MIMEImage(image_content, _subtype=subtype)
            image.add_header('Content-ID', '<bill_image>')
            image.add_header('Content-Disposition', 'inline', filename=uploaded_file.name)
            email.attach(image)

            # Update HTML to reference the image
            html_body_with_image = html_body + f'<br><img src="cid:bill_image" alt="Bill Image">'
            email.attach_alternative(html_body_with_image, "text/html")

        email.send(fail_silently=False)  # False for debugging

    return Response({'detail': f'Bill created for {len(users)} user(s).'}, status=status.HTTP_201_CREATED)
@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_user_and_ward_bills(request):
    """
    Return all bills of the current user + all bills of other users in the same ward.
    """

    user = request.user

    # Step 1: Check if user has a ward number assigned
    if not hasattr(user, "ward_number") or not user.ward_number:
        return Response(
            {"detail": "Your ward number is not assigned."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Step 2: Current user's bills
    user_bills = Bill.objects.filter(user=user)

    # Step 3: All bills in the same ward excluding current user's bills
    ward_bills = Bill.objects.filter(ward_number=user.ward_number).exclude(user=user)

    # Helper function to convert bill to dictionary
    def bill_to_dict(bill):
        return {
            "id": bill.id,
            "title": bill.title,
            "amount": bill.amount,
            "ward_number": bill.ward_number,
            "user_id": bill.user.id if bill.user else None,
            "user_name": bill.user.full_name if bill.user else None,
            "bill_file": bill.bill_file.url if bill.bill_file else None,
            "created_at": bill.created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(bill, "created_at") else None,
        }

    # Step 4: Build response
    data = {
        "user_details": {
            "id": user.id,
            "full_name": user.full_name,
            "ward_number": user.ward_number,
        },
        "my_bills": [bill_to_dict(b) for b in user_bills],
        "ward_bills": [bill_to_dict(b) for b in ward_bills],
    }

    return Response(data, status=status.HTTP_200_OK)

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAdminUser])
def get_all_ward_bills(request):
    """
    Return all bills across all wards
    """
    bills=Bill.objects.all()
    def bill_to_dict(bill):
        return {
            "id": bill.id,
            "title": bill.title,
            "amount": bill.amount,
            "ward_number": bill.ward_number,
            "user_id": bill.user.id if bill.user else None,
            "user_name": bill.user.full_name if bill.user else None,
            "bill_file": bill.bill_file.url if bill.bill_file else None,
            "created_at": bill.created_at.strftime("%Y-%m-%d %H:%M:%S") if hasattr(bill, "created_at") else None,
        }

    data = {
        "all_bills": [bill_to_dict(b) for b in bills],
    }

    return Response(data, status=status.HTTP_200_OK)

@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def create_scheme(request):
    if not request.user.is_superuser:  # ✅ Only superuser can create scheme
        return Response(
            {'detail': 'You do not have permission to perform this action.'},
            status=status.HTTP_403_FORBIDDEN
        )

    title = request.data.get('title')
    description = request.data.get('description')
    scheme_type = request.data.get('scheme_type')
    eligibility = request.data.get('eligibility')
    benefits = request.data.get('benefits')
    required_documents = request.data.get('required_documents')
    start_date = request.data.get('start_date')
    end_date = request.data.get('end_date')

    # ✅ Required validation
    if not title or not description or not scheme_type:
        return Response(
            {'detail': 'Title, description, and scheme_type are required.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # ✅ Create the scheme
    scheme = Scheme.objects.create(
        title=title,
        description=description,
        scheme_type=scheme_type,
        eligibility=eligibility,
        benefits=benefits,
        required_documents=required_documents,
        start_date=start_date,
        end_date=end_date if end_date else None
    )

    return Response(
        {
            'detail': 'Scheme created successfully.',
            'scheme_id': scheme.id,
            'title': scheme.title,
        },
        status=status.HTTP_201_CREATED
    )
@api_view(['PUT'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def update_scheme(request, pk):
    if not request.user.is_superuser:  # ✅ Only superuser can update
        return Response(
            {'detail': 'You do not have permission to perform this action.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        scheme = Scheme.objects.get(pk=pk)
    except Scheme.DoesNotExist:
        return Response(
            {'detail': 'Scheme not found.'},
            status=status.HTTP_404_NOT_FOUND
        )

    # ✅ Update fields from request data
    scheme.title = request.data.get('title', scheme.title)
    scheme.description = request.data.get('description', scheme.description)
    scheme.scheme_type = request.data.get('scheme_type', scheme.scheme_type)
    scheme.eligibility = request.data.get('eligibility', scheme.eligibility)
    scheme.benefits = request.data.get('benefits', scheme.benefits)
    scheme.required_documents = request.data.get('required_documents', scheme.required_documents)
    scheme.start_date = request.data.get('start_date', scheme.start_date)
    scheme.end_date = request.data.get('end_date', scheme.end_date)

    scheme.save()

    return Response(
        {'detail': 'Scheme updated successfully.'},
        status=status.HTTP_200_OK
    )
# ================== Update Bill (All Fields) ==================
@api_view(['PUT'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAdminUser])
def update_bill(request, pk):
    """
    Update all fields of a specific bill.
    Only the owner of the bill or a superuser can update.
    """
    try:
        bill = Bill.objects.get(pk=pk)
    except Bill.DoesNotExist:
        return Response({'detail': 'Bill not found.'}, status=status.HTTP_404_NOT_FOUND)

    # ✅ Permission check
    if bill.user != request.user and not request.user.is_superuser:
        raise PermissionDenied("You do not have permission to update this bill.")

    # ✅ Extract data
    title = request.data.get("title", bill.title)
    amount = request.data.get("amount", bill.amount)
    ward_number = request.data.get("ward_number", bill.ward_number)
    new_file = request.FILES.get("bill_file")

    # ✅ Update fields
    bill.title = title
    bill.amount = amount
    bill.ward_number = ward_number
    if new_file:  # only replace if a new file is uploaded
        bill.bill_file = new_file

    bill.save()

    return Response(
        {
            "detail": "Bill updated successfully.",
            "bill_id": bill.id,
            "title": bill.title,
            "amount": str(bill.amount),
            "ward_number": bill.ward_number,
            "bill_file": bill.bill_file.url if bill.bill_file else None,
            "updated_at": bill.created_at,
        },
        status=status.HTTP_200_OK,
    )


# ================== Delete Bill ==================
@api_view(['DELETE'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_bill(request, pk):
    """
    Delete a bill.
    Only the owner of the bill or a superuser can delete.
    """
    try:
        bill = Bill.objects.get(pk=pk)
    except Bill.DoesNotExist:
        return Response({'detail': 'Bill not found.'}, status=status.HTTP_404_NOT_FOUND)

    # ✅ Permission check
    if bill.user != request.user and not request.user.is_superuser:
        raise PermissionDenied("You do not have permission to delete this bill.")

    bill.delete()

    return Response({'detail': 'Bill deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

@api_view(['DELETE'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_scheme(request, pk):
    if not request.user.is_superuser:  # ✅ Only superuser can delete
        return Response(
            {'detail': 'You do not have permission to perform this action.'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        scheme = Scheme.objects.get(pk=pk)
    except Scheme.DoesNotExist:
        return Response(
            {'detail': 'Scheme not found.'},
            status=status.HTTP_404_NOT_FOUND
        )

    scheme.delete()
    return Response(
        {'detail': 'Scheme deleted successfully.'},
        status=status.HTTP_204_NO_CONTENT
    )

  # your custom auth if any

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_schemes(request):
    """
    Get all schemes for authenticated users.
    """
    schemes = Scheme.objects.all().order_by('-created_at')  # latest first

    scheme_list = []
    for scheme in schemes:
        scheme_list.append({
            "id": scheme.id,
            "title": scheme.title,
            "description": scheme.description,
            "scheme_type": scheme.scheme_type,
            "eligibility": scheme.eligibility,
            "benefits": scheme.benefits,
            "required_documents": scheme.required_documents,
            "start_date": scheme.start_date.strftime("%Y-%m-%d"),
            "end_date": scheme.end_date.strftime("%Y-%m-%d") if scheme.end_date else None,
            "created_at": scheme.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        })

    return Response(scheme_list, status=status.HTTP_200_OK)
# views.py
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.db.models import Count
from .models import Complaint
from .authentication import CookieJWTAuthentication  # make sure your auth class is imported

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def complaint_stats(request):
    """
    Return complaint counts and percentages by status for authenticated users.
    """
    total_complaints = Complaint.objects.count()

    # Count complaints by status
    status_counts_qs = Complaint.objects.values('status').annotate(count=Count('status'))

    # Initialize counts with default 0
    status_dict = {
        'pending': 0,
        'resolved': 0,
        'rejected': 0,
        'working': 0
    }

    for item in status_counts_qs:
        status_dict[item['status']] = item['count']

    # Calculate percentages
    percentages = {status: (count / total_complaints) * 100 if total_complaints > 0 else 0
                   for status, count in status_dict.items()}

    data = {
        'total_complaints': total_complaints,
        'status_counts': status_dict,
        'percentages': percentages
    }

    return Response(data, status=status.HTTP_200_OK)
from django.db.models import Count
from django.db.models.functions import ExtractMonth
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Announcement
from .authentication import CookieJWTAuthentication  # your JWT auth

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def monthwise_announcement_stats(request):
    """
    Returns month-wise count of announcements for each type.
    """
    # Annotate month from created_at and group by month and type
    qs = Announcement.objects.annotate(month=ExtractMonth('created_at')) \
        .values('month', 'announcement_type') \
        .annotate(count=Count('id')) \
        .order_by('month', 'announcement_type')

    # Prepare nested dictionary: {month: {type: count}}
    data = {}
    for item in qs:
        month = item['month']
        a_type = item['announcement_type']
        count = item['count']

        if month not in data:
            data[month] = {t[0]: 0 for t in Announcement.TYPE_CHOICES}  # initialize all types
        data[month][a_type] = count

    return Response(data, status=200)
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt  # put this **after DRF decorators**
def get_profile(request):
    user = request.user
    return Response({
        "full_name": user.full_name,
        "gender": user.gender,
        "mobile_number": user.mobile_number,
        "email": user.email,
        "home_number": user.home_number,
        "ward_number": user.ward_number,
        "live_location": user.live_location,
    })
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

  

@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([CookieJWTAuthentication])  # ✅ check tokens in cookies
def auth_check(request):
    """
    Simple endpoint to check if the user is authenticated.
    Frontend calls this to verify login status.
    """
    user = request.user
    if user and user.is_authenticated:
        return Response(
            {"authenticated": True, "username": user.email},
            status=status.HTTP_200_OK
        )
    return Response(
        {"authenticated": False},
        status=status.HTTP_401_UNAUTHORIZED
    )

from datetime import datetime
from django.db.models import Count, Sum
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import Announcement, Bill, Scheme, Complaint
from .authentication import CookieJWTAuthentication  # 👈 if you're using cookie JWT


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([CookieJWTAuthentication])
def monthly_stats(request):
    """
    Returns counts of announcements, bills, schemes, and complaints
    for the current month only.
    """

    # Current year & month
    now = datetime.now()
    current_year = now.year
    current_month = now.month

    # Announcements by type (only current month)
    announcements = (
        Announcement.objects.filter(created_at__year=current_year, created_at__month=current_month)
        .values("announcement_type")
        .annotate(count=Count("id"))
    )

    # Complaints by status (only current month)
    complaints = (
        Complaint.objects.filter(created_at__year=current_year, created_at__month=current_month)
        .values("status")
        .annotate(count=Count("id"))
    )

    # Schemes (count, grouped by type)
    schemes = (
        Scheme.objects.filter(created_at__year=current_year, created_at__month=current_month)
        .values("scheme_type")
        .annotate(count=Count("id"))
    )

    # Bills (count + total amount for the month)
    bills = Bill.objects.filter(created_at__year=current_year, created_at__month=current_month)
    bills_count = bills.count()
    bills_total_amount = bills.aggregate(total=Sum("amount"))["total"] or 0

    return Response(
        {
            "month": now.strftime("%B %Y"),
            "announcements": list(announcements),
            "complaints": list(complaints),
            "schemes": list(schemes),
            "bills": {
                "count": bills_count,
                "total_amount": bills_total_amount,
            },
        },
        status=status.HTTP_200_OK,
    )
@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([CookieJWTAuthentication])
def latest_announcements(request):
    """
    Returns the latest announcements, sorted by creation date (most recent first).
    """
    # Get the latest 5 announcements
    latest = Announcement.objects.order_by("-created_at")[:5]

    # Prepare response data
    announcements_list = [
        {
            "id": a.id,
            "title": a.title,
            "message": a.message,
            "announcement_type": a.announcement_type,
            "ward_number": a.ward_number,
            "valid_until": a.valid_until,
            "created_at": a.created_at,
            "file": a.file.url if a.file else None
        }
        for a in latest
    ]

    return Response(
        {
            "latest_announcements": announcements_list,
            "count": len(announcements_list)
        },
        status=status.HTTP_200_OK
    )
 

# ================== Get All Announcements ==================
@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_all_announcements(request):
    announcements = Announcement.objects.all().order_by('-created_at')
    data = []

    for ann in announcements:
        data.append({
            "id": ann.id,
            "title": ann.title,
            "message": ann.message,
            "announcement_type": ann.announcement_type,
            "ward_number": ann.ward_number,
            "valid_until": ann.valid_until,
            "created_at": ann.created_at,
            "file": ann.file.url if ann.file else None,
        })

    return Response({"announcements": data}, status=status.HTTP_200_OK)


# ================== Update Announcement ==================
@api_view(['PUT'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def update_announcement(request, pk):
    try:
        ann = Announcement.objects.get(pk=pk)
    except Announcement.DoesNotExist:
        return Response({"detail": "Announcement not found"}, status=status.HTTP_404_NOT_FOUND)

    # ✅ Only allow admin users to update
    if not request.user.is_superuser:
        raise PermissionDenied("You do not have permission to update this announcement.")

    title = request.data.get("title", ann.title)
    message = request.data.get("message", ann.message)
    announcement_type = request.data.get("announcement_type", ann.announcement_type)
    ward_number = request.data.get("ward_number", ann.ward_number)
    valid_until = request.data.get("valid_until", ann.valid_until)
    file = request.FILES.get("file")

    # ✅ Update fields
    ann.title = title
    ann.message = message
    ann.announcement_type = announcement_type
    ann.ward_number = ward_number
    ann.valid_until = valid_until
    if file:
        ann.file = file

    ann.save()

    return Response({
        "detail": "Announcement updated successfully",
        "id": ann.id,
        "title": ann.title,
        "message": ann.message,
        "announcement_type": ann.announcement_type,
        "ward_number": ann.ward_number,
        "valid_until": ann.valid_until,
        "file": ann.file.url if ann.file else None,
    }, status=status.HTTP_200_OK)


# ================== Delete Announcement ==================
@api_view(['DELETE'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_announcement(request, pk):
    try:
        ann = Announcement.objects.get(pk=pk)
    except Announcement.DoesNotExist:
        return Response({"detail": "Announcement not found"}, status=status.HTTP_404_NOT_FOUND)

    # ✅ Only allow admin users to delete
    if not request.user.is_superuser:
        raise PermissionDenied("You do not have permission to delete this announcement.")

    ann.delete()
    return Response({"detail": "Announcement deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
#document section
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from Myapp.models import Document

def document_detail_api(request, id): 
    doc = get_object_or_404(Document, id=id)

    data = {
        "id": doc.id,
        "name": doc.name,
        "required_documents": doc.required_documents,
        "process": doc.process,
        "office_address": doc.office_address,
        "office_contact": doc.office_contact,
        "office_hours": doc.office_hours,
        "image": doc.image.url if doc.image else None
    }
    return JsonResponse(data)
# Myapp/views.py
from django.http import JsonResponse
from Myapp.models import Document

def documents_list_api(request):
    docs = Document.objects.all()
    data = [{"id": doc.id, "name": doc.name} for doc in docs]
    return JsonResponse(data, safe=False)
# Myapp/views.py
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from .models import Document
from .authentication import CookieJWTAuthentication

 
@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAdminUser])
def add_document_api(request):
    """
    API to add a new Document (superuser only) without using serializer.
    """
    # Required fields
    name = request.data.get('name')
    required_documents = request.data.get('required_documents')
    process = request.data.get('process')
    office_address = request.data.get('office_address')
    office_contact = request.data.get('office_contact')
    office_hours = request.data.get('office_hours')
    image = request.FILES.get('image')  # optional

    # Validation
    missing_fields = []
    for field_name, value in [
        ('name', name),
        ('required_documents', required_documents),
        ('process', process),
        ('office_address', office_address),
        ('office_contact', office_contact),
        ('office_hours', office_hours),
    ]:
        if not value:
            missing_fields.append(field_name)

    if missing_fields:
        return Response(
            {"error": f"Missing required fields: {', '.join(missing_fields)}"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Check if document with same name exists
    if Document.objects.filter(name=name).exists():
        return Response(
            {"error": "Document with this name already exists."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Create and save document
    document = Document(
        name=name,
        required_documents=required_documents,
        process=process,
        office_address=office_address,
        office_contact=office_contact,
        office_hours=office_hours,
        image=image
    )
    document.save()

    return Response(
        {
            "message": "Document added successfully",
            "document": {
                "id": document.id,
                "name": document.name,
                "slug": document.slug,
                "required_documents": document.required_documents,
                "process": document.process,
                "office_address": document.office_address,
                "office_contact": document.office_contact,
                "office_hours": document.office_hours,
                "image": document.image.url if document.image else None
            }
        },
        status=status.HTTP_201_CREATED
    )
import traceback
from django.core.mail import send_mail
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from .models import UserQuery
from .authentication import CookieJWTAuthentication


# -----------------------------
# Submit a doubt (any authenticated user)
# -----------------------------
@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def submit_doubt(request):
    email = request.data.get("email")
    ward_number = request.data.get("ward_number")
    question_text = request.data.get("doubt")  # incoming JSON key can remain 'doubt'

    if not all([email, ward_number, question_text]):
        return Response(
            {"error": "Email, ward_number, and doubt are required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        ward_number = int(ward_number)
    except ValueError:
        return Response(
            {"error": "Ward number must be an integer"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # ✅ Use correct field name: question
    query = UserQuery.objects.create(
        user=request.user,
        email=email,
        ward_number=ward_number,
        question=question_text,
        status="Pending"
    )

    return Response({
        "message": "Doubt submitted successfully",
        "query_id": query.id,
        "user": getattr(request.user, "full_name", request.user.email),
        "email": query.email,
        "ward_number": query.ward_number,
        "doubt": query.question,
        "status": query.status,
    }, status=status.HTTP_201_CREATED)

@api_view(["POST"])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAdminUser])
def reply_doubt(request, doubt_id):
    try:
        reply_text = request.data.get("reply")
        if not reply_text:
            return Response({"error": "Reply text is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            query = UserQuery.objects.get(id=doubt_id)
        except UserQuery.DoesNotExist:
            return Response({"error": "Query not found"}, status=status.HTTP_404_NOT_FOUND)

        query.reply = reply_text
        query.status = "Answered"
        query.save()

        user_email = query.email
        if user_email:
            subject = "Reply to your doubt"
            message = f"""
Hello {user_email},

Your doubt (Ward {query.ward_number}):
{query.question}

Admin reply:
{reply_text}

Thank you for using JanPrshna!
"""
            send_mail(subject, message, "admin@janprshna.com", [user_email], fail_silently=False)

        return Response({
            "message": "Reply sent successfully",
            "query_id": query.id,
            "email": query.email,
            "ward_number": query.ward_number,
            "doubt": query.question,
            "reply": reply_text,
            "status": query.status,
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response(
            {"error": str(e), "trace": traceback.format_exc()},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

# -----------------------------

# -----------------------------
from django.shortcuts import render
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from .models import UserQuery
from .authentication import CookieJWTAuthentication

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAdminUser])
def get_all_doubts(request):
    queries = UserQuery.objects.all().order_by('-created_at')
    data = []
    for q in queries:
        data.append({
            "id": q.id,
            "email": q.email,
            "ward_number": q.ward_number,
            "doubt": q.question,
            "reply": q.reply,
            "status": q.status,
            "created_at": q.created_at,
        })
    return Response(data)
#chart for complaints 
# views.py
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db.models import Count
from django.db.models.functions import ExtractMonth
from datetime import datetime
from .models import Complaint
from .authentication import CookieJWTAuthentication

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def complaints_chart_data(request):
    year = datetime.now().year
    queryset = Complaint.objects.filter(created_at__year=year)

    # Group by month and status
    data = queryset.annotate(month=ExtractMonth('created_at')) \
                   .values('month', 'status') \
                   .annotate(count=Count('id')) \
                   .order_by('month')

    chart_data = {status: [0]*12 for status in ['pending', 'working', 'resolved', 'rejected']}
    for item in data:
        month_index = item['month'] - 1
        chart_data[item['status']][month_index] = item['count']

    return Response(chart_data)
#profile 
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .authentication import CookieJWTAuthentication  # ✅ custom cookie-based JWT auth

@api_view(["GET"])
@authentication_classes([CookieJWTAuthentication])  # ✅ read JWT from cookies
@permission_classes([IsAuthenticated])
def get_profile(request):
    """
    API to fetch logged-in user profile details
    """
    user = request.user
    data = {
        "id": user.id,
        "full_name": getattr(user, "full_name", ""),
        "email": user.email,
        "mobile_number": getattr(user, "mobile_number", ""),
        "gender": getattr(user, "gender", ""),
        "ward_number": getattr(user, "ward_number", ""),
        "home_number": getattr(user, "home_number", ""),
        "live_location": getattr(user, "live_location", ""),
    }
    return Response(data)




from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.utils import timezone
import random
from .authentication import CookieJWTAuthentication

@api_view(["PUT"])
@authentication_classes([CookieJWTAuthentication])  
@permission_classes([IsAuthenticated])  
def update_profile(request):
    """
    API to update logged-in user profile details
    """
    user = request.user
    data = request.data

    # Update normal fields
    user.full_name = data.get("full_name", user.full_name)
    user.mobile_number = data.get("mobile_number", user.mobile_number)
    user.gender = data.get("gender", user.gender)
    user.ward_number = data.get("ward_number", user.ward_number)
    user.home_number = data.get("home_number", user.home_number)
    user.live_location = data.get("live_location", user.live_location)

    # Handle email change
    new_email = data.get("email")
    if new_email and new_email != user.email:
        if user.pending_email and user.pending_email != new_email:
            return Response({"error": "You have already requested an email change. Please verify OTP first."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=new_email).exists():
            return Response({"error": "This email is already in use"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP for email change
        otp = str(random.randint(100000, 999999))
        user.pending_email = new_email
        user.email_otp = otp
        user.email_otp_created_at = timezone.now()
        
        # Send OTP to new email
        send_mail(
            subject="Email Change OTP",
            message=f"Hello {user.full_name}, your OTP to change email is: {otp}",
            from_email="abhisheksavalgi601@gmail.com",
            recipient_list=[new_email],
            fail_silently=False,
        )

    user.save()

    response_data = {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,  # current email, will change after OTP verification
        "mobile_number": user.mobile_number,
        "gender": user.gender,
        "ward_number": user.ward_number,
        "home_number": user.home_number,
        "live_location": user.live_location,
    }

    if new_email and new_email != user.email:
        response_data["message"] = "OTP sent to new email. Please verify to update email."

    return Response(response_data, status=status.HTTP_200_OK)


from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.utils import timezone
import random
from .authentication import CookieJWTAuthentication
from .models import User

@api_view(["POST"])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def request_email_change(request):
    """
    Request OTP for changing email
    """
    user = request.user
    new_email = request.data.get("email")

    if not new_email:
        return Response({"error": "New email is required"}, status=status.HTTP_400_BAD_REQUEST)

    if new_email == user.email:
        return Response({"error": "New email must be different from current email"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=new_email).exists():
        return Response({"error": "This email is already in use"}, status=status.HTTP_400_BAD_REQUEST)

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    user.pending_email = new_email
    user.email_otp = otp
    user.email_otp_created_at = timezone.now()
    user.save()

    # Send OTP to new email
    send_mail(
        subject="Email Change OTP",
        message=f"Hello {user.full_name}, your OTP to change email is: {otp}",
        from_email="abhisheksavalgi601@gmail.com",
        recipient_list=[new_email],
        fail_silently=False,
    )

    return Response({"message": "OTP sent to new email. Please verify to update email."}, status=status.HTTP_200_OK)
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .authentication import CookieJWTAuthentication

@api_view(["POST"])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_email_otp(request):
    """
    Verify OTP and update user email
    """
    user = request.user
    otp_input = request.data.get("otp")

    if not otp_input:
        return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)

    # Check if OTP exists and not expired (10 min validity)
    if not user.email_otp or not user.pending_email:
        return Response({"error": "No pending email change request"}, status=status.HTTP_400_BAD_REQUEST)

    time_diff = timezone.now() - user.email_otp_created_at
    if time_diff.total_seconds() > 600:  # 10 minutes
        user.pending_email = None
        user.email_otp = None
        user.email_otp_created_at = None
        user.save()
        return Response({"error": "OTP expired. Please request again"}, status=status.HTTP_400_BAD_REQUEST)

    if otp_input != user.email_otp:
        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

    # Update email
    user.email = user.pending_email
    user.pending_email = None
    
    user.email_otp = None
    user.email_otp_created_at = None
    user.save()

    return Response({"message": "Email updated successfully"}, status=status.HTTP_200_OK)