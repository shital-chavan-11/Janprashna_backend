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
        cache.set(data['email'], {**data, 'otp': otp}, timeout=60)

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

@api_view(['POST'])
@permission_classes([AllowAny])
def custom_login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"error": "Email and password are required"}, status=400)

    user = authenticate(request, username=email, password=password)
    if not user:
        return Response({"error": "Invalid credentials"}, status=400)

    refresh = RefreshToken.for_user(user)

    response = Response({
        "message": "Login successful",
        "is_superuser": user.is_superuser,
        "is_staff": user.is_staff,
        # tokens also in response for convenience/debugging
        "access_token": str(refresh.access_token),
        "refresh_token": str(refresh),
    })

    response.set_cookie(
        key="access_token",
        value=str(refresh.access_token),
        httponly=True,
        secure=False,      # False for local dev over HTTP
        samesite="Lax",    # Lax for local dev
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=str(refresh),
        httponly=True,
        secure=False,
        samesite="Lax",
        path="/",
    )

    return response

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
