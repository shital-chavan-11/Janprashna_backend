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
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

# Get the custom user model
User = get_user_model()

@api_view(['POST'])
def custom_login_view(request):
    """
    Custom login view that authenticates the user using email and password,
    checks if the user is verified, and returns JWT access & refresh tokens.
    """

    # Get email and password from request body
    email = request.data.get('email')
    password = request.data.get('password')

    # Check if both email and password are provided
    if not email or not password:
        return Response(
            {"error": "Email and password are required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Authenticate user using Django's built-in method
    user = authenticate(request, username=email, password=password)

    # If authentication fails
    if user is None:
        return Response(
            {"error": "Invalid credentials."},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # Optional: Check if the user has verified their email with OTP
    if not user.is_verified:
        return Response(
            {"error": "Email not verified with OTP."},
            status=status.HTTP_403_FORBIDDEN
        )

    # Generate refresh and access tokens using SimpleJWT
    refresh = RefreshToken.for_user(user)

    # Return tokens to the frontend (store them in localStorage or cookies)
    return Response({
        'refresh': str(refresh),                      # Long-lived token (can be used to get new access token)
        'access': str(refresh.access_token),          # Short-lived token (used for authenticated requests)
        'message': "Login successful"
    }, status=status.HTTP_200_OK)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Complaint

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def submit_complaint(request):
    try:
        category = request.data.get('category')
        description = request.data.get('description')
        image = request.FILES.get('image')  # optional
        ward_number = request.data.get('ward_number')
        live_location = request.data.get('live_location')

        if not all([category, description, ward_number, live_location]):
            return Response({'error': 'Missing required fields.'}, status=status.HTTP_400_BAD_REQUEST)

        complaint = Complaint.objects.create(
            user=request.user,
            category=category,
            description=description,
            image=image,
            ward_number=int(ward_number),
            live_location=live_location
        )

        return Response({'message': 'Complaint submitted successfully.', 'complaint_id': complaint.id}, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import Complaint

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_complaints(request):
    complaints = Complaint.objects.filter(user=request.user).order_by('-created_at')
    
    data = [
        {
            'id': comp.id,
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
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from rest_framework import status as http_status
from .models import Complaint

@api_view(['PATCH'])
@permission_classes([IsAdminUser])
def update_complaint_status(request, complaint_id):
    try:
        complaint = Complaint.objects.get(id=complaint_id)
        new_status = request.data.get('status')

        if new_status not in ['pending', 'working', 'resolved', 'rejected']:
            return Response({'error': 'Invalid status. Must be pending, working, resolved, or rejected.'},
                            status=http_status.HTTP_400_BAD_REQUEST)

        complaint.status = new_status
        complaint.save()

        return Response({'message': f'Status updated to {new_status}.'}, status=http_status.HTTP_200_OK)

    except Complaint.DoesNotExist:
        return Response({'error': 'Complaint not found.'}, status=http_status.HTTP_404_NOT_FOUND)
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response({"message": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)

    except TokenError:
        return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
