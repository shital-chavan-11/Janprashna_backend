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

User = get_user_model()

@api_view(['POST'])
def custom_login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(request, username=email, password=password)

    if user is None:
        return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

    if not user.is_verified:
        return Response({"error": "Email not verified with OTP."}, status=status.HTTP_403_FORBIDDEN)

    # ✅ Generate access and refresh tokens
    refresh = RefreshToken.for_user(user)
    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'message': "Login successful"
    }, status=status.HTTP_200_OK)
