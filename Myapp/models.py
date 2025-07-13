from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email address is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # hash password
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    )

    # Custom fields
    full_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    mobile_number = models.CharField(max_length=15, unique=True)
    email = models.EmailField(unique=True)
    home_number = models.CharField(max_length=100)
    ward_number = models.CharField(max_length=20)
    live_location = models.CharField(max_length=255, blank=True, null=True)

    # OTP verification
    otp = models.CharField(max_length=6, blank=True, null=True)
    is_verified = models.BooleanField(default=False)

    # Required by Django
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    # User manager and login configuration
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'mobile_number']

    def __str__(self):
        return self.email
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator

class Complaint(models.Model):
    CATEGORY_CHOICES = [
        ('electricity', 'Electricity'),
        ('water', 'Water'),
        ('garbage', 'Garbage'),
        ('other', 'Other'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    description = models.TextField()
    image = models.ImageField(upload_to='complaint_images/', blank=True, null=True)
    
    ward_number = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text="Enter a ward number between 1 and 10"
    )

    live_location = models.CharField(max_length=255)
    status = models.CharField(max_length=20, default='pending')  # admin will update this
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.full_name} - Ward {self.ward_number} - {self.category}"
