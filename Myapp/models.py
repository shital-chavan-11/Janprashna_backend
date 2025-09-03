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
from django.db import models
from django.utils import timezone

class Announcement(models.Model):
    TYPE_CHOICES = [
        ('welfare', 'Welfare'),
        ('educational', 'Educational'),
        ('other', 'Other'),
        ('commercial', 'Commercial'),
    ]

    title = models.CharField(max_length=255)
    message = models.TextField()
    announcement_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    ward_number = models.CharField(max_length=20)
    valid_until = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    file = models.FileField(upload_to='announcements_files/', blank=True, null=True)  # <-- now only user-provided

    def __str__(self):
        return f"{self.title} ({self.announcement_type})"
 

class Bill(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="bills"
    )
    title = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)  # e.g., 99999999.99
    bill_file = models.FileField(upload_to='bills/', blank=True, null=True)

    ward_number = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(10)],
        help_text="Enter a ward number between 1 and 10"
    )

    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.title} - ₹{self.amount} - Ward {self.ward_number}"
    
class Scheme(models.Model):
    SCHEME_TYPES = [
        ('Education', 'Education'),
        ('Health', 'Health'),
        ('Agriculture', 'Agriculture'),
        ('Employment', 'Employment'),
        ('Housing', 'Housing'),
        ('Other', 'Other'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    scheme_type = models.CharField(max_length=50, choices=SCHEME_TYPES)
    eligibility = models.TextField(help_text="Who is eligible for this scheme?")
    benefits = models.TextField(help_text="What benefits does this scheme provide?")
    required_documents = models.TextField(help_text="List of documents required")
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
from django.db import models
from django.utils.text import slugify

class Document(models.Model):
    # Basic information
    name = models.CharField(max_length=200, unique=True)  
    slug = models.SlugField(max_length=200, unique=True, blank=True)  
    # SEO-friendly URL, auto-generated from name

    # Required documents and process (comma-separated or JSON)
    required_documents = models.TextField()  
    process = models.TextField()  
    
    # Office information
    office_address = models.CharField(max_length=300)  
    office_contact = models.CharField(max_length=500)
    office_hours = models.CharField(max_length=100)  # Example: "Mon-Fri, 9 AM - 5 PM"
    
    # Optional image for card or detail page
    image = models.ImageField(upload_to='document_images/', blank=True, null=True)  

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def _str_(self):
        return self.name

    # Automatically generate slug from name
    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super(Document, self).save(*args, **kwargs)
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class UserQuery(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="queries")
    email = models.EmailField(null=True)  # User's email
    ward_number = models.CharField(max_length=10)  # Ward number
    question = models.TextField()  # User's question
    reply = models.TextField(blank=True, null=True)  # Admin's reply
    status = models.CharField(
        max_length=20,
        choices=[('Pending', 'Pending'), ('Answered', 'Answered')],
        default='Pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Query by {self.email} (Ward {self.ward_number})"