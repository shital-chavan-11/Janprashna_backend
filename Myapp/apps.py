from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.contrib.auth import get_user_model
import os

class MyappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Myapp'

    def ready(self):
        post_migrate.connect(create_admin_user, sender=self)

def create_admin_user(sender, **kwargs):
    User = get_user_model()

    ADMIN_EMAIL = "shitalchavan@gmail.com"
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "defaultpassword")

    # Only create superuser if it doesn't exist
    if not User.objects.filter(email=ADMIN_EMAIL).exists():
        User.objects.create_superuser(
            email=ADMIN_EMAIL,
            password=ADMIN_PASSWORD
        )
