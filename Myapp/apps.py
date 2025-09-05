from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.contrib.auth.models import User
import os

def create_admin_user(sender, **kwargs):
    ADMIN_USERNAME = "admin"
    ADMIN_EMAIL = "shitalchavan@gmail.com"
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "defaultpassword")

    if not User.objects.filter(username=ADMIN_USERNAME).exists():
        User.objects.create_superuser(username=ADMIN_USERNAME,
                                      email=ADMIN_EMAIL,
                                      password=ADMIN_PASSWORD)

class MyappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Myapp'

    def ready(self):
        post_migrate.connect(create_admin_user, sender=self)
