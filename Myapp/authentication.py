from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import exceptions

class CookieJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication that reads the access token from cookies.
    """
    def authenticate(self, request):
        raw_token = request.COOKIES.get("access_token")  # Must match cookie name
        if not raw_token:
            return None  # Let DRF handle 401 if required

        try:
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
            return (user, validated_token)
        except Exception:
            raise exceptions.AuthenticationFailed("Invalid or expired token")
