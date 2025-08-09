
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db.models import Q

class UsernameOrEmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            # Check if the input matches an email address
            if '@' in username:
                user = UserModel.objects.get(Q(email=username) | Q(username=username))
            else:
                # Assume it's a username
                user = UserModel.objects.get(Q(username=username) | Q(email=username))
        except UserModel.DoesNotExist:
            return None

        if user.check_password(password):
            return user
        return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
