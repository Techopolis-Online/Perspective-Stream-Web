from django.contrib.auth import SESSION_KEY, get_user_model


class SessionUserPKCompatibilityMiddleware:
    """
    Clears stale auth sessions created under a different AUTH_USER_MODEL PK type.

    Scenario: Switched from int PK (auth.User) to UUID PK (users.CustomUser).
    Old sessions store an integer in session[SESSION_KEY] (e.g., "1"), which
    Django will try to cast to UUID and raise ValidationError on access.

    This middleware runs before AuthenticationMiddleware and, if the stored
    auth user id cannot be parsed as the current model's PK type, it flushes the
    session so the request becomes anonymous and redirects will work instead of erroring.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            if SESSION_KEY in request.session:
                user_model = get_user_model()
                pk_field = user_model._meta.pk
                raw_id = request.session.get(SESSION_KEY)
                # Attempt to coerce the stored id into the current PK type
                try:
                    pk_field.to_python(raw_id)
                except Exception:
                    # Invalid for current PK type — clear session to avoid UUID errors
                    request.session.flush()
        except Exception:
            # Never block the request due to middleware errors
            pass

        return self.get_response(request)
"""
2FA Enforcement Middleware
"""

from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.contrib import messages
from django.utils import timezone
from django.http import HttpResponse
import logging

logger = logging.getLogger(__name__)


class TwoFactorEnforcementMiddleware:
    """
    Middleware to enforce 2FA for privileged users (admins, moderators, reviewers)
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        return response
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        """Process view to enforce 2FA requirements"""
        # Skip enforcement for anonymous users
        if not request.user.is_authenticated:
            return None
        
        # Get the current URL name
        try:
            current_url = resolve(request.path_info).url_name
            current_namespace = resolve(request.path_info).namespace
        except:
            return None
        
        # Skip enforcement for 2FA setup pages and logout
        if current_namespace == 'users' and current_url in [
            '2fa_setup', '2fa_setup_totp', '2fa_setup_email', '2fa_backup_codes',
            '2fa_verify', '2fa_login', 'logout', '2fa_disable', 'verify_email',
            'resend_verification'
        ]:
            return None
        
        # Skip enforcement for static files, API, and admin pages
        if (request.path.startswith('/static/') or 
            request.path.startswith('/media/') or
            request.path.startswith('/api/') or
            request.path.startswith('/admin/')):
            return None
        
        user = request.user
        
        # Check if user requires 2FA but doesn't have it enabled
        if user.requires_2fa and not user.two_factor_enabled:
            # Check if grace period has expired
            if not user.is_in_2fa_grace_period:
                # Force user to set up 2FA
                messages.error(
                    request, 
                    'You must enable two-factor authentication to access this system. '
                    'Your 14-day grace period has expired.'
                )
                return redirect('users:2fa_setup')
            else:
                # Show warning about upcoming deadline
                days_left = user.days_left_in_grace_period
                if days_left <= 7:  # Show warning in last 7 days
                    messages.warning(
                        request,
                        f'You have {days_left} days left to set up two-factor authentication. '
                        f'After that, you will not be able to access the system without 2FA.'
                    )
        
        return None
