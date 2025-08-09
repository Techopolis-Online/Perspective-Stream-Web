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
