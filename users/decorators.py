from functools import wraps
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django_otp.decorators import otp_required as django_otp_required
from django_otp import user_has_device
import logging

logger = logging.getLogger(__name__)


def mfa_required(view_func=None, *, redirect_field_name='next', login_url=None):
    """
    Decorator that requires the user to have MFA enabled and be verified.
    Similar to @otp_required but with custom logic for our implementation.
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required(login_url=login_url, redirect_field_name=redirect_field_name)
        def _wrapped_view(request, *args, **kwargs):
            user = request.user
            
            # Check if user has MFA enabled
            if not user.mfa_enabled or not user_has_device(user):
                logger.info(f"MFA required but not enabled for user {user.username}")
                messages.warning(
                    request,
                    'This action requires two-factor authentication. Please set up MFA first.'
                )
                return redirect('users:mfa_setup')
            
            # Check if user is verified (has completed MFA for this session)
            if not user.is_verified():
                logger.info(f"MFA verification required for user {user.username}")
                messages.info(
                    request,
                    'Please verify your identity with your two-factor authentication device.'
                )
                # Redirect to OTP verification (django-otp handles this)
                return redirect(f"{reverse('users:login')}?{redirect_field_name}={request.get_full_path()}")
            
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    
    if view_func:
        return decorator(view_func)
    return decorator


def role_mfa_enforced(allowed_roles=None):
    """
    Decorator that enforces MFA for specific roles.
    Used for views that should be protected for admin/moderator roles.
    """
    if allowed_roles is None:
        allowed_roles = ['admin', 'super_admin', 'moderator']
    
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            user = request.user
            
            # Check if user has the required role
            user_role = user.role.name if user.role else None
            if user_role not in allowed_roles:
                messages.error(
                    request,
                    'You do not have permission to access this area.'
                )
                return redirect('users:dashboard')
            
            # If user requires MFA enforcement, redirect to setup
            if user.requires_mfa_enforcement:
                logger.info(f"MFA enforcement triggered for {user.username} accessing protected view")
                messages.warning(
                    request,
                    'Your account role requires two-factor authentication. '
                    'Please complete the setup to continue.'
                )
                return redirect('users:mfa_setup')
            
            # If user has MFA enabled, require verification
            if user.mfa_enabled and user_has_device(user):
                if not user.is_verified():
                    messages.info(
                        request,
                        'Please verify your identity with your two-factor authentication device.'
                    )
                    return redirect(f"{reverse('users:login')}?next={request.get_full_path()}")
            
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    
    return decorator


def admin_mfa_required(view_func=None):
    """
    Shortcut decorator for admin-only views that require MFA.
    """
    def decorator(view_func):
        return role_mfa_enforced(['admin', 'super_admin'])(view_func)
    
    if view_func:
        return decorator(view_func)
    return decorator


def moderator_mfa_required(view_func=None):
    """
    Shortcut decorator for moderator views that require MFA.
    """
    def decorator(view_func):
        return role_mfa_enforced(['admin', 'super_admin', 'moderator'])(view_func)
    
    if view_func:
        return decorator(view_func)
    return decorator
