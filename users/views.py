from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views.generic import TemplateView, ListView, DetailView, CreateView, UpdateView, DeleteView
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.urls import reverse_lazy, reverse
from django.utils import timezone
from .models import (CustomUser, UserProfile, EmailVerificationToken, 
                    TwoFactorBackupToken, TwoFactorEmailToken, LoginAttempt)
from .forms import (CustomUserCreationForm, ProfileForm, CustomPasswordResetForm,
                   TwoFactorSetupForm, TOTPSetupForm, TwoFactorVerifyForm,
                   BackupCodesForm, DisableTwoFactorForm, CustomAuthenticationForm)
from utils.email_service import email_service


class LoginView(auth_views.LoginView):
    template_name = 'users/login.html'
    form_class = CustomAuthenticationForm
    redirect_authenticated_user = True
    
    def form_valid(self, form):
        """Override to handle 2FA requirements"""
        user = form.get_user()
        # Ensure user is a CustomUser instance
        if not hasattr(user, 'two_factor_enabled'):
            try:
                user = CustomUser.objects.get(pk=user.pk)
            except CustomUser.DoesNotExist:
                pass
        
        # Log the login attempt
        two_factor_enabled = getattr(user, 'two_factor_enabled', False)
        LoginAttempt.objects.create(
            email=user.email,
            ip_address=self.request.META.get('REMOTE_ADDR', ''),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            status='success' if not two_factor_enabled else '2fa_required'
        )
        
        # Check if user has 2FA enabled
        if two_factor_enabled:
            # Store user ID in session for 2FA verification
            self.request.session['2fa_user_id'] = str(user.id)
            messages.info(
                self.request,
                'Please complete two-factor authentication to finish logging in.'
            )
            return redirect('users:2fa_login')
        # Regular login for users without 2FA
        return super().form_valid(form)
    
    def get_success_url(self):
        return reverse_lazy('users:dashboard')


class LogoutView(auth_views.LogoutView):
    next_page = reverse_lazy('home')


class RegisterView(CreateView):
    form_class = CustomUserCreationForm
    template_name = 'users/register.html'
    success_url = reverse_lazy('users:login')
    
    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.object
        
        # Create email verification token
        try:
            verification_token = EmailVerificationToken.create_for_user(user)
            print(f"Created verification token for {user.username}: {verification_token.token}")
            
            # Build verification URL
            verification_url = self.request.build_absolute_uri(
                reverse('users:verify_email', kwargs={'token': verification_token.token})
            )
            print(f"Built verification URL: {verification_url}")
            
            # Send verification email
            print(f"Attempting to send verification email to {user.email}")
            email_sent = email_service.send_email_verification(
                user=user,
                verification_url=verification_url,
                request=self.request
            )
            
            if email_sent:
                print(f"Verification email sent successfully to {user.email}")
                messages.success(
                    self.request, 
                    'Account created successfully! Please check your email to verify your account.'
                )
            else:
                print(f"Failed to send verification email to {user.email}")
                messages.warning(
                    self.request,
                    'Account created successfully! However, we could not send the verification email. You can request a new one from your account settings.'
                )
                
        except Exception as e:
            # Log the error for debugging
            print(f"Exception in registration email verification: {str(e)}")
            import traceback
            traceback.print_exc()
            
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to create verification token or send email for user {user.username if user else 'unknown'}: {str(e)}")
            
            messages.warning(
                self.request,
                'Account created successfully! However, there was an issue sending the verification email. You can request a new one from your account settings.'
            )
        
        return response


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'users/dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Basic user stats
        # Add Perspective Stream stats
        context.update({
            'followers_count': user.followers.count() if hasattr(user, 'followers') else 0,
            'following_count': user.profile.following.count() if hasattr(user, 'profile') else 0,
            'broadcasts_count': user.broadcasts.count() if hasattr(user, 'broadcasts') else 0,
            'stations_count': user.stations.count() if hasattr(user, 'stations') else 0,
            'streams_count': user.streams.count() if hasattr(user, 'streams') else 0,
        })
        
    # Removed all shortcut review functionality and legacy imports
        
        return context


class ProfileView(LoginRequiredMixin, DetailView):
    template_name = 'users/profile.html'
    context_object_name = 'profile_user'
    
    def get_object(self):
        return self.request.user


class ProfileEditView(LoginRequiredMixin, UpdateView):
    model = UserProfile
    form_class = ProfileForm
    template_name = 'users/profile_edit.html'
    success_url = reverse_lazy('users:profile')
    
    def get_object(self):
        profile, created = UserProfile.objects.get_or_create(user=self.request.user)
        return profile


class SettingsView(LoginRequiredMixin, TemplateView):
    template_name = 'users/settings.html'


class FavoritesView(LoginRequiredMixin, ListView):
    template_name = 'users/favorites.html'
    context_object_name = 'favorites'
    paginate_by = 20
    
    def get_queryset(self):
        return self.request.user.favorites.select_related('shortcut')


class NotificationsView(LoginRequiredMixin, TemplateView):
    template_name = 'users/notifications.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Redirect to the new notifications app view
        return context


class FollowingView(LoginRequiredMixin, ListView):
    template_name = 'users/following.html'
    context_object_name = 'following_users'
    paginate_by = 20
    
    def get_queryset(self):
        if hasattr(self.request.user, 'profile'):
            return self.request.user.profile.following.all()
        return CustomUser.objects.none()


class FollowersView(LoginRequiredMixin, ListView):
    template_name = 'users/followers.html'
    context_object_name = 'followers'
    paginate_by = 20
    
    def get_queryset(self):
        return self.request.user.followers.all()


class PublicProfileView(DetailView):
    model = CustomUser
    template_name = 'users/public_profile.html'
    context_object_name = 'profile_user'
    slug_field = 'username'
    slug_url_kwarg = 'username'


class GuidelinesView(TemplateView):
    template_name = 'users/guidelines.html'


class ContactView(TemplateView):
    template_name = 'users/contact.html'


class FeedbackView(TemplateView):
    template_name = 'users/feedback.html'


class AdminRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_authenticated and self.request.user.is_admin


# Password reset views using Django's built-in views
class PasswordResetView(auth_views.PasswordResetView):
    template_name = 'users/password_reset.html'
    form_class = CustomPasswordResetForm
    email_template_name = 'email/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    html_email_template_name = 'email/password_reset_email.html'
    success_url = reverse_lazy('users:password_reset_done')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['protocol'] = 'https' if self.request.is_secure() else 'http'
        context['domain'] = self.request.get_host()
        return context
    
    def form_valid(self, form):
        # Determine if we should use HTTPS
        use_https = self.request.is_secure()
        
        # Override for production domain - always use HTTPS for configured SITE_DOMAIN
        host = self.request.get_host()
        from django.conf import settings
        site_domain = getattr(settings, 'SITE_DOMAIN', 'techopolis.app')
        if host == site_domain or host == f'www.{site_domain}':
            use_https = True
        
        # Save the form and send email using email_service
        user_email = form.cleaned_data.get('email')
        from utils.email_service import email_service
        user = None
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            user = User.objects.get(email=user_email)
        except User.DoesNotExist:
            pass
        if user:
            # Generate token and uid
            from django.utils.http import urlsafe_base64_encode
            from django.utils.encoding import force_bytes
            from django.contrib.auth.tokens import default_token_generator
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_url = f"{'https' if use_https else 'http'}://{host}/users/reset/{uid}/{token}/"
            email_service.send_password_reset_email(user, token, uid, request=self.request)
        
        return super().form_valid(form)


class PasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = 'users/password_reset_done.html'


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = 'users/password_reset_confirm.html'
    success_url = reverse_lazy('users:password_reset_complete')


class PasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = 'users/password_reset_complete.html'


class PasswordChangeView(auth_views.PasswordChangeView):
    template_name = 'users/password_change.html'
    success_url = reverse_lazy('users:password_change_done')

    def form_valid(self, form):
        response = super().form_valid(form)
        from utils.email_service import email_service
        user = self.request.user
        ip_address = self.request.META.get('REMOTE_ADDR', None)
        email_service.send_password_changed_email(user, ip_address, request=self.request)
        return response


class PasswordChangeDoneView(auth_views.PasswordChangeDoneView):
    template_name = 'users/password_change_done.html'


# Function-based views
def verify_email(request, token):
    """Verify user email using verification token"""
    try:
        verification_token = EmailVerificationToken.objects.get(token=token)
        
        # Check if token is expired
        if verification_token.is_expired:
            messages.error(request, 'Verification link has expired. Please request a new one.')
            return redirect('users:login')
        
        # Check if token is already used
        if verification_token.is_used:
            messages.warning(request, 'This verification link has already been used.')
            return redirect('users:login')
        
        # Mark email as verified
        user = verification_token.user
        user.email_verified_at = timezone.now()
        user.save()
        
        # Mark token as used
        verification_token.mark_as_used()
        
        messages.success(request, 'Email verified successfully! You can now log in.')
        return redirect('users:login')
        
    except EmailVerificationToken.DoesNotExist:
        messages.error(request, 'Invalid verification link.')
        return redirect('users:login')


# Two-Factor Authentication Views

class TwoFactorSetupView(LoginRequiredMixin, TemplateView):
    """Main 2FA setup view - choose method"""
    template_name = 'users/2fa/setup.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        context.update({
            'form': TwoFactorSetupForm(),
            'requires_2fa': user.requires_2fa,
            'is_in_grace_period': user.is_in_2fa_grace_period,
            'days_left': user.days_left_in_grace_period,
            'backup_codes_count': TwoFactorBackupToken.count_unused_tokens(user),
        })
        
        return context
    
    def post(self, request, *args, **kwargs):
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            method = form.cleaned_data['method']
            if method == 'totp':
                return redirect('users:2fa_setup_totp')
            elif method == 'email':
                return redirect('users:2fa_setup_email')
        
        return self.get(request, *args, **kwargs)


class TOTPSetupView(LoginRequiredMixin, TemplateView):
    """TOTP (Authenticator app) setup view"""
    template_name = 'users/2fa/setup_totp.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Get or create TOTP device
        from django_otp.plugins.otp_totp.models import TOTPDevice
        devices = TOTPDevice.objects.devices_for_user(user, confirmed=False)
        
        if devices:
            device = devices[0]
        else:
            device = TOTPDevice.objects.create(
                user=user,
                name=f'{user.username}-totp',
                confirmed=False
            )
        
        # Generate QR code URL
        import qrcode
        import qrcode.image.svg
        from io import BytesIO
        import base64
        
        # Create provisioning URI
        provisioning_uri = device.config_url
        
        # Generate QR code with high error correction for easier scanning
        from qrcode.constants import ERROR_CORRECT_H
        qr = qrcode.QRCode(version=1, error_correction=ERROR_CORRECT_H, box_size=8, border=2)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create SVG image
        factory = qrcode.image.svg.SvgPathImage
        svg_img = qr.make_image(image_factory=factory)
        
        # Convert SVG to string
        svg_stream = BytesIO()
        svg_img.save(svg_stream)
        qr_code_svg = svg_stream.getvalue().decode()

        # Additionally create high-res PNG and encode as data URI for broad compatibility
        png_img = qr.make_image(fill_color="black", back_color="white")
        png_stream = BytesIO()
        png_img.save(png_stream, format="PNG")
        png_b64 = base64.b64encode(png_stream.getvalue()).decode("ascii")
        qr_code_data_uri = f"data:image/png;base64,{png_b64}"
        
        from django.conf import settings
        context.update({
            'form': TOTPSetupForm(user=user, device=device),
            'device': device,
            'secret_key': device.key,
            'qr_code_svg': qr_code_svg,
            'provisioning_uri': provisioning_uri,
            'issuer_name': getattr(settings, 'SITE_NAME', 'Perspective Stream'),
            'account_name': f"{user.username}@{getattr(settings, 'SITE_DOMAIN', 'techopolis.app')}",
            'qr_code_data_uri': qr_code_data_uri,
        })
        
        return context
    
    def post(self, request, *args, **kwargs):
        user = request.user
        
        # Get the device
        from django_otp.plugins.otp_totp.models import TOTPDevice
        devices = TOTPDevice.objects.devices_for_user(user, confirmed=False)
        
        if not devices:
            messages.error(request, 'TOTP device not found. Please start setup again.')
            return redirect('users:2fa_setup')
        
        device = devices[0]
        form = TOTPSetupForm(user=user, device=device, data=request.POST)
        
        if form.is_valid():
            # Confirm the device
            device.confirmed = True
            device.save()
            
            # Enable 2FA for user
            user.two_factor_enabled = True
            user.save()
            
            # Generate backup codes
            backup_codes = TwoFactorBackupToken.generate_tokens_for_user(user)
            
            # Send confirmation email
            email_service.send_2fa_enabled_email(user, 'totp', request)
            
            # Store backup codes in session to show them
            request.session['new_backup_codes'] = backup_codes
            
            messages.success(request, 'Two-factor authentication has been successfully enabled!')
            return redirect('users:2fa_backup_codes')
        
        return self.get(request, *args, **kwargs)


class EmailTwoFactorSetupView(LoginRequiredMixin, TemplateView):
    """Email-based 2FA setup view"""
    template_name = 'users/2fa/setup_email.html'
    
    def post(self, request, *args, **kwargs):
        user = request.user
        
        # Enable 2FA for user
        user.two_factor_enabled = True
        user.save()
        
        # Generate backup codes
        backup_codes = TwoFactorBackupToken.generate_tokens_for_user(user)
        
        # Send confirmation email
        email_service.send_2fa_enabled_email(user, 'email', request)
        
        # Store backup codes in session to show them
        request.session['new_backup_codes'] = backup_codes
        
        messages.success(request, 'Email-based two-factor authentication has been enabled!')
        return redirect('users:2fa_backup_codes')


class BackupCodesView(LoginRequiredMixin, TemplateView):
    """Display backup codes after 2FA setup"""
    template_name = 'users/2fa/backup_codes.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get backup codes from session (for new setup) or from database
        new_codes = self.request.session.get('new_backup_codes', [])
        existing_codes = TwoFactorBackupToken.count_unused_tokens(self.request.user)
        
        context.update({
            'backup_codes': new_codes,
            'is_new_setup': bool(new_codes),
            'existing_codes_count': existing_codes,
            'form': BackupCodesForm(),
        })
        
        return context
    
    def post(self, request, *args, **kwargs):
        form = BackupCodesForm(request.POST)
        if form.is_valid():
            # Clear the session
            if 'new_backup_codes' in request.session:
                del request.session['new_backup_codes']
            
            messages.success(request, 'Two-factor authentication setup is complete!')
            return redirect('users:settings')
        
        return self.get(request, *args, **kwargs)


class TwoFactorLoginView(TemplateView):
    """2FA verification during login"""
    template_name = 'users/2fa/verify.html'
    
    def dispatch(self, request, *args, **kwargs):
        # Check if user is in the middle of 2FA login process
        if not request.session.get('2fa_user_id'):
            messages.error(request, 'Invalid 2FA login session.')
            return redirect('users:login')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Get user from session
        user_id = self.request.session.get('2fa_user_id')
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            user = None
        
        if user:
            context.update({
                'form': TwoFactorVerifyForm(user=user),
                'user': user,
                'show_email_option': True,
                'backup_codes_available': TwoFactorBackupToken.count_unused_tokens(user) > 0,
            })
        
        return context
    
    def post(self, request, *args, **kwargs):
        user_id = request.session.get('2fa_user_id')
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            messages.error(request, 'Invalid 2FA session.')
            return redirect('users:login')
        
        if 'send_email_code' in request.POST:
            # Send email code with robust error handling and logging
            try:
                email_token = TwoFactorEmailToken.create_for_user(user)
                sent = email_service.send_2fa_email_code(user, email_token.token, request)
                if sent:
                    messages.success(request, 'Verification code sent to your email!')
                else:
                    messages.error(request, 'We could not send the email code. Please try again in a moment or use another method.')
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to send 2FA email code to {user.email if user else 'unknown'}: {str(e)}")
                messages.error(request, 'An error occurred while sending the email code. Please try again or use another method.')
            return self.get(request, *args, **kwargs)
        
        form = TwoFactorVerifyForm(user=user, data=request.POST)
        if form.is_valid():
            # Log the user in
            from django.contrib.auth import login
            login(request, user, backend='users.backends.UsernameOrEmailBackend')
            
            # Log successful 2FA
            LoginAttempt.objects.create(
                email=user.email,
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status='2fa_success',
                two_factor_method=form.cleaned_data['method']
            )
            
            # Clear 2FA session
            if '2fa_user_id' in request.session:
                del request.session['2fa_user_id']
            
            # Check if backup code was used
            if form.cleaned_data['method'] == 'backup':
                remaining_codes = TwoFactorBackupToken.count_unused_tokens(user)
                email_service.send_2fa_backup_code_used_email(user, remaining_codes, request)
                
                if remaining_codes <= 3:
                    messages.warning(
                        request, 
                        f'You have {remaining_codes} backup codes remaining. '
                        'Consider generating new ones soon.'
                    )
            
            messages.success(request, 'Successfully logged in!')
            return redirect('users:dashboard')
        
        context = self.get_context_data(**kwargs)
        context['form'] = form
        return self.render_to_response(context)


class DisableTwoFactorView(LoginRequiredMixin, TemplateView):
    """Disable 2FA view"""
    template_name = 'users/2fa/disable.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Check if user is required to have 2FA
        if user.requires_2fa:
            context['cannot_disable'] = True
            context['reason'] = 'Your account role requires two-factor authentication.'
        
        context.update({
            'form': DisableTwoFactorForm(user=user),
            'backup_codes_count': TwoFactorBackupToken.count_unused_tokens(user),
        })
        
        return context
    
    def post(self, request, *args, **kwargs):
        user = request.user
        
        # Check if user is required to have 2FA
        if user.requires_2fa:
            messages.error(request, 'You cannot disable 2FA as your account role requires it.')
            return redirect('users:settings')
        
        form = DisableTwoFactorForm(user=user, data=request.POST)
        if form.is_valid():
            # Disable 2FA
            user.two_factor_enabled = False
            user.save()
            
            # Delete all TOTP devices
            from django_otp.plugins.otp_totp.models import TOTPDevice
            TOTPDevice.objects.filter(user=user).delete()
            
            # Delete unused backup tokens
            TwoFactorBackupToken.objects.filter(user=user, is_used=False).delete()
            
            # Send notification email
            ip_address = request.META.get('REMOTE_ADDR', 'Unknown')
            email_service.send_2fa_disabled_email(user, ip_address, request)
            
            messages.success(request, 'Two-factor authentication has been disabled.')
            return redirect('users:settings')
        
        context = self.get_context_data(**kwargs)
        context['form'] = form
        return self.render_to_response(context)


@login_required
def resend_verification(request):
    """Resend email verification"""
    user = request.user
    
    # Check if email is already verified
    if user.is_email_verified:
        messages.info(request, 'Your email is already verified.')
        return redirect('users:dashboard')
    
    # Create new verification token
    try:
        verification_token = EmailVerificationToken.create_for_user(user)
        print(f"Created verification token for {user.username}: {verification_token.token}")
        
        # Build verification URL
        verification_url = request.build_absolute_uri(
            reverse('users:verify_email', kwargs={'token': verification_token.token})
        )
        print(f"Built verification URL: {verification_url}")
        
        # Send verification email
        print(f"Attempting to send verification email to {user.email}")
        email_sent = email_service.send_email_verification(
            user=user,
            verification_url=verification_url,
            request=request
        )
        
        if email_sent:
            print(f"Verification email sent successfully to {user.email}")
            messages.success(request, 'Verification email sent! Please check your inbox.')
        else:
            print(f"Failed to send verification email to {user.email}")
            messages.error(request, 'Failed to send verification email. Please try again later.')
            
    except Exception as e:
        # Log the error for debugging
        print(f"Exception in resend verification: {str(e)}")
        import traceback
        traceback.print_exc()
        
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to create verification token or send email for user {user.username if user else 'unknown'}: {str(e)}")
        
        messages.error(request, 'Failed to send verification email. Please try again later.')
    
    return redirect('users:settings')


@login_required
def follow_user(request, username):
    target_user = get_object_or_404(CustomUser, username=username)
    if request.user != target_user:
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        profile.following.add(target_user)
        messages.success(request, f'You are now following {target_user.username}')
    return redirect('users:public_profile', username=username)


@login_required
def unfollow_user(request, username):
    target_user = get_object_or_404(CustomUser, username=username)
    if hasattr(request.user, 'profile'):
        request.user.profile.following.remove(target_user)
        messages.success(request, f'You are no longer following {target_user.username}')
    return redirect('users:public_profile', username=username)


# Review Action Views for Dashboard
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.shortcuts import get_object_or_404

@require_POST
@csrf_exempt
def quick_approve_shortcut(request):
    """Quick approve a shortcut from dashboard"""
    if not (request.user.is_superuser or request.user.has_perm('shortcuts.change_shortcut')):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    # Shortcuts app not installed; disable endpoint gracefully
    return JsonResponse({'error': 'Shortcuts feature not available'}, status=404)

@require_POST
@csrf_exempt
def quick_reject_shortcut(request):
    """Quick reject a shortcut from dashboard"""
    if not (request.user.is_superuser or request.user.has_perm('shortcuts.change_shortcut')):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    return JsonResponse({'error': 'Shortcuts feature not available'}, status=404)

@require_POST
@csrf_exempt
def assign_to_me(request):
    """Assign a shortcut to current user for review"""
    if not (request.user.is_superuser or request.user.has_perm('shortcuts.change_shortcut')):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    return JsonResponse({'error': 'Shortcuts feature not available'}, status=404)


class MFAStatusView(LoginRequiredMixin, TemplateView):
    """MFA status and management view"""
    template_name = 'users/mfa_status.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Check for TOTP devices
        from django_otp.plugins.otp_totp.models import TOTPDevice
        totp_devices = TOTPDevice.objects.devices_for_user(user, confirmed=True)
        totp_device = totp_devices[0] if totp_devices else None
        
        # Check for active (unexpired, unused) email tokens
        email_tokens = TwoFactorEmailToken.objects.filter(
            user=user,
            is_used=False,
            expires_at__gt=timezone.now()
        ).exists()
        
        # Get backup codes count
        backup_codes_count = TwoFactorBackupToken.count_unused_tokens(user)
        
        context.update({
            'user': user,
            'totp_device': totp_device,
            'has_email_2fa': email_tokens,
            'backup_codes_count': backup_codes_count,
            'requires_mfa': user.requires_2fa,
            'is_in_grace_period': user.is_in_2fa_grace_period,
            'days_left': user.days_left_in_grace_period,
        })
        
        return context



