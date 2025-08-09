from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm, AuthenticationForm
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from utils.text_utils import strip_emojis
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
from django.core.exceptions import ValidationError
from django_otp.forms import OTPTokenForm
from django_otp import user_has_device
from .models import CustomUser, UserProfile, TwoFactorBackupToken, TwoFactorEmailToken

User = get_user_model()


class CustomPasswordResetForm(PasswordResetForm):
    """Custom password reset form that sends HTML emails"""
    
    def send_mail(self, subject_template_name, email_template_name,
                  context, from_email, to_email, html_email_template_name=None):
        """
        Send HTML email for password reset
        """
        # Render HTML template and strip emojis
        html_content = render_to_string(html_email_template_name or email_template_name, context)
        html_content = strip_emojis(html_content)
        
        # Render plain text subject and strip emojis
        subject = render_to_string(subject_template_name, context)
        subject = strip_emojis(''.join(subject.splitlines()))
        
        # Create plain text version
        from django.utils.html import strip_tags
        text_content = strip_emojis(strip_tags(html_content))
        
        # Create and send email
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email,
            to=[to_email]
        )
        
        # Attach HTML version
        email.attach_alternative(html_content, "text/html")
        email.send()
        
    def save(self, domain_override=None,
             subject_template_name='registration/password_reset_subject.txt',
             email_template_name='registration/password_reset_email.html',
             use_https=False, token_generator=default_token_generator,
             from_email=None, request=None, html_email_template_name=None,
             extra_email_context=None):
        """
        Generate a one-use only link for resetting password and send it to the user.
        """
        email = self.cleaned_data["email"]
        
        if not domain_override:
            # Use dynamic domain detection when available
            if request and getattr(settings, 'USE_DYNAMIC_DOMAIN', True):
                domain = request.get_host()
                # Use configured brand name
                site_name = getattr(settings, 'SITE_NAME', 'Perspective Stream')
            else:
                # Fallback to SITE_DOMAIN setting
                domain = getattr(settings, 'SITE_DOMAIN', 'techopolis.app')
                site_name = getattr(settings, 'SITE_NAME', 'Perspective Stream')
        else:
            site_name = domain = domain_override
        
        # Determine protocol based on environment and domain
        if not use_https:
            # Auto-detect HTTPS based on domain and debug mode
            if request and request.is_secure():
                use_https = True
            elif domain in ['localhost', '127.0.0.1'] or ':' in domain:  # Handle localhost with ports
                use_https = False
            elif (
                domain in [getattr(settings, 'SITE_DOMAIN', 'techopolis.app'), f"www.{getattr(settings, 'SITE_DOMAIN', 'techopolis.app')}"]
                and getattr(settings, 'FORCE_HTTPS_PRODUCTION', True)
            ):
                use_https = True
            else:
                use_https = False  # Default to HTTP for development/unknown domains
        
        email_field_name = User.get_email_field_name()
        for user in self.get_users(email):
            user_email = getattr(user, email_field_name)
            context = {
                'email': user_email,
                'domain': domain,
                'site_name': site_name,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'user': user,
                'token': token_generator.make_token(user),
                'protocol': 'https' if use_https else 'http',
                **(extra_email_context or {}),
            }
            self.send_mail(
                subject_template_name, email_template_name, context, from_email,
                user_email, html_email_template_name=html_email_template_name or email_template_name,
            )


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=30, required=False)
    last_name = forms.CharField(max_length=30, required=False)
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        if commit:
            user.save()
        return user


class ProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['bio', 'website', 'location', 'github_username', 'twitter_handle', 'profile_visibility', 'email_visibility']
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4}),
            'website': forms.URLInput(),
        }


# 2FA Forms

class TwoFactorSetupForm(forms.Form):
    """Form for choosing 2FA setup method"""
    
    METHOD_CHOICES = [
        ('totp', 'Authenticator App (Google Authenticator, Authy, etc.)'),
        ('email', 'Email Codes'),
    ]
    
    method = forms.ChoiceField(
        choices=METHOD_CHOICES,
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input',
            'role': 'radio',
            'aria-describedby': 'method-help'
        }),
        label='Choose your preferred two-factor authentication method:',
        help_text='Select the method you prefer for receiving your second authentication factor.'
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set TOTP as default
        self.fields['method'].initial = 'totp'


class TOTPSetupForm(forms.Form):
    """Form for TOTP setup"""
    
    token = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-lg text-center',
            'placeholder': '000000',
            'maxlength': '6',
            'pattern': '[0-9]{6}',
            'autocomplete': 'one-time-code',
            'aria-label': 'Six-digit verification code',
            'aria-describedby': 'token-help'
        }),
        label='Verification Code',
        help_text='Enter the 6-digit code from your authenticator app'
    )
    
    def __init__(self, user=None, device=None, *args, **kwargs):
        self.user = user
        self.device = device
        super().__init__(*args, **kwargs)
    
    def clean_token(self):
        token = self.cleaned_data.get('token')
        
        if not token:
            raise ValidationError('Please enter the verification code.')
        
        if not token.isdigit() or len(token) != 6:
            raise ValidationError('Please enter a valid 6-digit code.')
        
        # Verify the token with the device
        if self.device and not self.device.verify_token(token):
            raise ValidationError(
                'Invalid code. Please try again with a fresh code from your app.'
            )
        
        return token


class TwoFactorVerifyForm(forms.Form):
    """Form for 2FA verification during login"""
    
    METHOD_CHOICES = [
        ('totp', 'Authenticator App'),
        ('email', 'Email Code'),
        ('backup', 'Backup Code'),
    ]
    
    method = forms.ChoiceField(
        choices=METHOD_CHOICES,
        widget=forms.Select(attrs={
            'class': 'form-select',
            'aria-label': 'Authentication method'
        }),
        label='Authentication Method'
    )
    
    token = forms.CharField(
        max_length=8,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-lg text-center',
            'placeholder': 'Enter code',
            'autocomplete': 'one-time-code',
            'aria-label': 'Verification code'
        }),
        label='Code'
    )
    
    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        
        # Customize available methods based on user setup
        if user:
            available_methods = []
            
            # Check if user has TOTP device
            if user_has_device(user, confirmed=True):
                available_methods.append(('totp', 'Authenticator App'))
            
            # Email is always available if user has it enabled
            if user.two_factor_enabled:
                available_methods.append(('email', 'Email Code'))
            
            # Backup codes are available if user has unused ones
            if TwoFactorBackupToken.count_unused_tokens(user) > 0:
                available_methods.append(('backup', 'Backup Code'))
            
            if available_methods:
                self.fields['method'].choices = available_methods
                # Set default to TOTP if available, otherwise first available method
                if any(method[0] == 'totp' for method in available_methods):
                    self.fields['method'].initial = 'totp'
                else:
                    self.fields['method'].initial = available_methods[0][0]
    
    def clean(self):
        cleaned_data = super().clean()
        method = cleaned_data.get('method')
        token = cleaned_data.get('token')
        
        if not token:
            raise ValidationError('Please enter the verification code.')
        
        if method == 'totp':
            # Verify TOTP token
            from django_otp.plugins.otp_totp.models import TOTPDevice
            devices = TOTPDevice.objects.devices_for_user(self.user, confirmed=True)
            valid = any(device.verify_token(token) for device in devices)
            if not valid:
                raise ValidationError('Invalid authenticator code. Please try again.')
        
        elif method == 'email':
            # Verify email token
            if not TwoFactorEmailToken.verify_token(self.user, token):
                raise ValidationError('Invalid or expired email code. Please request a new one.')
        
        elif method == 'backup':
            # Verify backup token
            if not TwoFactorBackupToken.verify_token(self.user, token):
                raise ValidationError('Invalid backup code. Each code can only be used once.')
        
        return cleaned_data


class BackupCodesForm(forms.Form):
    """Form for generating backup codes"""
    
    confirm = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'role': 'checkbox'
        }),
        label='I have saved these backup codes in a safe place',
        help_text='You will not be able to see these codes again after leaving this page.'
    )


class DisableTwoFactorForm(forms.Form):
    """Form for disabling 2FA"""
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Current password',
            'aria-label': 'Current password'
        }),
        label='Confirm Password',
        help_text='Enter your current password to disable two-factor authentication.'
    )
    
    confirm = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'role': 'checkbox'
        }),
        label='I understand that disabling 2FA reduces my account security',
        help_text='Disabling 2FA will make your account less secure.'
    )
    
    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        
        if not password:
            raise ValidationError('Please enter your password.')
        
        if not self.user.check_password(password):
            raise ValidationError('Incorrect password.')
        
        return password


class CustomAuthenticationForm(AuthenticationForm):
    """Extended authentication form that handles 2FA"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Add accessibility attributes
        self.fields['username'].widget.attrs.update({
            'class': 'form-control form-control-lg',
            'placeholder': 'Email or username',
            'aria-label': 'Email or username',
            'autofocus': True
        })
        
        self.fields['password'].widget.attrs.update({
            'class': 'form-control form-control-lg',
            'placeholder': 'Password',
            'aria-label': 'Password'
        })
    
    def confirm_login_allowed(self, user):
        """Override to allow login even if 2FA is required - we'll handle it in views"""
        super().confirm_login_allowed(user)
        
        # Check if account is disabled
        if not user.is_active:
            raise ValidationError(
                'This account has been disabled.',
                code='inactive',
            ) 