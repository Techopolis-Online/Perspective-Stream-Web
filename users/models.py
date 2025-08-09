import uuid
import secrets
import string
from datetime import timedelta
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.utils import timezone
from cryptography.fernet import Fernet


class Role(models.Model):
    """User roles with different permission levels"""
    ROLE_CHOICES = [
        ('standard', 'Standard User'),
        ('verified_contributor', 'Verified Contributor'),
        ('moderator', 'Moderator'),
        ('admin', 'Administrator'),
        ('super_admin', 'Super Administrator'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    description = models.TextField(blank=True)
    permissions = models.JSONField(default=dict, help_text="Role permissions as JSON")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.get_name_display()


class CustomUser(AbstractUser):
    """Extended user model based on spec requirements"""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
        ('banned', 'Banned'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    username = models.CharField(max_length=30, unique=True, db_index=True)
    full_name = models.CharField(max_length=100, blank=True)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    

    # Override groups and user_permissions to avoid reverse accessor clash
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    # iOS Device Information
    device_type = models.CharField(max_length=20, blank=True, choices=[
        ('iphone', 'iPhone'),
        ('ipad', 'iPad'),
        ('mac', 'Mac'),
        ('apple_watch', 'Apple Watch'),
    ])
    ios_version = models.CharField(max_length=20, blank=True)
    
    # 2FA fields
    two_factor_enabled = models.BooleanField(default=False)
    two_factor_enforced_at = models.DateTimeField(null=True, blank=True, help_text="When 2FA enforcement started for this user")
    two_factor_grace_period_ends = models.DateTimeField(null=True, blank=True, help_text="When the 14-day grace period ends")
    backup_tokens_generated_at = models.DateTimeField(null=True, blank=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    @property  
    def is_email_verified(self):
        """Check if user's email is verified (renamed to avoid conflict with django-otp)"""
        return self.email_verified_at is not None
    
    @property
    def is_moderator(self):
        return self.role and self.role.name in ['moderator', 'admin', 'super_admin']
    
    @property
    def is_admin(self):
        return self.role and self.role.name in ['admin', 'super_admin']
    
    @property
    def is_reviewer(self):
        """Check if user is a reviewer (moderator, admin, or super_admin)"""
        return self.is_superuser or self.is_moderator
    
    @property
    def requires_2fa(self):
        """Check if user is required to have 2FA enabled"""
        return (
            self.is_superuser or 
            self.is_reviewer or 
            (self.role and self.role.name in ['moderator', 'admin', 'super_admin'])
        )
    
    @property
    def is_in_2fa_grace_period(self):
        """Check if user is still in the 14-day grace period for 2FA"""
        if not self.requires_2fa or self.two_factor_enabled:
            return False
        
        if not self.two_factor_grace_period_ends:
            return False
            
        return timezone.now() < self.two_factor_grace_period_ends
    
    @property
    def days_left_in_grace_period(self):
        """Get days remaining in 2FA grace period"""
        if not self.is_in_2fa_grace_period:
            return 0
        
        remaining = self.two_factor_grace_period_ends - timezone.now()
        return max(0, remaining.days)
    
    def start_2fa_enforcement(self):
        """Start the 14-day grace period for 2FA enforcement"""
        if not self.requires_2fa:
            return False
        
        now = timezone.now()
        self.two_factor_enforced_at = now
        self.two_factor_grace_period_ends = now + timedelta(days=14)
        self.save()
        return True


class TwoFactorBackupToken(models.Model):
    """Recovery/backup codes for 2FA"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='backup_tokens')
    token_hash = models.CharField(max_length=255, unique=True)
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['created_at']
    
    def __str__(self):
        return f"Backup token for {self.user.username}"
    
    @classmethod
    def generate_tokens_for_user(cls, user, count=10):
        """Generate a set of backup tokens for a user"""
        import hashlib
        
        # Clear existing unused tokens
        cls.objects.filter(user=user, is_used=False).delete()
        
        tokens = []
        plain_tokens = []
        
        for _ in range(count):
            # Generate a secure random token
            plain_token = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            plain_tokens.append(plain_token)
            
            # Hash the token for storage
            token_hash = hashlib.sha256(plain_token.encode()).hexdigest()
            
            tokens.append(cls(user=user, token_hash=token_hash))
        
        # Bulk create tokens
        cls.objects.bulk_create(tokens)
        
        # Update user's backup tokens generation timestamp
        user.backup_tokens_generated_at = timezone.now()
        user.save()
        
        return plain_tokens
    
    @classmethod
    def verify_token(cls, user, token):
        """Verify and consume a backup token"""
        import hashlib
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        try:
            backup_token = cls.objects.get(
                user=user,
                token_hash=token_hash,
                is_used=False
            )
            
            # Mark as used
            backup_token.is_used = True
            backup_token.used_at = timezone.now()
            backup_token.save()
            
            return True
        except cls.DoesNotExist:
            return False
    
    @classmethod
    def count_unused_tokens(cls, user):
        """Count remaining unused tokens for user"""
        return cls.objects.filter(user=user, is_used=False).count()


class TwoFactorEmailToken(models.Model):
    """Email-based 2FA tokens as alternative to TOTP"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='email_2fa_tokens')
    token = models.CharField(max_length=6)  # 6-digit code
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Email 2FA token for {self.user.username}"
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    @classmethod
    def create_for_user(cls, user):
        """Create a new email 2FA token for user"""
        # Delete any existing unused tokens
        cls.objects.filter(user=user, is_used=False).delete()
        
        # Generate 6-digit token
        token = ''.join(secrets.choice(string.digits) for _ in range(6))
        
        # Create token with 5-minute expiry
        expires_at = timezone.now() + timedelta(minutes=5)
        
        return cls.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )
    
    @classmethod
    def verify_token(cls, user, token):
        """Verify and consume an email 2FA token"""
        try:
            email_token = cls.objects.get(
                user=user,
                token=token,
                is_used=False
            )
            
            if email_token.is_expired:
                return False
            
            # Mark as used
            email_token.is_used = True
            email_token.used_at = timezone.now()
            email_token.save()
            
            return True
        except cls.DoesNotExist:
            return False


class UserProfile(models.Model):
    """Extended user profile information"""
    PRIVACY_CHOICES = [
        ('public', 'Public'),
        ('private', 'Private'),
        ('friends_only', 'Friends Only'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=100, blank=True)
    website = models.URLField(blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    
    # Social media links
    twitter_handle = models.CharField(max_length=50, blank=True)
    github_username = models.CharField(max_length=50, blank=True)
    
    # Privacy settings
    profile_visibility = models.CharField(max_length=20, choices=PRIVACY_CHOICES, default='public')
    email_visibility = models.CharField(max_length=20, choices=PRIVACY_CHOICES, default='private')
    activity_visibility = models.BooleanField(default=True)
    
    # Preferences stored as JSON
    privacy_settings = models.JSONField(default=dict)
    preferences = models.JSONField(default=dict)
    notification_preferences = models.JSONField(default=dict)
    
    # Community features
    following = models.ManyToManyField(CustomUser, related_name='followers', blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username}'s Profile"


class UserSession(models.Model):
    """Track user sessions for security and analytics"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sessions')
    token_hash = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Session for {self.user.username}"
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at


class LoginAttempt(models.Model):
    """Track login attempts for security"""
    ATTEMPT_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('blocked', 'Blocked'),
        ('2fa_required', '2FA Required'),
        ('2fa_success', '2FA Success'),
        ('2fa_failed', '2FA Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    status = models.CharField(max_length=20, choices=ATTEMPT_CHOICES)
    failure_reason = models.CharField(max_length=100, blank=True)
    two_factor_method = models.CharField(max_length=20, blank=True, choices=[
        ('totp', 'TOTP App'),
        ('email', 'Email Code'),
        ('backup', 'Backup Code'),
    ])
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.status.title()} login attempt for {self.email}"


class EmailVerificationToken(models.Model):
    """Email verification tokens for new users"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='verification_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Email verification token for {self.user.email}"
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def mark_as_used(self):
        self.is_used = True
        self.save()
    
    @classmethod
    def create_for_user(cls, user):
        # Delete any existing tokens for this user
        cls.objects.filter(user=user, is_used=False).delete()
        
        # Create new token with 24-hour expiry
        expires_at = timezone.now() + timedelta(hours=24)
        return cls.objects.create(user=user, expires_at=expires_at)


# Signal to automatically create user profiles and handle 2FA enforcement
from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create a UserProfile when a user is created"""
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=CustomUser)
def handle_2fa_enforcement(sender, instance, created, **kwargs):
    """Handle 2FA enforcement for privileged users"""
    if created and instance.requires_2fa:
        # Start 2FA enforcement grace period for new privileged users
        instance.start_2fa_enforcement()
    elif not created:
        # Check if user role changed to require 2FA
        if instance.requires_2fa and not instance.two_factor_enabled and not instance.two_factor_enforced_at:
            instance.start_2fa_enforcement()






