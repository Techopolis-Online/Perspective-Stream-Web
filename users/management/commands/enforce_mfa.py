from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from users.models import CustomUser, MFAEnforcementLog
from utils.email_service import email_service
from django_otp import user_has_device
import logging
from utils.text_utils import strip_emojis

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Enforce MFA for admin and reviewer roles after specified days'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without actually doing it'
        )
        parser.add_argument(
            '--send-warnings',
            action='store_true',
            help='Send warning emails to users who will need MFA soon'
        )
        parser.add_argument(
            '--enforce',
            action='store_true',
            help='Enforce MFA for eligible users'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=getattr(settings, 'MFA_ENFORCEMENT_DAYS', 14),
            help='Number of days after account creation to enforce MFA (default: 14)'
        )
    
    def handle(self, *args, **options):
        enforcement_days = options['days']
        dry_run = options['dry_run']
        send_warnings = options['send_warnings']
        enforce = options['enforce']
        
        if not send_warnings and not enforce:
            self.stdout.write(
                self.style.WARNING(
                    'Please specify --send-warnings or --enforce (or both)'
                )
            )
            return
        
        self.stdout.write(
            f"MFA Enforcement Check (Days: {enforcement_days}, Dry Run: {dry_run})"
        )
        
        # Get users who require MFA based on role
        required_roles = getattr(settings, 'MFA_REQUIRED_ROLES', ['admin', 'super_admin', 'moderator'])
        
        # Users who need MFA but don't have it
        target_users = CustomUser.objects.filter(
            role__name__in=required_roles,
            mfa_enabled=False
        ).exclude(
            is_superuser=True  # Exclude superusers
        )
        
        if send_warnings:
            self._send_warning_emails(target_users, enforcement_days, dry_run)
            
        if enforce:
            self._enforce_mfa(target_users, enforcement_days, dry_run)
    
    def _send_warning_emails(self, users, enforcement_days, dry_run):
        """Send warning emails to users who will need MFA soon"""
        warning_days = getattr(settings, 'MFA_WARNING_DAYS', [7, 3, 1])
        now = timezone.now()
        
        for warning_day in warning_days:
            # Calculate the cutoff date for this warning
            cutoff_date = now - timezone.timedelta(days=enforcement_days - warning_day)
            warning_users = users.filter(
                created_at__lte=cutoff_date,
                created_at__gt=cutoff_date - timezone.timedelta(hours=1)  # Only users created around this time
            )
            
            for user in warning_users:
                # Check if we already sent this warning
                existing_warning = MFAEnforcementLog.objects.filter(
                    user=user,
                    action='warning_sent',
                    message__contains=f'{warning_day} day'
                ).exists()
                
                if existing_warning:
                    continue
                
                days_until_enforcement = (
                    user.created_at + timezone.timedelta(days=enforcement_days) - now
                ).days
                
                if dry_run:
                    self.stdout.write(
                        f"[DRY RUN] Would send {warning_day}-day warning to {user.email} "
                        f"(enforcement in {days_until_enforcement} days)"
                    )
                else:
                    try:
                        self._send_mfa_warning_email(user, days_until_enforcement)
                        
                        # Log the warning
                        MFAEnforcementLog.objects.create(
                            user=user,
                            action='warning_sent',
                            message=f'{warning_day} day warning sent - {days_until_enforcement} days until enforcement'
                        )
                        
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"Sent {warning_day}-day warning to {user.email}"
                            )
                        )
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(
                                f"Failed to send warning to {user.email}: {str(e)}"
                            )
                        )
                        logger.error(f"MFA warning email failed for {user.email}: {str(e)}")
    
    def _enforce_mfa(self, users, enforcement_days, dry_run):
        """Enforce MFA for users whose grace period has expired"""
        cutoff_date = timezone.now() - timezone.timedelta(days=enforcement_days)
        enforcement_users = users.filter(
            created_at__lte=cutoff_date,
            mfa_enforced_at__isnull=True
        )
        
        self.stdout.write(f"Found {enforcement_users.count()} users eligible for MFA enforcement")
        
        for user in enforcement_users:
            # Double-check they don't already have MFA enabled
            if user.mfa_enabled or user_has_device(user):
                continue
            
            if dry_run:
                self.stdout.write(
                    f"[DRY RUN] Would enforce MFA for {user.email} "
                    f"(account created {user.created_at.strftime('%Y-%m-%d')})"
                )
            else:
                try:
                    # Mark MFA as enforced
                    user.enforce_mfa()
                    
                    # Send enforcement notification
                    self._send_mfa_enforcement_email(user)
                    
                    # Log the enforcement
                    MFAEnforcementLog.objects.create(
                        user=user,
                        action='access_restricted',
                        message=f'MFA enforcement activated - account access restricted until 2FA setup'
                    )
                    
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Enforced MFA for {user.email} (role: {user.role.name})"
                        )
                    )
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(
                            f"Failed to enforce MFA for {user.email}: {str(e)}"
                        )
                    )
                    logger.error(f"MFA enforcement failed for {user.email}: {str(e)}")
    
    def _send_mfa_warning_email(self, user, days_until_enforcement):
        """Send MFA warning email to user"""
        subject = strip_emojis(f"Action Required: Set Up Two-Factor Authentication - {days_until_enforcement} Days Remaining")
        
        template_data = {
            'user': user,
            'days_remaining': days_until_enforcement,
            'setup_url': f"{settings.SITE_DOMAIN}/users/mfa-setup/",
            'role_name': user.role.get_name_display() if user.role else 'Admin/Moderator'
        }
        
        # Send HTML email
        html_content = strip_emojis(f"""
        <h2>Two-Factor Authentication Setup Required</h2>
        
        <p>Hello {user.username},</p>
        
        <p>Your account role (<strong>{template_data['role_name']}</strong>) requires two-factor authentication (2FA) for enhanced security.</p>
        
        <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #ffeaa7;">
            <h3 style="color: #856404; margin: 0 0 10px 0;">{days_until_enforcement} Days Remaining</h3>
            <p style="margin: 0; color: #856404;">You have <strong>{days_until_enforcement} days</strong> to set up 2FA before your account access is restricted.</p>
        </div>
        
        <h3>What You Need to Do:</h3>
        <ol>
            <li><strong>Install an authenticator app</strong> like Google Authenticator, Authy, or Microsoft Authenticator</li>
            <li><strong>Set up 2FA</strong> by visiting: <a href="{template_data['setup_url']}">{template_data['setup_url']}</a></li>
            <li><strong>Save your recovery codes</strong> in a secure location</li>
        </ol>
        
        <h3>Why This Matters:</h3>
        <ul>
            <li>Protects your account and our platform from unauthorized access</li>
            <li>Required for all administrative and moderation roles</li>
            <li>Industry standard security practice</li>
        </ul>
        
        <div style="background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #bee5eb;">
            <p style="margin: 0; color: #0c5460;"><strong>Need Help?</strong> Contact our support team if you have any questions about setting up 2FA.</p>
        </div>
        
        <p>Best regards,<br>The Beyond the Gallery Team</p>
        """)
        
        email_service.send_email(
            to_email=user.email,
            subject=subject,
            html_content=html_content,
            context=template_data
        )
    
    def _send_mfa_enforcement_email(self, user):
        """Send MFA enforcement notification email"""
        subject = strip_emojis("Account Access Restricted - Two-Factor Authentication Required")
        
        template_data = {
            'user': user,
            'setup_url': f"{settings.SITE_DOMAIN}/users/mfa-setup/",
            'role_name': user.role.get_name_display() if user.role else 'Admin/Moderator'
        }
        
        html_content = strip_emojis(f"""
        <h2>Account Access Restricted</h2>
        
        <p>Hello {user.username},</p>
        
        <div style="background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #f5c6cb;">
            <h3 style="color: #721c24; margin: 0 0 10px 0;">Access Restricted</h3>
            <p style="margin: 0; color: #721c24;">Your account access has been restricted because two-factor authentication setup is overdue.</p>
        </div>
        
        <p>Your account role (<strong>{template_data['role_name']}</strong>) requires two-factor authentication for security compliance.</p>
        
        <h3>To Restore Access:</h3>
        <ol>
            <li><strong>Log in to your account</strong> (you can still access the 2FA setup)</li>
            <li><strong>Complete 2FA setup</strong> at: <a href="{template_data['setup_url']}">{template_data['setup_url']}</a></li>
            <li><strong>Your access will be restored</strong> immediately after setup</li>
        </ol>
        
        <h3>Setup Process:</h3>
        <ol>
            <li>Install an authenticator app (Google Authenticator, Authy, etc.)</li>
            <li>Scan the QR code provided in your account</li>
            <li>Enter the verification code to complete setup</li>
            <li>Save your recovery codes securely</li>
        </ol>
        
        <div style="background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #bee5eb;">
            <p style="margin: 0; color: #0c5460;"><strong>Need Assistance?</strong> Contact our support team immediately if you need help with 2FA setup.</p>
        </div>
        
        <p>We apologize for any inconvenience, but this security measure is essential for protecting our platform and community.</p>
        
        <p>Best regards,<br>The Beyond the Gallery Team</p>
        """)
        
        email_service.send_email(
            to_email=user.email,
            subject=subject,
            html_content=html_content,
            context=template_data
        )
