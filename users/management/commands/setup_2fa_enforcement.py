"""
Management command to set up 2FA enforcement for existing privileged users
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import models
from users.models import CustomUser
from utils.email_service import email_service

User = get_user_model()


class Command(BaseCommand):
    help = 'Set up 2FA enforcement for existing privileged users (admins, moderators, reviewers)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes',
        )
        parser.add_argument(
            '--send-emails',
            action='store_true',
            help='Send notification emails to affected users',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        send_emails = options['send_emails']
        
        self.stdout.write(
            self.style.SUCCESS('🔐 Setting up 2FA enforcement for privileged users...')
        )
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN MODE - No changes will be made')
            )
        
        # Find privileged users who need 2FA enforcement
        privileged_users = User.objects.filter(
            models.Q(is_superuser=True) |
            models.Q(role__name__in=['moderator', 'admin', 'super_admin'])
        ).exclude(two_factor_enabled=True)
        
        affected_count = 0
        
        for user in privileged_users:
            if user.requires_2fa and not user.two_factor_enabled:
                # Check if enforcement is already started
                if not user.two_factor_enforced_at:
                    if not dry_run:
                        user.start_2fa_enforcement()
                        self.stdout.write(f'  ✅ Started 2FA enforcement for {user.username} ({user.email})')
                        
                        # Send notification email
                        if send_emails:
                            try:
                                email_service.send_2fa_enforcement_warning(
                                    user, 
                                    user.days_left_in_grace_period
                                )
                                self.stdout.write(f'     📧 Sent notification email to {user.email}')
                            except Exception as e:
                                self.stdout.write(
                                    self.style.ERROR(f'     ❌ Failed to send email to {user.email}: {str(e)}')
                                )
                    else:
                        self.stdout.write(f'  📝 Would start 2FA enforcement for {user.username} ({user.email})')
                        if send_emails:
                            self.stdout.write(f'     📝 Would send notification email to {user.email}')
                    
                    affected_count += 1
                else:
                    days_left = user.days_left_in_grace_period
                    self.stdout.write(
                        f'  ⏰ {user.username} already has 2FA enforcement started '
                        f'({days_left} days remaining)'
                    )
        
        if affected_count == 0:
            self.stdout.write(
                self.style.SUCCESS('✅ No new users need 2FA enforcement setup')
            )
        else:
            action_verb = 'Would affect' if dry_run else 'Affected'
            self.stdout.write(
                self.style.SUCCESS(f'✅ {action_verb} {affected_count} user(s)')
            )
            
            if not dry_run:
                self.stdout.write(
                    self.style.WARNING(
                        f'These users have 14 days to set up 2FA before access is restricted.'
                    )
                )
        
        # Show summary of all privileged users
        self.stdout.write('\n📊 Summary of all privileged users:')
        
        all_privileged = User.objects.filter(
            models.Q(is_superuser=True) |
            models.Q(role__name__in=['moderator', 'admin', 'super_admin'])
        )
        
        total_privileged = all_privileged.count()
        enabled_2fa = all_privileged.filter(two_factor_enabled=True).count()
        in_grace_period = sum(1 for user in all_privileged if user.is_in_2fa_grace_period)
        needs_setup = total_privileged - enabled_2fa
        
        self.stdout.write(f'  Total privileged users: {total_privileged}')
        self.stdout.write(f'  ✅ With 2FA enabled: {enabled_2fa}')
        self.stdout.write(f'  ⏰ In grace period: {in_grace_period}')
        self.stdout.write(f'  ❌ Need to set up 2FA: {needs_setup}')
        
        if not dry_run and affected_count > 0:
            self.stdout.write(
                self.style.SUCCESS(
                    '\n🎉 2FA enforcement setup complete! '
                    'Affected users will receive email notifications.'
                )
            )
