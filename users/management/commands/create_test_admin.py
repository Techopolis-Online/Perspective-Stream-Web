from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from users.models import Role

User = get_user_model()


class Command(BaseCommand):
    help = 'Create test admin user for MFA testing'
    
    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, required=True, help='Admin email')
        parser.add_argument('--username', type=str, required=True, help='Admin username')
        parser.add_argument('--password', type=str, default='testpass123', help='Admin password')
        parser.add_argument('--role', type=str, default='admin', help='User role')
    
    def handle(self, *args, **options):
        email = options['email']
        username = options['username']
        password = options['password']
        role_name = options['role']
        
        # Check if user already exists
        if User.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.WARNING(f'User with email {email} already exists')
            )
            return
        
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'User with username {username} already exists')
            )
            return
        
        # Get or create role
        role, created = Role.objects.get_or_create(
            name=role_name,
            defaults={
                'description': f'Test {role_name.title()} Role',
                'permissions': {'test': True}
            }
        )
        
        if created:
            self.stdout.write(
                self.style.SUCCESS(f'Created role: {role_name}')
            )
        
        # Create user
        user = User.objects.create_user(
            email=email,
            username=username,
            password=password,
            role=role,
            full_name=f'Test {role_name.title()}',
            is_staff=True if role_name in ['admin', 'super_admin'] else False
        )
        
        # Verify email immediately for testing
        user.email_verified_at = user.created_at
        user.save()
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created test user:\n'
                f'  Email: {email}\n'
                f'  Username: {username}\n'
                f'  Role: {role_name}\n'
                f'  Password: {password}'
            )
        )
        
        # Check MFA enforcement requirement
        if user.requires_mfa_enforcement:
            self.stdout.write(
                self.style.WARNING(
                    'This user will require MFA setup (account is over 14 days old or role requires MFA)'
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    'User is within the 14-day grace period for MFA setup'
                )
            )
