from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import CustomUser, Role, UserProfile, UserSession, LoginAttempt


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'description', 'created_at']
    list_filter = ['name', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'full_name', 'role', 'status', 'is_email_verified', 'date_joined']
    list_filter = ['status', 'role', 'device_type', 'is_staff', 'is_superuser', 'date_joined']
    search_fields = ['username', 'email', 'full_name']
    readonly_fields = ['id', 'date_joined', 'last_login', 'created_at', 'updated_at']
    
    fieldsets = UserAdmin.fieldsets + (
        ('Beyond the Gallery Info', {
            'fields': ('full_name', 'role', 'status', 'email_verified_at')
        }),
        ('Device Information', {
            'fields': ('device_type', 'ios_version')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def is_verified(self, obj):
        if obj.email_verified_at:
            return format_html('<span style="color: green;">✓ Verified</span>')
        return format_html('<span style="color: red;">✗ Not Verified</span>')
    is_verified.short_description = 'Email Verified'


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'location', 'profile_visibility', 'created_at']
    list_filter = ['profile_visibility', 'email_visibility', 'activity_visibility', 'created_at']
    search_fields = ['user__username', 'user__email', 'bio', 'location']
    readonly_fields = ['id', 'created_at', 'updated_at']
    raw_id_fields = ['user', 'following']
    
    fieldsets = [
        ('User Information', {
            'fields': ['user']
        }),
        ('Profile Details', {
            'fields': ['bio', 'location', 'website', 'avatar']
        }),
        ('Social Media', {
            'fields': ['twitter_handle', 'github_username']
        }),
        ('Privacy Settings', {
            'fields': ['profile_visibility', 'email_visibility', 'activity_visibility']
        }),
        ('Preferences', {
            'fields': ['privacy_settings', 'preferences', 'notification_preferences'],
            'classes': ('collapse',)
        }),
        ('Community', {
            'fields': ['following']
        }),
        ('Timestamps', {
            'fields': ['created_at', 'updated_at'],
            'classes': ('collapse',)
        }),
    ]


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'ip_address', 'is_active', 'is_expired_display', 'created_at']
    list_filter = ['is_active', 'created_at', 'expires_at']
    search_fields = ['user__username', 'user__email', 'ip_address']
    readonly_fields = ['id', 'token_hash', 'created_at', 'is_expired_display']
    raw_id_fields = ['user']
    
    def is_expired_display(self, obj):
        if obj.is_expired:
            return format_html('<span style="color: red;">Expired</span>')
        return format_html('<span style="color: green;">Active</span>')
    is_expired_display.short_description = 'Status'


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['email', 'status', 'ip_address', 'failure_reason', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['email', 'ip_address', 'failure_reason']
    readonly_fields = ['id', 'created_at']
    
    def has_add_permission(self, request):
        return False  # Don't allow manual creation
    
    def has_change_permission(self, request, obj=None):
        return False  # Read-only






