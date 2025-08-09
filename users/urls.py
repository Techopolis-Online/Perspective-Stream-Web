from django.urls import path
from django.shortcuts import redirect
from . import views

app_name = 'users'

urlpatterns = [
    # Authentication
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/<uuid:token>/', views.verify_email, name='verify_email'),
    path('resend-verification/', views.resend_verification, name='resend_verification'),
    
    # Two-Factor Authentication
    path('2fa/', views.MFAStatusView.as_view(), name='2fa'),  # Main 2FA dashboard
    path('2fa/setup/', views.TwoFactorSetupView.as_view(), name='2fa_setup'),
    path('2fa/setup/totp/', views.TOTPSetupView.as_view(), name='2fa_setup_totp'),
    path('2fa/setup/email/', views.EmailTwoFactorSetupView.as_view(), name='2fa_setup_email'),
    path('2fa/backup-codes/', views.BackupCodesView.as_view(), name='2fa_backup_codes'),
    path('2fa/login/', views.TwoFactorLoginView.as_view(), name='2fa_login'),
    path('2fa/disable/', views.DisableTwoFactorView.as_view(), name='2fa_disable'),
    path('2fa/status/', views.MFAStatusView.as_view(), name='mfa_status'),
    
    # Password management
    path('password/reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('password/reset/done/', views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password/reset/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password/reset/complete/', views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('password/change/', views.PasswordChangeView.as_view(), name='password_change'),
    path('password/change/done/', views.PasswordChangeDoneView.as_view(), name='password_change_done'),
    
    # Profile and dashboard
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('profile/edit/', views.ProfileEditView.as_view(), name='profile_edit'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('settings/', views.SettingsView.as_view(), name='settings'),
    
    # User interactions
    path('favorites/', views.FavoritesView.as_view(), name='favorites'),
    
    # Review actions (for dashboard)
    path('quick-approve/', views.quick_approve_shortcut, name='quick_approve'),
    path('quick-reject/', views.quick_reject_shortcut, name='quick_reject'),
    path('assign-to-me/', views.assign_to_me, name='assign_to_me'),
    
    # Redirect to notifications app
    path('notifications/', lambda request: redirect('notifications:notifications_list'), name='notifications'),
    path('following/', views.FollowingView.as_view(), name='following'),
    path('followers/', views.FollowersView.as_view(), name='followers'),
    
    # Redirect to help app
    path('help/', lambda request: redirect('help:help'), name='help'),
    path('guidelines/', views.GuidelinesView.as_view(), name='guidelines'),
    path('contact/', views.ContactView.as_view(), name='contact'),
    path('feedback/', views.FeedbackView.as_view(), name='feedback'),
    
    # Redirect to API key management
    path('api-keys/', lambda request: redirect('api:api_keys'), name='api_keys'),
    
    # Public profiles - MUST BE LAST as they use a catch-all pattern
    path('<str:username>/', views.PublicProfileView.as_view(), name='public_profile'),
    path('<str:username>/follow/', views.follow_user, name='follow_user'),
    path('<str:username>/unfollow/', views.unfollow_user, name='unfollow_user'),
]