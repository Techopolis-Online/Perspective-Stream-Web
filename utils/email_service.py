"""
Email utility functions for Perspective Stream
"""

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.utils.html import strip_tags
from django.utils import timezone
from django.db.models import Q
import logging
from utils.text_utils import strip_emojis

logger = logging.getLogger(__name__)

class EmailService:
    """Service class for sending emails with HTML and text versions"""
    
    def __init__(self):
        # Use SMTP account as envelope sender to satisfy strict SMTP servers
        # Keep branded From header via extra headers on the message
        self.envelope_from = getattr(settings, 'EMAIL_HOST_USER', None) or settings.DEFAULT_FROM_EMAIL
        self.from_header = settings.DEFAULT_FROM_EMAIL
    
    def send_template_email(self, template_name, context, subject, to_email, request=None):
        """
        Send an email using HTML template with automatic text fallback
        
        Args:
            template_name: Name of the template (without .html extension)
            context: Dictionary of context variables for the template
            subject: Email subject line
            to_email: Recipient email address (string or list)
            request: HTTP request object (optional, for domain context)
        """
        print(f"📧 Preparing to send email template: {template_name}")
        try:
            # Ensure to_email is a list
            if isinstance(to_email, str):
                to_email = [to_email]
                print(f"Email will be sent to: {to_email}")
            
            # Add site context with dynamic domain detection
            if request and getattr(settings, 'USE_DYNAMIC_DOMAIN', True):
                # Use dynamic domain from request
                domain = request.get_host()
                protocol = 'https' if request.is_secure() else 'http'
                
                # Override protocol for specific domains
                if domain in ['localhost', '127.0.0.1'] or ':' in domain:
                    protocol = 'http'
                elif domain in ['beyondthegallery.com', 'www.beyondthegallery.com']:
                    protocol = 'https'
                
                print(f"Using domain from request: {domain} with protocol: {protocol}")
                
                context.update({
                    'domain': domain,
                    'site_name': 'Beyond the Gallery',
                    'protocol': protocol
                })
            else:
                # Fallback when no request is available
                domain = getattr(settings, 'SITE_DOMAIN', 'beyondthegallery.com')
                # Use HTTPS for production domain, HTTP for others
                if domain in ['beyondthegallery.com', 'www.beyondthegallery.com']:
                    protocol = 'https'
                else:
                    protocol = 'http'
                
                print(f"Using fallback domain: {domain} with protocol: {protocol}")
                    
                context.update({
                    'domain': domain,
                    'site_name': 'Beyond the Gallery',
                    'protocol': protocol
                })
            
            # Check if the template_name already has email/ prefix
            if template_name.startswith('email/'):
                # Use as-is
                html_template = f'{template_name}.html'
                print(f"Using provided template path: {html_template}")
            else:
                # Add email/ prefix
                html_template = f'email/{template_name}.html'
                print(f"Using constructed template path: {html_template}")
            
            try:
                # Render HTML template
                print(f"Attempting to render template: {html_template}")
                html_content = render_to_string(html_template, context)
                html_content = strip_emojis(html_content)
                print(f"Successfully rendered HTML template of length: {len(html_content)}")
                
                # Create text version by stripping HTML tags and emojis
                text_content = strip_emojis(strip_tags(html_content))
                
                # Create email message with HTML content as the main body
                email = EmailMultiAlternatives(
                    subject=strip_emojis(subject),
                    body=text_content,
                    from_email=self.envelope_from,
                    to=to_email,
                    headers={'From': self.from_header}
                )
                
                # Attach HTML version as alternative
                email.attach_alternative(html_content, "text/html")
                
                # Send email
                print(f"Attempting to send email to {to_email}")
                email.send()
                
                print(f"✅ Email sent successfully to {to_email}: {subject}")
                return True
            except Exception as render_error:
                print(f"❌ Template rendering error: {str(render_error)}")
                
                # Try alternate template path as fallback
                try:
                    alternate_template = f'{template_name}.html'  # Without email/ prefix
                    print(f"Trying alternate template path: {alternate_template}")
                    html_content = render_to_string(alternate_template, context)
                    html_content = strip_emojis(html_content)
                    
                    # Create text version
                    text_content = strip_emojis(strip_tags(html_content))
                    
                    # Create email message
                    email = EmailMultiAlternatives(
                        subject=strip_emojis(subject),
                        body=text_content,
                        from_email=self.envelope_from,
                        to=to_email,
                        headers={'From': self.from_header}
                    )
                    
                    # Attach HTML version
                    email.attach_alternative(html_content, "text/html")
                    
                    # Send email
                    email.send()
                    
                    print(f"✅ Email sent successfully with alternate template to {to_email}: {subject}")
                    return True
                except Exception as alt_error:
                    print(f"❌ Alternate template also failed: {str(alt_error)}")
                    return False
            
        except Exception as e:
            print(f"❌ Error sending email to {to_email}: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_welcome_email(self, user, request=None):
        """Send welcome email to new user"""
        return self.send_template_email(
            template_name='welcome_email',
            context={'user': user},
            subject='Welcome to Beyond the Gallery! 🎉',
            to_email=user.email,
            request=request
        )
    
    def send_password_reset_email(self, user, token, uid, request=None):
        """Send password reset email"""
        context = {
            'user': user,
            'token': token,
            'uid': uid,
        }
        
        return self.send_template_email(
            template_name='password_reset_email',
            context=context,
            subject='Password Reset for Beyond the Gallery',
            to_email=user.email,
            request=request
        )
    
    def send_password_changed_email(self, user, ip_address=None, request=None):
        """Send password changed confirmation email"""
        context = {
            'user': user,
            'ip_address': ip_address or 'Unknown',
            'timestamp': user.last_login
        }
        
        return self.send_template_email(
            template_name='password_changed',
            context=context,
            subject='Password Changed - Beyond the Gallery',
            to_email=user.email,
            request=request
        )
    
    def send_email_verification(self, user, verification_url, request=None):
        """Send email verification email"""
        try:
            # Validate inputs
            if not user or not user.email:
                print("❌ Invalid user or email provided")
                return False
            
            if not verification_url:
                print("❌ No verification URL provided")
                return False
            
            print(f"📧 Sending verification email to {user.email}")
            
            # Create context
            context = {
                'user': user,
                'verification_url': verification_url,
                'domain': request.get_host() if request else 'localhost:8000',
                'site_name': 'Beyond the Gallery',
                'protocol': 'https' if request and request.is_secure() else 'http'
            }
            
            print(f"Context: domain={context.get('domain')}, protocol={context.get('protocol')}")
            print(f"Verification URL: {verification_url}")
            
            # Try to send using the template email method
            result = self.send_template_email(
                template_name='email_verification',
                context=context,
                subject='Verify Your Email - Beyond the Gallery',
                to_email=user.email,
                request=request
            )
            
            if result:
                print(f"✅ Verification email sent successfully to {user.email}")
                return True
            else:
                print(f"❌ Failed to send verification email to {user.email}")
                
                # Try a direct fallback approach
                print("🔄 Attempting direct email send as fallback...")
                
                try:
                    # Direct email sending without template
                    from django.core.mail import EmailMultiAlternatives
                    from django.template.loader import render_to_string
                    
                    # Try to render template directly
                    html_content = render_to_string('email/email_verification.html', context)
                    html_content = strip_emojis(html_content)
                    text_content = strip_emojis(strip_tags(html_content))
                    
                    email = EmailMultiAlternatives(
                        subject='Verify Your Email - Beyond the Gallery',
                        body=text_content,
                        from_email=self.envelope_from,
                        to=[user.email],
                        headers={'From': self.from_header}
                    )
                    
                    email.attach_alternative(html_content, "text/html")
                    email.send()
                    
                    print(f"✅ Direct fallback email sent successfully to {user.email}")
                    return True
                    
                except Exception as fallback_error:
                    print(f"❌ Direct fallback also failed: {str(fallback_error)}")
                    return False
            
        except Exception as e:
            print(f"❌ Exception in send_email_verification: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def send_comment_notification(self, user, shortcut, comment, commenter, request=None):
        """Send notification about new comment on user's shortcut"""
        context = {
            'user': user,
            'shortcut': shortcut,
            'comment': comment,
            'commenter': commenter
        }
        
        return self.send_template_email(
            template_name='new_comment_notification',
            context=context,
            subject=f'New comment on "{shortcut.name}" - Beyond the Gallery',
            to_email=user.email,
            request=request
        )
    
    def send_security_alert(self, user, activity_type, ip_address, location, user_agent, is_suspicious=False, request=None):
        """Send security alert email"""
        context = {
            'user': user,
            'activity_type': activity_type,
            'ip_address': ip_address,
            'location': location,
            'user_agent': user_agent,
            'is_suspicious': is_suspicious,
            'timestamp': user.last_login
        }
        
        subject = 'Security Alert - Beyond the Gallery' if is_suspicious else 'Security Notification - Beyond the Gallery'
        
        return self.send_template_email(
            template_name='security_alert',
            context=context,
            subject=subject,
            to_email=user.email,
            request=request
        )
    
    def send_weekly_digest(self, user, digest_data, request=None):
        """Send weekly digest email"""
        context = {
            'user': user,
            **digest_data  # Unpack digest data into context
        }
        
        return self.send_template_email(
            template_name='weekly_digest',
            context=context,
            subject='Your Weekly Shortcut Digest',
            to_email=user.email,
            request=request
        )
    
    def send_account_deactivated_email(self, user, request=None):
        """Send account deactivated email"""
        return self.send_template_email(
            template_name='account_deactivated',
            context={'user': user},
            subject='Account Deactivated - Beyond the Gallery',
            to_email=user.email,
            request=request
        )
    
    def send_general_notification(self, user, title, content, action_url=None, action_text=None, additional_info=None, request=None):
        """Send general notification email"""
        context = {
            'user': user,
            'notification_title': title,
            'notification_content': content,
            'action_url': action_url,
            'action_text': action_text,
            'additional_info': additional_info
        }
        
        return self.send_template_email(
            template_name='general_notification',
            context=context,
            subject=f'{title} - Beyond the Gallery',
            to_email=user.email,
            request=request
        )
    
    # Shortcut-related emails
    def send_shortcut_submitted_email(self, user, shortcut, request=None):
        """Send shortcut submission confirmation email"""
        context = {
            'user': user,
            'shortcut': shortcut,
        }
        
        return self.send_template_email(
            template_name='shortcut_submitted',
            context=context,
            subject=f'Shortcut Submitted: {shortcut.name}',
            to_email=user.email,
            request=request
        )
    
    def send_shortcut_approved_email(self, user, shortcut, reviewer=None, review_notes=None, request=None):
        """Send shortcut approval email"""
        context = {
            'user': user,
            'shortcut': shortcut,
            'reviewer': reviewer,
            'review_notes': review_notes,
        }
        
        return self.send_template_email(
            template_name='shortcut_approved',
            context=context,
            subject=f'Shortcut Approved: {shortcut.name}',
            to_email=user.email,
            request=request
        )
    
    def send_shortcut_revision_requested_email(self, user, shortcut, reviewer, review_notes, request=None):
        """Send shortcut revision request email"""
        context = {
            'user': user,
            'shortcut': shortcut,
            'reviewer': reviewer,
            'review_notes': review_notes,
        }
        
        return self.send_template_email(
            template_name='shortcut_revision_requested',
            context=context,
            subject=f'Revision Requested: {shortcut.name}',
            to_email=user.email,
            request=request
        )
    
    def send_shortcut_rejected_email(self, user, shortcut, reviewer, review_notes, request=None):
        """Send shortcut rejection email"""
        context = {
            'user': user,
            'shortcut': shortcut,
            'reviewer': reviewer,
            'review_notes': review_notes,
        }
        
        return self.send_template_email(
            template_name='shortcut_rejected',
            context=context,
            subject=f'Submission Update: {shortcut.name}',
            to_email=user.email,
            request=request
        )
    
    def send_shortcut_featured_email(self, user, shortcut, request=None):
        """Send shortcut featured notification email"""
        context = {
            'user': user,
            'shortcut': shortcut,
        }
        
        return self.send_template_email(
            template_name='shortcut_featured',
            context=context,
            subject=f'Your Shortcut is Featured: {shortcut.name}',
            to_email=user.email,
            request=request
        )
    
    def send_new_rating_email(self, user, shortcut, rating, request=None):
        """Send new rating notification email"""
        context = {
            'user': user,
            'shortcut': shortcut,
            'rating': rating,
        }
        
        return self.send_template_email(
            template_name='new_rating_notification',
            context=context,
            subject=f'New Rating on {shortcut.name}',
            to_email=user.email,
            request=request
        )
    
    # Contact-related emails
    def send_contact_received_email(self, contact_message, request=None):
        """Send contact message received confirmation"""
        context = {
            'contact_message': contact_message,
        }
        
        return self.send_template_email(
            template_name='contact_received',
            context=context,
            subject=f'Message Received: {contact_message.get_subject_display()}',
            to_email=contact_message.email,
            request=request
        )
    
    def send_contact_response_email(self, contact_message, response_message, request=None):
        """Send contact message response"""
        context = {
            'contact_message': contact_message,
            'response_message': response_message,
        }
        
        return self.send_template_email(
            template_name='contact_response',
            context=context,
            subject=f'Response: {contact_message.get_subject_display()}',
            to_email=contact_message.email,
            request=request
        )
    
    # Notification emails
    def send_notification_email(self, user, notification, request=None):
        """Send notification email"""
        context = {
            'user': user,
            'notification': notification,
        }
        
        return self.send_template_email(
            template_name='notification_email',
            context=context,
            subject=notification.title,
            to_email=user.email,
            request=request
        )
    
    def send_maintenance_notice_email(self, user, maintenance_start, maintenance_end, 
                                    maintenance_duration, maintenance_type, 
                                    maintenance_reason=None, improvements=None, request=None):
        """Send maintenance notice email"""
        context = {
            'user': user,
            'maintenance_start': maintenance_start,
            'maintenance_end': maintenance_end,
            'maintenance_duration': maintenance_duration,
            'maintenance_type': maintenance_type,
            'maintenance_reason': maintenance_reason,
            'improvements': improvements or [],
        }
        
        return self.send_template_email(
            template_name='maintenance_notice',
            context=context,
            subject='🔧 Scheduled Maintenance Notice',
            to_email=user.email,
            request=request
        )
    
    # Help-related emails
    def send_help_article_notification(self, user, article, request=None):
        """Send new help article notification"""
        context = {
            'user': user,
            'article': article,
        }
        
        return self.send_template_email(
            template_name='help_article_notification',
            context=context,
            subject=f'New Help Article: {article.title}',
            to_email=user.email,
            request=request
        )
    
    # Community engagement emails
    def send_new_follower_email(self, user, follower, total_downloads=0, request=None):
        """Send new follower notification"""
        context = {
            'user': user,
            'follower': follower,
            'total_downloads': total_downloads,
        }
        
        return self.send_template_email(
            template_name='new_follower_notification',
            context=context,
            subject=f'{follower.get_full_name() or follower.username} is now following you!',
            to_email=user.email,
            request=request
        )
    
    def send_monthly_report_email(self, user, report_month, monthly_stats, achievements, 
                                top_shortcuts, community_stats, request=None):
        """Send monthly community report"""
        context = {
            'user': user,
            'report_month': report_month,
            'monthly_stats': monthly_stats,
            'achievements': achievements,
            'top_shortcuts': top_shortcuts,
            'community_stats': community_stats,
        }
        
        return self.send_template_email(
            template_name='monthly_report',
            context=context,
            subject=f'Monthly Report: {report_month.strftime("%B %Y")}',
            to_email=user.email,
            request=request
        )
    
    # Special occasion emails
    def send_birthday_wishes_email(self, user, featured_shortcut=None, total_downloads=0, request=None):
        """Send birthday wishes email"""
        context = {
            'user': user,
            'featured_shortcut': featured_shortcut,
            'total_downloads': total_downloads,
        }
        
        return self.send_template_email(
            template_name='birthday_wishes',
            context=context,
            subject='Happy Birthday from Beyond the Gallery!',
            to_email=user.email,
            request=request
        )
    
    def send_anniversary_email(self, user, years_member, total_downloads, avg_rating, 
                             featured_count, comments_made, ratings_given, help_articles, 
                             milestone_achievements, request=None):
        """Send anniversary celebration email"""
        context = {
            'user': user,
            'years_member': years_member,
            'total_downloads': total_downloads,
            'avg_rating': avg_rating,
            'featured_count': featured_count,
            'comments_made': comments_made,
            'ratings_given': ratings_given,
            'help_articles': help_articles,
            'milestone_achievements': milestone_achievements,
        }
        
        return self.send_template_email(
            template_name='anniversary_celebration',
            context=context,
            subject=f'Happy {years_member} Year Anniversary!',
            to_email=user.email,
            request=request
        )
        
    def send_shortcut_submission_notification(self, shortcut, request=None):
        """Send notification when a new shortcut is submitted - to submitter"""
        context = {
            'shortcut': shortcut,
            'user': shortcut.user,
        }
        
        return self.send_template_email(
            template_name='shortcut_submission_notification',
            context=context,
            subject=f'Your shortcut "{shortcut.name}" has been submitted',
            to_email=shortcut.user.email,
            request=request
        )
    
    def send_shortcut_review_notification(self, shortcut, request=None):
        """Send notification to reviewers and admins about a new shortcut submission"""
        from django.contrib.auth import get_user_model
        from django.contrib.auth.models import Group, Permission
        User = get_user_model()
        
        # Get users with review permissions (admins and reviewers)
        # Look for users with 'change_shortcut' permission
        change_shortcut_perm = Permission.objects.get(codename='change_shortcut')
        
        # Get reviewers (those with the permission directly or through a group)
        reviewers = User.objects.filter(
            Q(user_permissions=change_shortcut_perm) | 
            Q(groups__permissions=change_shortcut_perm)
        ).distinct()
        
        # Get admin emails
        admins = User.objects.filter(is_superuser=True)
        
        # Combine and remove duplicates
        recipients = set([user.email for user in list(reviewers) + list(admins) if user.email])
        
        if not recipients:
            return False
        
        context = {
            'shortcut': shortcut,
            'submitter': shortcut.user,
        }
        
        return self.send_template_email(
            template_name='shortcut_review_request',
            context=context,
            subject=f'New Shortcut Submitted for Review: "{shortcut.name}"',
            to_email=list(recipients),
            request=request
        )
    
    # 2FA Related Emails
    def send_2fa_email_code(self, user, code, request=None):
        """Send 2FA email verification code"""
        context = {
            'user': user,
            'code': code,
            'expires_in_minutes': 5,
        }
        
        return self.send_template_email(
            template_name='2fa_email_code',
            context=context,
            subject='Your verification code for Beyond the Gallery',
            to_email=user.email,
            request=request
        )
    
    def send_2fa_enabled_email(self, user, method, request=None):
        """Send confirmation that 2FA has been enabled"""
        context = {
            'user': user,
            'method': 'Authenticator App' if method == 'totp' else 'Email Codes',
            'backup_codes_count': 10,  # Default backup codes count
        }
        
        return self.send_template_email(
            template_name='2fa_enabled',
            context=context,
            subject='Two-factor authentication enabled for your account',
            to_email=user.email,
            request=request
        )
    
    def send_2fa_disabled_email(self, user, ip_address=None, request=None):
        """Send notification that 2FA has been disabled"""
        context = {
            'user': user,
            'ip_address': ip_address or 'Unknown',
            'timestamp': timezone.now(),
        }
        
        return self.send_template_email(
            template_name='2fa_disabled',
            context=context,
            subject='Two-factor authentication disabled for your account',
            to_email=user.email,
            request=request
        )
    
    def send_2fa_backup_code_used_email(self, user, codes_remaining, request=None):
        """Send notification when a backup code is used"""
        context = {
            'user': user,
            'codes_remaining': codes_remaining,
            'low_codes': codes_remaining <= 3,
        }
        
        return self.send_template_email(
            template_name='2fa_backup_code_used',
            context=context,
            subject='Backup code used for two-factor authentication',
            to_email=user.email,
            request=request
        )
    
    def send_2fa_enforcement_warning(self, user, days_remaining, request=None):
        """Send warning about upcoming 2FA enforcement deadline"""
        context = {
            'user': user,
            'days_remaining': days_remaining,
            'deadline_date': user.two_factor_grace_period_ends,
        }
        
        return self.send_template_email(
            template_name='2fa_enforcement_warning',
            context=context,
            subject=f'Action required: Set up two-factor authentication ({days_remaining} days remaining)',
            to_email=user.email,
            request=request
        )

# Create a singleton instance
email_service = EmailService()
