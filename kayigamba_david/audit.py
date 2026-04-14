"""
Audit logging utilities for security-relevant events.

Provides functions to log authentication, privilege, and security-related events
without exposing sensitive data (passwords, tokens, etc.).

All functions extract IP address and user agent from Django request objects.
"""
import logging
from django.contrib.auth.models import User
from .models import AuditLog

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Extract client IP from request, handling proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', 'unknown')
    return ip


def get_user_agent(request):
    """Extract user agent from request."""
    return request.META.get('HTTP_USER_AGENT', '')


def log_registration(request, user):
    """
    Log a successful user registration.
    
    Args:
        request: Django request object
        user: Newly created User instance
    
    SECURITY: Never logs password or signup form data.
    """
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_REGISTRATION,
        user=user,
        username=user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'User registration ({user.username})',
        details={
            'email': user.email or 'not provided',
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
        }
    )
    logger.info(f'AUDIT: User registered: {user.username} from {get_client_ip(request)}')


def log_login_success(request, user):
    """
    Log a successful login.
    
    Args:
        request: Django request object
        user: Authenticated User instance
    
    SECURITY: Never logs password.
    """
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_LOGIN_SUCCESS,
        user=user,
        username=user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'Login successful ({user.username})',
        details={
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
            'last_login_before': str(user.last_login) if user.last_login else 'first login',
        }
    )
    logger.info(f'AUDIT: Login successful: {user.username} from {get_client_ip(request)}')


def log_login_failure(request, username, reason='invalid credentials'):
    """
    Log a failed login attempt.
    
    Args:
        request: Django request object
        username: Username that failed to authenticate
        reason: Why the login failed (e.g., 'invalid credentials', 'account locked')
    
    SECURITY: Never logs password (it's not passed to this function).
    Target user may not exist (early-stage attack), so user field is null.
    """
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_LOGIN_FAILURE,
        user=None,  # User may not exist when login fails
        username=username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'Login failed ({username}): {reason}',
        details={
            'reason': reason,
        }
    )
    logger.warning(f'AUDIT: Login failed: {username} from {get_client_ip(request)} ({reason})')


def log_logout(request, user):
    """
    Log a successful logout.
    
    Args:
        request: Django request object
        user: User being logged out
    """
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_LOGOUT,
        user=user,
        username=user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'User logged out ({user.username})',
        details={}
    )
    logger.info(f'AUDIT: Logout: {user.username} from {get_client_ip(request)}')


def log_password_change(request, user):
    """
    Log a password change via user-initiated change (not reset).
    
    Args:
        request: Django request object
        user: User who changed their password
    
    SECURITY: Never logs old or new password.
    Records that password was changed from which IP, for forensics.
    """
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_PASSWORD_CHANGE,
        user=user,
        username=user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'Password changed ({user.username})',
        details={}
    )
    logger.info(f'AUDIT: Password changed: {user.username} from {get_client_ip(request)}')


def log_password_reset_request(request, username, email=None):
    """
    Log a password reset request.
    
    Args:
        request: Django request object
        username: Username requesting the reset
        email: Email provided in reset form (may differ from account email)
    
    SECURITY: Never logs passwords or sensitive account recovery info.
    Records the request for forensics (password reset abuse detection).
    """
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_PASSWORD_RESET_REQUEST,
        user=None,  # User performing reset may not be authenticated
        username=username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'Password reset requested ({username})',
        details={
            'email_provided': email or 'not provided',
        }
    )
    logger.warning(f'AUDIT: Password reset requested: {username} from {get_client_ip(request)}')


def log_password_reset_confirm(request, user):
    """
    Log a password reset confirmation (token consumed).
    
    Args:
        request: Django request object
        user: User confirming their password reset
    
    SECURITY: Never logs new password.
    Records which user performed the reset and from where.
    """
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_PASSWORD_RESET_CONFIRM,
        user=user,
        username=user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'Password reset confirmed ({user.username})',
        details={}
    )
    logger.warning(f'AUDIT: Password reset confirmed: {user.username} from {get_client_ip(request)}')


def log_permission_grant(request, target_user, group_name, granted_by_user=None):
    """
    Log a permission/group grant to a user.
    
    Args:
        request: Django request object
        target_user: User receiving the permission
        group_name: Group/permission name being granted
        granted_by_user: User who performed the grant (if available)
    
    SECURITY: Records who, when, what, and where for privilege escalation auditing.
    """
    granter = granted_by_user.username if granted_by_user else request.user.username if request.user.is_authenticated else 'system'
    
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_PERMISSION_GRANT,
        user=target_user,
        username=target_user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'Permission granted: {group_name} to {target_user.username}',
        details={
            'group': group_name,
            'granted_by': granter,
        }
    )
    logger.warning(f'AUDIT: Permission granted: {group_name} to {target_user.username} by {granter} from {get_client_ip(request)}')


def log_permission_revoke(request, target_user, group_name, revoked_by_user=None):
    """
    Log a permission/group revocation from a user.
    
    Args:
        request: Django request object
        target_user: User losing the permission
        group_name: Group/permission name being revoked
        revoked_by_user: User who performed the revocation (if available)
    
    SECURITY: Records who, when, what, and where for privilege change auditing.
    """
    revoker = revoked_by_user.username if revoked_by_user else request.user.username if request.user.is_authenticated else 'system'
    
    AuditLog.objects.create(
        event_type=AuditLog.EVENT_PERMISSION_REVOKE,
        user=target_user,
        username=target_user.username,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request),
        description=f'Permission revoked: {group_name} from {target_user.username}',
        details={
            'group': group_name,
            'revoked_by': revoker,
        }
    )
    logger.warning(f'AUDIT: Permission revoked: {group_name} from {target_user.username} by {revoker} from {get_client_ip(request)}')
