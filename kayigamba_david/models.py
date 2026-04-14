from django.contrib.auth.models import Group, User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserProfile(models.Model):
    """
    Extends Django's built-in User with additional profile fields.
    One-to-one link ensures each user has exactly one profile.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.user.username} Profile'

    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
        # Custom permissions used by the RBAC setup_roles command.
        # Assigned to groups, not individual users, to keep logic auditable.
        permissions = [
            ('can_view_user_list',          'Can view list of all users'),
            ('can_access_instructor_panel', 'Can access the instructor panel'),
            ('can_access_admin_panel',      'Can access the admin management panel'),
        ]


# ── Brute-force: login attempt log ───────────────────────────────────────────

class LoginAttempt(models.Model):
    """
    Persists every login attempt for brute-force detection.

    Each row records who tried, from where, when, and whether they succeeded.
    The throttle module queries this table to decide whether a request should
    be blocked.  Using the database (rather than cache) keeps the audit trail
    durable and the logic testable without a running cache server.
    """
    username   = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    timestamp  = models.DateTimeField(auto_now_add=True)
    succeeded  = models.BooleanField(default=False)

    class Meta:
        verbose_name        = 'Login Attempt'
        verbose_name_plural = 'Login Attempts'
        ordering            = ['-timestamp']
        # Compound indexes speed up the two frequent queries:
        # "failures for username in window" and "failures for IP in window".
        indexes = [
            models.Index(fields=['username',   'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        status = 'OK' if self.succeeded else 'FAIL'
        return f'{self.username} @ {self.ip_address} [{status}] {self.timestamp:%Y-%m-%d %H:%M}'


# ── Signal: auto-assign Member group ─────────────────────────────────────────

@receiver(post_save, sender=User)
def assign_default_group(sender, instance, created, **kwargs):
    """
    Automatically place every newly created user into the Member group.
    This enforces the principle of least privilege: new accounts start
    with the minimum role and must be explicitly promoted.
    get_or_create is intentional — the group is created on first use if
    setup_roles has not been run yet.
    """
    if created:
        member_group, _ = Group.objects.get_or_create(name='Member')
        instance.groups.add(member_group)
