"""
rbac.py — Role-Based Access Control helpers for SYS_UAS.

Authorization model
-------------------
Role        | Group         | Flag          | What they can access
----------- | ------------- | ------------- | -------------------------------------------
Anonymous   | —             | —             | Login, Register only
Member      | Member        | is_active     | Dashboard, Profile, Password change
Instructor  | Instructor    | —             | + Instructor panel, User list
Admin       | Admin         | is_staff=True | + Admin management panel (everything)

Design decisions
----------------
* Decorators return 403 (PermissionDenied) for authenticated users who lack access,
  and redirect to LOGIN_URL for unauthenticated users. Never reveal protected content.
* Superusers bypass all group/flag checks — they are outside the role hierarchy.
* Group names are kept as constants (ROLE_*) to avoid magic strings in views.
* A context processor injects role helpers into every template automatically,
  so templates never call Python helpers directly.
"""

from functools import wraps

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

# ── Role name constants ───────────────────────────────────────────────────────
ROLE_MEMBER     = 'Member'
ROLE_INSTRUCTOR = 'Instructor'
ROLE_ADMIN      = 'Admin'


# ── Decorators ────────────────────────────────────────────────────────────────

def group_required(*group_names):
    """
    Restrict a view to users who belong to at least one of the named groups.

    Behaviour:
    - Unauthenticated → redirect to LOGIN_URL preserving ?next=
    - Authenticated without the required group → 403 PermissionDenied
    - Staff / superusers always pass (they sit above the group hierarchy)
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect(f'{settings.LOGIN_URL}?next={request.path}')
            # Staff and superusers are never blocked by group checks.
            if request.user.is_superuser or request.user.is_staff:
                return view_func(request, *args, **kwargs)
            if request.user.groups.filter(name__in=group_names).exists():
                return view_func(request, *args, **kwargs)
            raise PermissionDenied
        return wrapper
    return decorator


def staff_required(view_func):
    """
    Restrict a view to staff members and superusers only (Admin role).

    Behaviour:
    - Unauthenticated → redirect to LOGIN_URL
    - Authenticated but not staff → 403
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(f'{settings.LOGIN_URL}?next={request.path}')
        if request.user.is_superuser or request.user.is_staff:
            return view_func(request, *args, **kwargs)
        raise PermissionDenied
    return wrapper


# ── Helper functions ──────────────────────────────────────────────────────────

def get_user_role(user):
    """
    Return a human-readable role label for the given user.
    Used for display only — not for access decisions.
    """
    if not user.is_authenticated:
        return 'Anonymous'
    if user.is_superuser:
        return 'Superuser'
    if user.is_staff or user.groups.filter(name=ROLE_ADMIN).exists():
        return 'Admin'
    if user.groups.filter(name=ROLE_INSTRUCTOR).exists():
        return 'Instructor'
    return 'Member'


def user_has_group(user, *group_names):
    """
    Return True if the user belongs to any of the named groups.
    Staff and superusers always return True.
    Safe to call with unauthenticated users (returns False).
    """
    if not user.is_authenticated:
        return False
    if user.is_superuser or user.is_staff:
        return True
    return user.groups.filter(name__in=group_names).exists()


# ── Context processor ─────────────────────────────────────────────────────────

def rbac_context(request):
    """
    Inject role helpers into every template automatically.
    Registered in settings.TEMPLATES[].OPTIONS.context_processors.

    Template variables provided:
    - user_role          : 'Anonymous' | 'Member' | 'Instructor' | 'Admin' | 'Superuser'
    - is_instructor_plus : True for Instructor and above
    - is_admin           : True for Admin / staff / superuser
    """
    user = request.user
    return {
        'user_role': get_user_role(user),
        'is_instructor_plus': user_has_group(user, ROLE_INSTRUCTOR, ROLE_ADMIN),
        'is_admin': bool(user.is_authenticated and (user.is_staff or user.is_superuser)),
    }
