from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, redirect, render

from .forms import (
    CustomLoginForm,
    CustomPasswordChangeForm,
    RegistrationForm,
    UserProfileForm,
    UserUpdateForm,
)
from .models import UserProfile
from .rbac import get_user_role, group_required, staff_required


# ── Public views (authentication) ────────────────────────────────────────────

def register_view(request):
    """
    Handle user registration.
    On success: create user + profile, log in immediately, redirect to dashboard.
    The post_save signal in models.py auto-assigns the Member group.
    """
    if request.user.is_authenticated:
        return redirect('kayigamba_david:dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(user=user)
            login(request, user)
            messages.success(request, f'Welcome, {user.username}! Your account has been created.')
            return redirect('kayigamba_david:dashboard')
    else:
        form = RegistrationForm()

    return render(request, 'kayigamba_david/register.html', {'form': form})


def login_view(request):
    """
    Handle user login using Django's AuthenticationForm, which validates
    credentials and raises a ValidationError on failure — no manual checks needed.
    """
    if request.user.is_authenticated:
        return redirect('kayigamba_david:dashboard')

    if request.method == 'POST':
        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            # Honour ?next= param safely (must be a local path).
            next_url = request.GET.get('next')
            if next_url and next_url.startswith('/'):
                return redirect(next_url)
            return redirect('kayigamba_david:dashboard')
    else:
        form = CustomLoginForm(request)

    return render(request, 'kayigamba_david/login.html', {'form': form})


@login_required
def logout_view(request):
    """
    Log out only on POST to prevent CSRF-based logout via GET requests.
    """
    if request.method == 'POST':
        logout(request)
        messages.info(request, 'You have been logged out.')
        return redirect('kayigamba_david:login')
    return render(request, 'kayigamba_david/logout.html')


# ── Member views (any authenticated user) ────────────────────────────────────

@login_required
def dashboard_view(request):
    """Protected dashboard — requires authentication (Member role and above)."""
    return render(request, 'kayigamba_david/dashboard.html', {
        'user': request.user,
        'user_role': get_user_role(request.user),
    })


@login_required
def profile_view(request):
    """
    Allow users to update their own User and UserProfile fields.
    Users can only edit their own profile — no user-id parameter is exposed.
    """
    profile = get_object_or_404(UserProfile, user=request.user)

    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = UserProfileForm(request.POST, instance=profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile has been updated.')
            return redirect('kayigamba_david:profile')
    else:
        user_form = UserUpdateForm(instance=request.user)
        profile_form = UserProfileForm(instance=profile)

    return render(request, 'kayigamba_david/profile.html', {
        'user_form': user_form,
        'profile_form': profile_form,
    })


@login_required
def change_password_view(request):
    """
    Password change using Django's PasswordChangeForm.
    update_session_auth_hash() keeps the user logged in after the change.
    """
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('kayigamba_david:profile')
    else:
        form = CustomPasswordChangeForm(request.user)

    return render(request, 'kayigamba_david/change_password.html', {'form': form})


# ── Instructor views (Instructor group and above) ─────────────────────────────

@group_required('Instructor')
def instructor_panel_view(request):
    """
    Instructor panel — accessible to Instructor group members and all staff.
    Shows a read-only list of all non-superuser accounts with their roles.
    @group_required('Instructor') also allows staff/superusers through.
    """
    users = (
        User.objects
        .filter(is_superuser=False)
        .select_related('profile')
        .prefetch_related('groups')
        .order_by('username')
    )
    # Annotate each user with their display role for the template.
    user_rows = [
        {'user': u, 'role': get_user_role(u)}
        for u in users
    ]
    return render(request, 'kayigamba_david/instructor_panel.html', {
        'user_rows': user_rows,
        'total': len(user_rows),
    })


# ── Admin views (staff / Admin role only) ─────────────────────────────────────

@staff_required
def admin_panel_view(request):
    """
    Admin management panel — restricted to is_staff=True (Admin role).
    Provides a full user list with group details and account controls.
    @staff_required returns 403 for authenticated non-staff users — never
    redirects to login so as not to confirm the URL exists to non-admins.
    """
    users = (
        User.objects
        .select_related('profile')
        .prefetch_related('groups')
        .order_by('-date_joined')
    )
    user_rows = [
        {'user': u, 'role': get_user_role(u), 'groups': ', '.join(g.name for g in u.groups.all()) or '—'}
        for u in users
    ]
    staff_count = sum(1 for u in users if u.is_staff)
    instructor_count = sum(1 for r in user_rows if r['role'] == 'Instructor')
    member_count = sum(1 for r in user_rows if r['role'] == 'Member')
    return render(request, 'kayigamba_david/admin_panel.html', {
        'user_rows': user_rows,
        'total': len(user_rows),
        'staff_count': staff_count,
        'instructor_count': instructor_count,
        'member_count': member_count,
    })
