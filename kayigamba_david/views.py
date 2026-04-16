from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.views import PasswordResetConfirmView, PasswordResetView
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme

from .audit import (
    log_login_failure,
    log_login_success,
    log_logout,
    log_password_change,
    log_password_reset_confirm,
    log_password_reset_request,
    log_registration,
)
from .forms import (
    CustomLoginForm,
    CustomPasswordChangeForm,
    RegistrationForm,
    UserProfileForm,
    UserUpdateForm,
)
from .models import UserProfile
from .rbac import get_user_role, group_required, staff_required
from .throttle import clear_failures, get_client_ip, get_lockout_status, record_attempt


# ── Public views (authentication) ────────────────────────────────────────────

def register_view(request):
    """
    Handle user registration.
    On success: create user + profile, log in immediately, redirect to dashboard.
    The post_save signal in models.py auto-assigns the Member group.
    
    SECURITY: No user-controlled redirect parameter accepted. Redirect target
    is hardcoded to 'dashboard' — this is safe-by-default against open redirects.
    """
    if request.user.is_authenticated:
        return redirect('kayigamba_david:dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(user=user)
            login(request, user)
            log_registration(request, user)
            messages.success(request, f'Welcome, {user.username}! Your account has been created.')
            return redirect('kayigamba_david:dashboard')
    else:
        form = RegistrationForm()

    return render(request, 'kayigamba_david/register.html', {'form': form})


def login_view(request):
    """
    Handle user login with brute-force protection.

    Flow:
    1. Authenticated users → redirect to dashboard (no re-login needed).
    2. POST: extract username + IP, check lockout status BEFORE validating
       credentials so a locked account is never probed further.
    3. If not locked: validate credentials normally.
       - Success → record attempt, clear old failures, redirect.
       - Failure → record attempt, re-check status for updated count.
    4. GET: render empty form.

    The lockout_info dict from throttle.get_lockout_status() is passed to the
    template so it can show a lockout message or a "X attempts remaining"
    warning without any template-level logic about thresholds.
    """
    if request.user.is_authenticated:
        return redirect('kayigamba_david:dashboard')

    lockout_info = None

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        ip       = get_client_ip(request)
        status   = get_lockout_status(username, ip)

        if status['is_locked']:
            # Block early — no credential validation, no new failure recorded.
            # Rendering a blank form (not the submitted one) avoids echoing
            # the attempted username back into the input field.
            return render(request, 'kayigamba_david/login.html', {
                'form':         CustomLoginForm(request),
                'lockout_info': status,
            })

        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            record_attempt(username, ip, succeeded=True)
            clear_failures(username, ip)
            log_login_success(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            
            # SECURITY: Open Redirect Protection (CWE-601)
            # Honour ?next= parameter only for safe, same-host internal paths.
            # Prevents attackers from redirecting users to phishing sites via:
            #   - Absolute URLs: http://attacker.com/steal
            #   - Protocol-relative URLs: //evil.com/phish (also starts with /)
            #   - Javascript protocols: javascript:alert('xss')
            #   - Data URLs: data:text/html,<script>alert('xss')</script>
            #
            # url_has_allowed_host_and_scheme() validates:
            #   ✅ Host matches request.get_host() (same domain only)
            #   ✅ Scheme matches context (HTTPS if secure, allows HTTP if not)
            #   ❌ Blocks all absolute external URLs
            #   ❌ Blocks protocol-relative URLs (//evil.com is not //)
            #   ❌ Blocks non-standard schemes
            #
            # Safe Redirects (allowed):
            #   - /dashboard/
            #   - /profile/
            #   - /help/?topic=login
            #
            # Attack Attempts (blocked, falls back to dashboard):
            #   - //evil.com/steal
            #   - http://attacker.com
            #   - https://phishing.com/fake-login
            next_url = request.GET.get('next', '').strip()
            if next_url and url_has_allowed_host_and_scheme(
                url=next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                return redirect(next_url)
            # Safe default: redirect to dashboard if no valid next param
            return redirect('kayigamba_david:dashboard')
        else:
            record_attempt(username, ip, succeeded=False)
            log_login_failure(request, username, 'invalid credentials')
            # Re-query so lockout_info reflects the attempt we just recorded.
            lockout_info = get_lockout_status(username, ip)
    else:
        form = CustomLoginForm(request)

    return render(request, 'kayigamba_david/login.html', {
        'form':         form,
        'lockout_info': lockout_info,
    })


@login_required
def logout_view(request):
    """
    Log out only on POST to prevent CSRF-based logout via GET requests.
    
    SECURITY: No user-controlled redirect parameter accepted. Redirect target
    is hardcoded to 'login' — this is safe-by-default against open redirects
    (CWE-601). No validation needed because there's no user input.
    """
    if request.method == 'POST':
        user = request.user
        log_logout(request, user)
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
    
    SECURITY: Redirect target is hardcoded (safe-by-default against open
    redirects). No user-controlled redirect parameters are accepted.
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
    
    SECURITY: Redirect target is hardcoded (safe-by-default against open
    redirects). No user-controlled redirect parameters are accepted.
    """
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            log_password_change(request, user)
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
    # Derive counts from the already-evaluated list — no second queryset hit.
    staff_count      = sum(1 for r in user_rows if r['role'] in ('Admin', 'Superuser'))
    instructor_count = sum(1 for r in user_rows if r['role'] == 'Instructor')
    member_count     = sum(1 for r in user_rows if r['role'] == 'Member')
    return render(request, 'kayigamba_david/admin_panel.html', {
        'user_rows': user_rows,
        'total': len(user_rows),
        'staff_count': staff_count,
        'instructor_count': instructor_count,
        'member_count': member_count,
    })


# ── Password reset views (custom subclasses for audit logging) ────────────────

class CustomPasswordResetView(PasswordResetView):
    """
    Custom password reset request view that logs the reset request.
    
    SECURITY: Always shows success regardless of whether the email exists,
    preventing user enumeration. Audit logging records the request attempt.
    """
    def form_valid(self, form):
        email = form.cleaned_data.get('email', '')
        # Try to find user by email for logging purposes
        try:
            user = User.objects.get(email=email)
            username = user.username
        except User.DoesNotExist:
            username = f'(unknown: {email})'
        
        log_password_reset_request(self.request, username, email)
        return super().form_valid(form)


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """
    Custom password reset confirm view that logs the confirmation.
    
    SECURITY: Records when a reset token is used for forensics.
    """
    def form_valid(self, form):
        user = form.save()
        log_password_reset_confirm(self.request, user)
        return super().form_valid(form)
