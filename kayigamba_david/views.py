from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .forms import (
    CustomLoginForm,
    CustomPasswordChangeForm,
    RegistrationForm,
    UserProfileForm,
    UserUpdateForm,
)
from .models import UserProfile


def register_view(request):
    """
    Handle user registration.
    On success: create user + profile, log in immediately, redirect to dashboard.
    """
    if request.user.is_authenticated:
        return redirect('kayigamba_david:dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Auto-create profile so profile page never 404s.
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
    # GET: show confirmation page.
    return render(request, 'kayigamba_david/logout.html')


@login_required
def dashboard_view(request):
    """Protected dashboard — requires authentication."""
    return render(request, 'kayigamba_david/dashboard.html', {'user': request.user})


@login_required
def profile_view(request):
    """
    Allow users to update their User fields and UserProfile fields together.
    Uses two forms submitted in a single POST.
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
            # Rotate session hash so the current session stays valid.
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('kayigamba_david:profile')
    else:
        form = CustomPasswordChangeForm(request.user)

    return render(request, 'kayigamba_david/change_password.html', {'form': form})
