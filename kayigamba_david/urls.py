from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from . import views

app_name = 'kayigamba_david'

urlpatterns = [
    # ── Public ──────────────────────────────────────────────────────
    path('register/',        views.register_view,        name='register'),
    path('login/',           views.login_view,            name='login'),
    path('logout/',          views.logout_view,           name='logout'),

    # ── Member (any authenticated user) ─────────────────────────────
    path('dashboard/',       views.dashboard_view,        name='dashboard'),
    path('profile/',         views.profile_view,          name='profile'),
    path('password/change/', views.change_password_view,  name='change_password'),

    # ── Instructor+ (Instructor group and above) ─────────────────────
    path('instructor/',      views.instructor_panel_view, name='instructor_panel'),

    # ── Admin only (is_staff=True) ───────────────────────────────────
    path('admin-panel/',     views.admin_panel_view,      name='admin_panel'),

    # ── Password reset (4-step flow, all Django built-in CBVs) ──────
    #
    # Step 1 — user submits their email address.
    # Security: always redirects to "done" regardless of whether the
    # email exists, preventing user enumeration.
    path(
        'password/reset/',
        auth_views.PasswordResetView.as_view(
            template_name='kayigamba_david/password_reset_request.html',
            email_template_name='kayigamba_david/password_reset_email.html',
            subject_template_name='kayigamba_david/password_reset_subject.txt',
            success_url=reverse_lazy('kayigamba_david:password_reset_done'),
        ),
        name='password_reset',
    ),

    # Step 2 — confirmation page ("check your email").
    path(
        'password/reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='kayigamba_david/password_reset_done.html',
        ),
        name='password_reset_done',
    ),

    # Step 3 — user clicks the link from the email; enters new password.
    # Django validates the HMAC token, stores it in the session, then
    # redirects to a stable URL (/<uidb64>/set-password/) so the token
    # never appears in HTTP Referer headers sent by the browser.
    path(
        'password/reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='kayigamba_david/password_reset_confirm.html',
            success_url=reverse_lazy('kayigamba_david:password_reset_complete'),
        ),
        name='password_reset_confirm',
    ),

    # Step 4 — success page after the password has been updated.
    path(
        'password/reset/complete/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='kayigamba_david/password_reset_complete.html',
        ),
        name='password_reset_complete',
    ),
]
