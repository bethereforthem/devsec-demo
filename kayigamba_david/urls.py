from django.urls import path

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
]
