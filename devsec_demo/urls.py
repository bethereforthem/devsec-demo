"""
URL configuration for devsec_demo project.
"""
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

# Convenience redirect aliases — these short paths redirect to the canonical
# /auth/... URLs so that typing /dashboard/, /login/, etc. in the browser
# still works without breaking the namespaced URL structure.
_R = RedirectView.as_view  # shorthand

urlpatterns = [
    # ── Django admin ────────────────────────────────────────────────
    path('admin/', admin.site.urls),

    # ── App (canonical URLs under /auth/) ───────────────────────────
    path('auth/', include('kayigamba_david.urls', namespace='kayigamba_david')),

    # ── Root ────────────────────────────────────────────────────────
    path('', _R(url='/auth/login/', permanent=False)),

    # ── Short-URL aliases (redirect to canonical) ───────────────────
    path('login/',           _R(url='/auth/login/',           permanent=False)),
    path('logout/',          _R(url='/auth/logout/',          permanent=False)),
    path('register/',        _R(url='/auth/register/',        permanent=False)),
    path('dashboard/',       _R(url='/auth/dashboard/',       permanent=False)),
    path('profile/',         _R(url='/auth/profile/',         permanent=False)),
    path('change-password/', _R(url='/auth/password/change/', permanent=False)),
    path('instructor/',      _R(url='/auth/instructor/',      permanent=False)),
    path('admin-panel/',     _R(url='/auth/admin-panel/',     permanent=False)),
]
