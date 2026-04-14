"""
URL configuration for devsec_demo project.
"""
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    # Root → redirect straight to login (or dashboard for authenticated users via the view logic)
    path('', RedirectView.as_view(url='/auth/login/', permanent=False)),
    path('admin/', admin.site.urls),
    path('auth/', include('kayigamba_david.urls', namespace='kayigamba_david')),
]
