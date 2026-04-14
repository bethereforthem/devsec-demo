from django.contrib.auth.models import User
from django.db import models


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
