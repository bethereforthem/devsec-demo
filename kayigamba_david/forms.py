from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.models import User

from .models import UserProfile


class RegistrationForm(forms.ModelForm):
    """
    Registration form with password confirmation.
    Uses Django's built-in password hashing via set_password().
    """
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exists():
            raise forms.ValidationError('A user with this email already exists.')
        return email

    def clean(self):
        cleaned_data = super().clean()
        pw1 = cleaned_data.get('password1')
        pw2 = cleaned_data.get('password2')
        if pw1 and pw2 and pw1 != pw2:
            self.add_error('password2', 'Passwords do not match.')
        return cleaned_data

    def save(self, commit=True):
        # Use set_password so Django hashes the password — never store plaintext.
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class CustomLoginForm(AuthenticationForm):
    """
    Thin wrapper around Django's AuthenticationForm for template consistency.
    Inherits all validation and brute-force protection from the base class.
    """
    username = forms.CharField(
        widget=forms.TextInput(attrs={'autofocus': True, 'autocomplete': 'username'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'})
    )


class UserProfileForm(forms.ModelForm):
    """Form for updating the extended profile fields."""
    class Meta:
        model = UserProfile
        fields = ('bio',)
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Tell us a little about yourself…'}),
        }


class UserUpdateForm(forms.ModelForm):
    """Form for updating the base User fields from the profile page."""
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        qs = User.objects.filter(email=email).exclude(pk=self.instance.pk)
        if email and qs.exists():
            raise forms.ValidationError('A user with this email already exists.')
        return email


# Re-export Django's built-in PasswordChangeForm unchanged.
# It validates the old password, enforces AUTH_PASSWORD_VALIDATORS, and
# calls set_password() — no custom logic needed.
CustomPasswordChangeForm = PasswordChangeForm
