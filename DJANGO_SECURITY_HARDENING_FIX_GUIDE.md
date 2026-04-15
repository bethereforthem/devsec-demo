# Django Security Hardening - Implementation Guide

## Overview

This guide provides step-by-step instructions to harden Django security configuration for production deployment. Implementation involves updating `settings.py` for environment-aware security settings and documenting environment variable requirements.

---

## Architecture Overview

### Environment-Based Configuration Pattern

```
Development Environment:
- DEBUG = True
- ALLOWED_HOSTS = ['localhost', '127.0.0.1']
- SESSION_COOKIE_SECURE = False
- SECURE_SSL_REDIRECT = False
- EMAIL_BACKEND = console

Production Environment:
- DEBUG = False
- ALLOWED_HOSTS = ['example.com', 'www.example.com']
- SESSION_COOKIE_SECURE = True
- SECURE_SSL_REDIRECT = True
- EMAIL_BACKEND = SMTP
- HSTS enabled
- CSP configured
```

---

## Fix 1: Environment Detection and Base Configuration

### File: `devsec_demo/settings.py`

Add environment detection at the top (after imports):

```python
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Environment Detection
# Set ENVIRONMENT=production for production deployment
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development').lower()
IS_PRODUCTION = ENVIRONMENT == 'production'
IS_DEVELOPMENT = ENVIRONMENT == 'development'

# Secret Key Management
# CRITICAL: Use secure, unique key for each environment
# Generate with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if IS_PRODUCTION:
        raise RuntimeError(
            'DJANGO_SECRET_KEY environment variable is required for production. '
            'Generate with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
        )
    else:
        # Development default (NOT for production)
        SECRET_KEY = 'django-insecure-dev-key-only-for-development'

# Debug Mode
# CRITICAL: Must be False in production
DEBUG = False if IS_PRODUCTION else os.environ.get('DJANGO_DEBUG', 'False').strip().lower() in ('true', '1', 'yes')

# Allowed Hosts
# CRITICAL: Must be specific to your domain in production
# Set via environment: ALLOWED_HOSTS=example.com,www.example.com,api.example.com
allowed_hosts_env = os.environ.get('ALLOWED_HOSTS', '')
if IS_PRODUCTION:
    if not allowed_hosts_env:
        raise RuntimeError(
            'ALLOWED_HOSTS environment variable required for production. '
            'Format: ALLOWED_HOSTS=example.com,www.example.com'
        )
    ALLOWED_HOSTS = [h.strip() for h in allowed_hosts_env.split(',')]
else:
    # Development defaults
    ALLOWED_HOSTS = allowed_hosts_env.split(',') if allowed_hosts_env else ['127.0.0.1', 'localhost']
```

**Why This Works:**

- Environment variable `ENVIRONMENT` determines configuration tier
- Production requires explicit SECRET_KEY (prevents accidental development keys in prod)
- ALLOWED_HOSTS enforced and configurable per environment
- Clear development defaults that are obviously insecure

---

## Fix 2: Session and Cookie Security

### File: `devsec_demo/settings.py`

Add after MIDDLEWARE configuration:

```python
# ── Session and Cookie Security ──────────────────────────────────────────────
# These settings protect session tokens and CSRF tokens from theft and MITM attacks

if IS_PRODUCTION:
    # Production: Strict cookie security
    # Prevent cookie transmission over unencrypted HTTP
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

    # Prevent JavaScript access to cookies (XSS mitigation)
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True

    # SameSite policy prevents CSRF attacks
    # Strict: most secure, may break some integrations
    # Lax: balances security and UX
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SAMESITE = 'Lax'

    # Cookie lifespan (2 weeks)
    SESSION_COOKIE_AGE = 1209600

    # Regenerate session ID on login (prevents session fixation)
    SESSION_SAVE_EVERY_REQUEST = False

else:
    # Development: Permissive for easier testing
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    CSRF_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SAMESITE = 'Lax'
```

**Why This Works:**

- `SECURE` flags prevent transmission over HTTP (MITM protection)
- `HTTPONLY` prevents JavaScript access (XSS cookie theft prevention)
- `SAMESITE` prevents cross-site CSRF attacks
- Environment-based toggles allow development flexibility

---

## Fix 3: HTTPS and Transport Security

### File: `devsec_demo/settings.py`

Add after session security:

```python
# ── HTTPS and Transport Security ─────────────────────────────────────────────
# These settings enforce secure HTTPS connections and prevent downgrade attacks

if IS_PRODUCTION:
    # Redirect all HTTP requests to HTTPS
    SECURE_SSL_REDIRECT = True

    # HTTP Strict Transport Security (HSTS)
    # Tells browser to ALWAYS use HTTPS for this domain
    # max_age: 1 year (31536000 seconds)
    SECURE_HSTS_SECONDS = 31536000

    # Apply HSTS to all subdomains
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True

    # Add domain to HSTS preload list (hardcoded in browsers)
    # Only set if you control the domain and can guarantee HTTPS forever
    SECURE_HSTS_PRELOAD = False  # Set to True after domain verification

    # Prevent proxy/middleware from stripping SSL
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

else:
    # Development: Allow plain HTTP for local testing
    SECURE_SSL_REDIRECT = False
    SECURE_HSTS_SECONDS = 0
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False
```

**Why This Works:**

- `SECURE_SSL_REDIRECT` forces HTTPS (prevents credential interception)
- `SECURE_HSTS_*` prevents browser downgrade to HTTP
- `SECURE_PROXY_SSL_HEADER` works with reverse proxies (nginx, load balancers)

---

## Fix 4: Security Headers and Content Protection

### File: `devsec_demo/settings.py`

Add after HTTPS security:

```python
# ── Security Headers ─────────────────────────────────────────────────────────
# HTTP headers that instruct browsers to enforce security policies

if IS_PRODUCTION:
    # Prevent clickjacking attacks
    # DENY: Page cannot be framed at all
    # SAMEORIGIN: Can only be framed by same-origin pages
    X_FRAME_OPTIONS = 'DENY'

    # Prevent MIME type sniffing
    # Forces browser to trust Content-Type header
    SECURE_CONTENT_TYPE_NOSNIFF = True

    # Enable XSS filter in older browsers
    SECURE_BROWSER_XSS_FILTER = True

    # Referrer Policy
    # Limits referrer information sent to external sites
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

    # Content Security Policy
    # Whitelist trusted sources for scripts, styles, images, etc.
    SECURE_CONTENT_SECURITY_POLICY = {
        # Default: only allow from same origin
        'default-src': ("'self'",),

        # Scripts: only from same origin
        'script-src': ("'self'",),

        # Styles: same origin + unsafe-inline (for Django admin)
        'style-src': ("'self'", "'unsafe-inline'"),

        # Images: same origin, data URIs, HTTPS external
        'img-src': ("'self'", 'data:', 'https:'),

        # Fonts: same origin only
        'font-src': ("'self'",),

        # AJAX/Fetch: same origin only
        'connect-src': ("'self'",),

        # Prevent framing in iframes
        'frame-ancestors': ("'none'",),

        # Form submission restrictions
        'form-action': ("'self'",),

        # Require HTTPS for embedded content
        'upgrade-insecure-requests': [],
    }

else:
    # Development: More permissive for testing
    X_FRAME_OPTIONS = 'SAMEORIGIN'
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = False
    SECURE_REFERRER_POLICY = 'same-origin'
    SECURE_CONTENT_SECURITY_POLICY = {
        'default-src': ("'self'", 'http://localhost:*'),
        'script-src': ("'self'", "'unsafe-inline'"),
        'style-src': ("'self'", "'unsafe-inline'"),
    }
```

**Why This Works:**

- `X_FRAME_OPTIONS` prevents clickjacking attacks
- `Content-Type-Options: nosniff` prevents browser from guessing file types
- `CSP` is the most powerful header - whitelists all trusted resources
- Headers layered for defense-in-depth

---

## Fix 5: Database Configuration for Production

### File: `devsec_demo/settings.py`

Update DATABASES section:

```python
# ── Database Configuration ──────────────────────────────────────────────────
# SQLite suitable only for development; use PostgreSQL/MySQL in production

if IS_PRODUCTION:
    # Production: Use PostgreSQL (more secure, handles concurrency)
    DATABASES = {
        'default': {
            'ENGINE': os.environ.get(
                'DATABASE_ENGINE',
                'django.db.backends.postgresql'
            ),
            'NAME': os.environ.get('DATABASE_NAME'),
            'USER': os.environ.get('DATABASE_USER'),
            'PASSWORD': os.environ.get('DATABASE_PASSWORD'),
            'HOST': os.environ.get('DATABASE_HOST'),
            'PORT': os.environ.get('DATABASE_PORT', '5432'),
            # Security: Require SSL for database connections
            'OPTIONS': {
                'sslmode': 'require',
            } if 'postgres' in os.environ.get('DATABASE_ENGINE', '').lower() else {},
        }
    }
    # Verify all required database settings are present
    required_db_settings = ['DATABASE_NAME', 'DATABASE_USER', 'DATABASE_PASSWORD', 'DATABASE_HOST']
    for setting in required_db_settings:
        if not os.environ.get(setting):
            raise RuntimeError(f'{setting} environment variable is required for production')
else:
    # Development: SQLite is convenient (only for local testing)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
```

**Why This Works:**

- SQLite not suitable for production (single file, no concurrency control)
- PostgreSQL provides better security and performance
- SSL required for database connections (encryption in transit)
- Environment-based configuration enforces production requirements

---

## Fix 6: Email Configuration for Production

### File: `devsec_demo/settings.py`

Update email configuration:

```python
# ── Email Configuration ──────────────────────────────────────────────────────
# Console backend only for development; use SMTP in production

if IS_PRODUCTION:
    # Production: Real SMTP server for sending emails
    EMAIL_BACKEND = os.environ.get(
        'EMAIL_BACKEND',
        'django.core.mail.backends.smtp.EmailBackend'
    )
    EMAIL_HOST = os.environ.get('EMAIL_HOST')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
    EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() in ('true', '1')
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', f'{EMAIL_HOST_USER}@example.com')

    # Verify email settings are configured
    if not EMAIL_HOST or not EMAIL_HOST_USER or not EMAIL_HOST_PASSWORD:
        raise RuntimeError('Email configuration requires EMAIL_HOST, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD')
else:
    # Development: Print emails to console (safe for testing)
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    DEFAULT_FROM_EMAIL = 'test@localhost'
```

**Why This Works:**

- Console backend prevents accidental email sending during development
- SMTP backend for production with TLS encryption
- Explicit configuration prevents misconfiguration

---

## Fix 7: Additional Hardening Settings

### File: `devsec_demo/settings.py`

Add at end of security settings:

```python
# ── Additional Security Settings ────────────────────────────────────────────

if IS_PRODUCTION:
    # Prevent form data from being cached by browsers (history sniffing risk)
    CSRF_TRUSTED_ORIGINS = []  # Set via env if needed: CSRF_TRUSTED_ORIGINS=https://trusted.com

    # Logging configuration (log security events)
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '[%(asctime)s] %(levelname)s - %(name)s - %(message)s'
            },
        },
        'handlers': {
            'file': {
                'level': 'WARNING',
                'class': 'logging.FileHandler',
                'filename': BASE_DIR / 'logs' / 'django_security.log',
                'formatter': 'verbose',
            },
            'console': {
                'level': 'WARNING',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'django': {
                'handlers': ['file', 'console'],
                'level': 'WARNING',
                'propagate': True,
            },
            'kayigamba_david': {
                'handlers': ['file', 'console'],
                'level': 'INFO',
                'propagate': True,
            },
        },
    }

    # Ensure logs directory exists
    logs_dir = BASE_DIR / 'logs'
    logs_dir.mkdir(exist_ok=True)

else:
    # Development: Minimal logging
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
    }

# Signing method for tokens (password reset, etc.)
# Uses default HMAC with SHA256 (secure)
SIGNING_BACKEND = 'django.core.signing.TimestampSigner'

# Password reset timeout (already set but document it)
# 1 hour = 3600 seconds (limits exposure if link leaked)
PASSWORD_RESET_TIMEOUT = 3600
```

---

## Fix 8: Environment Variable Documentation

### File: `.env.example` (NEW - for documentation)

Create this file to document required environment variables:

```bash
# ==============================================================================
# DJANGO SECURITY CONFIGURATION - Environment Variables
# ==============================================================================
# Copy this file to .env and fill in production values
# NEVER commit .env to version control!
# Add to .gitignore: .env, .env.*.local

# Environment Tier
# Options: development, production
ENVIRONMENT=development

# ==============================================================================
# SECRET MANAGEMENT
# ==============================================================================
# CRITICAL: Generate unique key for each environment
# Generate with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
# MUST be 50+ characters and unpredictable
DJANGO_SECRET_KEY=<your-50-character-secret-key-here>

# ==============================================================================
# DEBUG MODE
# ==============================================================================
# CRITICAL: Must be False in production
# Set to True only during development
DJANGO_DEBUG=False

# ==============================================================================
# ALLOWED HOSTS
# ==============================================================================
# Production: Comma-separated list of your domain(s)
# Example: example.com,www.example.com,api.example.com
# Development: Can be empty (defaults to localhost, 127.0.0.1)
ALLOWED_HOSTS=example.com,www.example.com

# ==============================================================================
# DATABASE CONFIGURATION (Production)
# ==============================================================================
# For development: SQLite is used automatically
# For production: PostgreSQL recommended

DATABASE_ENGINE=django.db.backends.postgresql
DATABASE_NAME=devsec_prod
DATABASE_USER=devsec_user
DATABASE_PASSWORD=<strong-password-here>
DATABASE_HOST=db.example.com
DATABASE_PORT=5432

# ==============================================================================
# EMAIL CONFIGURATION (Production)
# ==============================================================================
# For development: Emails printed to console
# For production: Use real SMTP server

EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=noreply@example.com
EMAIL_HOST_PASSWORD=<gmail-app-password-here>
DEFAULT_FROM_EMAIL=noreply@example.com

# ==============================================================================
# HTTPS / SECURITY HEADERS
# ==============================================================================
# These are configured in settings.py based on ENVIRONMENT variable
# No need to set via environment unless overriding defaults

# ==============================================================================
# CSRF TRUSTED ORIGINS (if needed)
# ==============================================================================
# Comma-separated list of origins allowed to POST to your site
# Example: https://trusted-api.com,https://app.example.com
# CSRF_TRUSTED_ORIGINS=https://trusted.com

# ==============================================================================
# APPLICATION SETTINGS
# ==============================================================================
DJANGO_EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
DJANGO_DEFAULT_FROM_EMAIL=noreply@example.com
DJANGO_PASSWORD_RESET_TIMEOUT=3600

# ==============================================================================
# OPTIONAL: ADVANCED SETTINGS
# ==============================================================================
# Uncomment and configure as needed

# Sentry (error tracking)
# SENTRY_DSN=https://key@sentry.io/project-id

# Redis (caching, sessions)
# REDIS_URL=redis://localhost:6379/0

# AWS S3 (static files, media)
# AWS_ACCESS_KEY_ID=<key>
# AWS_SECRET_ACCESS_KEY=<secret>
# AWS_STORAGE_BUCKET_NAME=bucket-name
```

---

## Fix 9: Update .gitignore

### File: `.gitignore`

Ensure environment files are NOT committed:

```
# ── Environment Variables ──
.env
.env.local
.env.*.local
!.env.example

# ── Database (development only) ──
db.sqlite3
*.sqlite
*.sqlite3

# ── Logs ──
logs/
*.log

# ── Secrets ──
secrets/
*.key
*.pem
```

---

## Verification Checklist

### Django Check Command

```bash
# Test configured settings
python manage.py check --deploy

# Expected: No errors or warnings (or only expected warnings)
```

### Security Verification

```bash
# Log configuration
python manage.py shell
>>> from django.conf import settings
>>> settings.SECURE_SSL_REDIRECT
True
>>> settings.SESSION_COOKIE_SECURE
True
>>> settings.SESSION_COOKIE_HTTPONLY
True
```

### environment Validation

```bash
# Verify environment variables loaded correctly
ENVIRONMENT=production python manage.py shell
>>> from django.conf import settings
>>> settings.DEBUG
False
>>> settings.IS_PRODUCTION
True
```

---

## Production Deployment Checklist

- [ ] Set ENVIRONMENT=production
- [ ] Generate unique SECRET_KEY for production
- [ ] Configure ALLOWED_HOSTS with your domain(s)
- [ ] Set DATABASE\_\* variables for PostgreSQL
- [ ] Configure EMAIL\_\* variables for SMTP
- [ ] Ensure .env is NOT in git (add to .gitignore)
- [ ] Verify DEBUG=False
- [ ] Test with `python manage.py check --deploy`
- [ ] Verify HTTPS certificate is valid
- [ ] Test HSTS headers with curl
- [ ] Verify CSP headers in browser
- [ ] Test session security with browser dev tools
- [ ] Monitor logs for errors

---

## Complete Settings.py Structure

After implementing all fixes, your `settings.py` should have this structure:

```
1. Imports and Load Environment
2. Environment Detection (IS_PRODUCTION, IS_DEVELOPMENT)
3. Base Path Configuration
4. Secret Key Management
5. Debug and Allowed Hosts
6. Application Definition (INSTALLED_APPS, MIDDLEWARE, etc.)
7. URL Configuration
8. Templates Configuration
9. Database Configuration
10. Password Validators
11. Internationalization
12. Static Files
13. Session and Cookie Security ← FIX 2
14. HTTPS and Transport Security ← FIX 3
15. Security Headers ← FIX 4
16. Database Configuration ← FIX 5
17. Email Configuration ← FIX 6
18. Logging and Additional Security ← FIX 7
19. Authentication Redirects
20. Default Primary Key
```

---

## Common Mistakes to Avoid

❌ **Don't:** Commit .env files to git

```bash
git add .env  # DANGER - secrets exposed
```

✅ **Do:** Add to .gitignore and use .env.example

```bash
echo ".env" >> .gitignore
cp .env .env.example
git add .env.example
```

---

❌ **Don't:** Use same SECRET_KEY for all environments

```python
SECRET_KEY = 'my-secret-key-used-everywhere'  # DANGER
```

✅ **Do:** Generate unique key per environment

```bash
# Generate for production
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
# Store in ENVIRONMENT-specific .env or secrets manager
```

---

❌ **Don't:** Leave DEBUG=True in production

```python
DEBUG = True  # DANGER - exposes sensitive info
```

✅ **Do:** Use environment-based DEBUG

```python
DEBUG = False if IS_PRODUCTION else True
```

---

❌ **Don't:** Use SQLite in production

```python
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3'}}  # DANGER
```

✅ **Do:** Use PostgreSQL with SSL

```python
DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql'}}
# With OPTIONS: {'sslmode': 'require'}
```
