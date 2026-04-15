# Django Security Hardening - Quick Reference (30 Minutes)

## ⚡ TL;DR - Critical Production Fixes

Production Django requires these 3 essential setting blocks. No file uploads, no complexity—just settings.

---

## 1️⃣ ENVIRONMENT DETECTION (2 minutes)

Add at top of `devsec_demo/settings.py` after imports:

```python
import os
from dotenv import load_dotenv

load_dotenv()

# Environment Detection
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development').lower()
IS_PRODUCTION = ENVIRONMENT == 'production'
IS_DEVELOPMENT = ENVIRONMENT == 'development'
```

**Set via environment variable:**

```bash
# Development (default)
export ENVIRONMENT=development

# Production
export ENVIRONMENT=production
```

---

## 2️⃣ SECRET & HOST SETTINGS (3 minutes)

Replace existing SECRET_KEY section with:

```python
# Secret Key - UNIQUE per environment
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if IS_PRODUCTION:
        raise RuntimeError('DJANGO_SECRET_KEY required for production')
    SECRET_KEY = 'django-insecure-dev-key'

# Debug Mode - MUST be False in production
DEBUG = False if IS_PRODUCTION else os.environ.get('DJANGO_DEBUG', 'False').lower() in ('true', '1')

# Allowed Hosts - specify your domain(s)
allowed_hosts_env = os.environ.get('ALLOWED_HOSTS', '')
if IS_PRODUCTION:
    if not allowed_hosts_env:
        raise RuntimeError('Set ALLOWED_HOSTS for production')
    ALLOWED_HOSTS = [h.strip() for h in allowed_hosts_env.split(',')]
else:
    ALLOWED_HOSTS = allowed_hosts_env.split(',') if allowed_hosts_env else ['127.0.0.1', 'localhost']
```

**Set environment variables in production .env:**

```bash
ENVIRONMENT=production
DJANGO_SECRET_KEY=<generate-with-command-below>
ALLOWED_HOSTS=example.com,www.example.com

# Generate SECRET_KEY:
# python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

---

## 3️⃣ SESSION & COOKIE SECURITY (5 minutes)

Add after MIDDLEWARE in settings.py:

```python
if IS_PRODUCTION:
    # Prevent cookie transmission over HTTP
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

    # Prevent JavaScript access to cookies
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True

    # Cross-site request forgery protection
    SESSION_COOKIE_SAMESITE = 'Lax'
    CSRF_COOKIE_SAMESITE = 'Lax'

else:
    # Development: Allow testing
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    CSRF_COOKIE_SAMESITE = 'Lax'
```

---

## 4️⃣ HTTPS & TRANSPORT SECURITY (5 minutes)

Add after session security:

```python
if IS_PRODUCTION:
    # Force HTTPS connections
    SECURE_SSL_REDIRECT = True

    # Tell browser to always use HTTPS
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = False  # Set to True after domain verification

    # For reverse proxy setups (nginx, load balancers)
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

else:
    # Development
    SECURE_SSL_REDIRECT = False
    SECURE_HSTS_SECONDS = 0
```

---

## 5️⃣ SECURITY HEADERS (5 minutes)

Add after HTTPS security:

```python
if IS_PRODUCTION:
    # Prevent clickjacking
    X_FRAME_OPTIONS = 'DENY'

    # Prevent MIME sniffing
    SECURE_CONTENT_TYPE_NOSNIFF = True

    # Enable XSS filter (older browsers)
    SECURE_BROWSER_XSS_FILTER = True

    # Referrer policy (don't leak URLs)
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

    # Content Security Policy (prevents script injection)
    SECURE_CONTENT_SECURITY_POLICY = {
        'default-src': ("'self'",),
        'script-src': ("'self'",),
        'style-src': ("'self'", "'unsafe-inline'"),
        'img-src': ("'self'", 'data:', 'https:'),
        'font-src': ("'self'",),
        'connect-src': ("'self'",),
        'frame-ancestors': ("'none'",),
        'form-action': ("'self'",),
    }
else:
    X_FRAME_OPTIONS = 'SAMEORIGIN'
    SECURE_CONTENT_TYPE_NOSNIFF = True
```

---

## 6️⃣ DATABASE CONFIGURATION (5 minutes)

Replace DATABASES section:

```python
if IS_PRODUCTION:
    # Use PostgreSQL in production
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('DATABASE_NAME'),
            'USER': os.environ.get('DATABASE_USER'),
            'PASSWORD': os.environ.get('DATABASE_PASSWORD'),
            'HOST': os.environ.get('DATABASE_HOST'),
            'PORT': os.environ.get('DATABASE_PORT', '5432'),
            'OPTIONS': {
                'sslmode': 'require',  # Require SSL for database
            }
        }
    }
else:
    # SQLite for development only
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
```

**Production environment variables:**

```bash
DATABASE_NAME=mydb
DATABASE_USER=myuser
DATABASE_PASSWORD=strong-password
DATABASE_HOST=db.example.com
DATABASE_PORT=5432
```

---

## 🎯 VERIFICATION CHECKLIST

After making changes:

```bash
# 1. Run Django security check
python manage.py check --deploy

# 2. Test development mode
export ENVIRONMENT=development
python manage.py runserver
# Visit http://localhost:8000 - should work

# 3. Test HTTPS redirect (requires HTTPS setup)
export ENVIRONMENT=production
export DJANGO_SECRET_KEY=$(python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")
export ALLOWED_HOSTS=localhost,127.0.0.1
python manage.py check --deploy
# Should show no security warnings
```

---

## 🔧 ENVIRONMENT SETUP

### Development (.env)

```bash
ENVIRONMENT=development
DJANGO_DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_SECRET_KEY=django-insecure-dev-key
```

### Production (.env or container secrets)

```bash
ENVIRONMENT=production
DJANGO_DEBUG=False
ALLOWED_HOSTS=example.com,www.example.com
DJANGO_SECRET_KEY=<secure-50-char-key>
DATABASE_NAME=proddb
DATABASE_USER=produser
DATABASE_PASSWORD=<strong-password>
DATABASE_HOST=db.example.com
```

---

## ❌ COMMON MISTAKES (Avoid These!)

| ❌ Wrong                     | ✅ Right                            |
| ---------------------------- | ----------------------------------- |
| `DEBUG = True` in production | Use environment variable            |
| Same SECRET_KEY in all envs  | Generate unique key per environment |
| SQLite in production         | Use PostgreSQL/MySQL                |
| No ALLOWED_HOSTS check       | Validate before deploying           |
| HTTP in production           | Must enforce HTTPS                  |
| No HSTS header               | Add SECURE_HSTS_SECONDS             |
| Cookies without SECURE flag  | Always set in production            |
| No CSP header                | Implement Content-Security-Policy   |
| Shared .env file             | Use environment-specific secrets    |

---

## 🚀 QUICK DEPLOY

```bash
# 1. Update settings.py with all 6 fixes above
# 2. Create production .env file
# 3. Test locally
python manage.py check --deploy

# 4. Deploy
export $(cat .env.production | xargs)
export ENVIRONMENT=production
python manage.py migrate
python manage.py collectstatic --noinput
gunicorn devsec_demo.wsgi:application

# 5. Verify headers
curl -i https://your-domain.com | grep -i secure
```

---

## 📋 BEFORE/AFTER SUMMARY

### BEFORE (Insecure)

```
✗ DEBUG=True - exposes errors
✗ No SECURE cookies - hijackable via MITM
✗ No HTTPS redirect - downgradeable
✗ No HSTS - browser doesn't enforce HTTPS
✗ No CSP - XSS can run arbitrary JavaScript
✗ SQLite database - not for production
✗ ALLOWED_HOSTS not validated
```

### AFTER (Hardened)

```
✓ DEBUG=False - hides errors
✓ SECURE + HTTPONLY cookies - MITM + XSS resistant
✓ HTTPS redirect - all traffic encrypted
✓ HSTS enabled - browser enforces HTTPS
✓ CSP configured - limits XSS impact
✓ PostgreSQL - production-ready database
✓ ALLOWED_HOSTS enforced - prevents Host header attacks
```

---

## 🧪 TESTING COMMANDS

### Check Security Headers

```bash
curl -i https://your-domain.com | grep -E "Strict-Transport|X-Frame|CSP|X-Content"
```

### Verify Cookie Flags

```bash
# Browser DevTools → Application → Cookies
# Confirm: ✓ Secure, ✓ HttpOnly, ✓ SameSite=Lax
```

### Validate Django Configuration

```bash
python manage.py check --deploy
```

### Test HTTP to HTTPS redirect

```bash
curl -i http://your-domain.com/
# Should see: 301 Moved Permanently to HTTPS
```

---

## 📚 REFERENCE LINKS

- [Django Deployment Checklist](https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/)
- [OWASP Production Security Headers](https://owasp.org/www-project-secure-headers/)
- [Mozilla Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Content Security Policy MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

## ⏱️ TIME ESTIMATE

| Step                    | Time       |
| ----------------------- | ---------- |
| Environment detection   | 2 min      |
| Secret & host config    | 3 min      |
| Session/cookie security | 5 min      |
| HTTPS enforcement       | 5 min      |
| Security headers        | 5 min      |
| Database config         | 5 min      |
| Testing                 | 5 min      |
| **Total**               | **30 min** |

All changes are in `settings.py` only—no other files to modify!
