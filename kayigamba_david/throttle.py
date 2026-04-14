"""
throttle.py — Brute-force login protection for SYS_UAS.

Protection strategy: hybrid username + IP timed lockout
────────────────────────────────────────────────────────
* Account lockout : ACCOUNT_LOCKOUT_THRESHOLD failed attempts within
  LOCKOUT_WINDOW_MINUTES → cooldown for LOCKOUT_DURATION_MINUTES.
  Scoped by username — protects specific accounts against targeted guessing.

* IP lockout : IP_LOCKOUT_THRESHOLD failed attempts (any username) within
  the same window → IP is blocked.
  Protects against credential-spray attacks from a single source.

Why a timed cooldown and not a permanent lock?
  A permanent lockout can be weaponised to DoS accounts simply by repeatedly
  submitting wrong credentials.  A 15-minute cooldown is equally disruptive
  for automated attack tools while being self-healing for legitimate users.

Design decisions
────────────────
* Pure database — no cache server required; audit trail is durable.
* All constants are module-level so tests can monkey-patch them.
* get_client_ip() reads X-Forwarded-For to handle reverse-proxy deployments.
* Imports of LoginAttempt are deferred (inside functions) to avoid circular
  import issues at module load time.
"""

from datetime import timedelta

from django.utils import timezone

# ── Tuneable constants ────────────────────────────────────────────────────────

ACCOUNT_LOCKOUT_THRESHOLD = 5   # failed attempts before account cooldown
IP_LOCKOUT_THRESHOLD      = 20  # failed attempts (any user) before IP block
LOCKOUT_WINDOW_MINUTES    = 15  # sliding look-back window
LOCKOUT_DURATION_MINUTES  = 15  # how long a cooldown lasts


# ── IP extraction ─────────────────────────────────────────────────────────────

def get_client_ip(request):
    """
    Extract the real client IP from the request.
    Reads X-Forwarded-For first to handle reverse-proxy setups.
    The leftmost address in the chain is the original client.
    Falls back to REMOTE_ADDR if the header is absent.
    """
    forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


# ── Core API ──────────────────────────────────────────────────────────────────

def get_lockout_status(username, ip_address):
    """
    Return the current lockout state for a (username, IP) pair.

    Returned dict:
      is_locked          bool      – True → request must be blocked
      by                 str|None  – 'account', 'ip', or None
      attempts_used      int       – failures in window for this username
      attempts_remaining int       – failures still allowed before lockout
      lockout_until      datetime  – when the block lifts (None if unlocked)
    """
    from .models import LoginAttempt

    window_start = timezone.now() - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)

    account_failures = LoginAttempt.objects.filter(
        username=username,
        succeeded=False,
        timestamp__gte=window_start,
    ).count()

    ip_failures = LoginAttempt.objects.filter(
        ip_address=ip_address,
        succeeded=False,
        timestamp__gte=window_start,
    ).count()

    # ── Account-level lockout ─────────────────────────────────────────────
    if account_failures >= ACCOUNT_LOCKOUT_THRESHOLD:
        last = (
            LoginAttempt.objects
            .filter(username=username, succeeded=False)
            .order_by('-timestamp')
            .first()
        )
        lockout_until = last.timestamp + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        if timezone.now() < lockout_until:
            return {
                'is_locked':          True,
                'by':                 'account',
                'attempts_used':      account_failures,
                'attempts_remaining': 0,
                'lockout_until':      lockout_until,
            }

    # ── IP-level lockout ──────────────────────────────────────────────────
    if ip_failures >= IP_LOCKOUT_THRESHOLD:
        last = (
            LoginAttempt.objects
            .filter(ip_address=ip_address, succeeded=False)
            .order_by('-timestamp')
            .first()
        )
        lockout_until = last.timestamp + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        if timezone.now() < lockout_until:
            return {
                'is_locked':          True,
                'by':                 'ip',
                'attempts_used':      account_failures,
                'attempts_remaining': 0,
                'lockout_until':      lockout_until,
            }

    remaining = max(0, ACCOUNT_LOCKOUT_THRESHOLD - account_failures)
    return {
        'is_locked':          False,
        'by':                 None,
        'attempts_used':      account_failures,
        'attempts_remaining': remaining,
        'lockout_until':      None,
    }


def record_attempt(username, ip_address, *, succeeded):
    """Persist one login attempt for audit and throttle purposes."""
    from .models import LoginAttempt
    LoginAttempt.objects.create(
        username=username,
        ip_address=ip_address,
        succeeded=succeeded,
    )


def clear_failures(username, ip_address):
    """
    Delete in-window failure records for a username after successful login.

    Not strictly required — the window expires naturally — but immediately
    resets the counter so a user who struggled through several wrong attempts
    is not penalised when they return for their next legitimate session.
    """
    from .models import LoginAttempt
    window_start = timezone.now() - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
    LoginAttempt.objects.filter(
        username=username,
        succeeded=False,
        timestamp__gte=window_start,
    ).delete()
