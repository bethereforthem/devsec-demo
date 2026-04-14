# Audit Logging Implementation

## Overview

Audit logging provides a security-relevant event trail for the authentication system. All critical authentication events (registration, login, logout, password changes, password resets) are now logged to the database with IP address, timestamp, and user agent information.

**Learning Objective:** Audit logging is a critical part of secure engineering because it provides observability—the ability to review and investigate security events after they occur.

## Why Audit Logging Matters

### Accountability

- Who did what, when, and from where
- Establishes a timeline of events for forensic investigation
- Helps identify attack patterns and compromised accounts

### Compliance

- Many regulations (GDPR, HIPAA, SOC 2) require security event logging
- Demonstrates that the application can trace user actions
- Supports incident response and breach notification

### Threat Detection

- Identify brute-force attacks in progress
- Detect unusual login patterns or locations
- Find password reset abuse
- Spot privilege escalation attempts

## Architecture

### AuditLog Model

Located in `kayigamba_david/models.py`:

```python
class AuditLog(models.Model):
    event_type = CharField()        # What happened (login, logout, etc.)
    user = ForeignKey(User)         # Who did it (may be null for failed login)
    username = CharField()          # Username (always recorded, even if user doesn't exist)
    ip_address = GenericIPAddressField()  # Where from (for forensics)
    user_agent = TextField()        # Browser/client info
    timestamp = DateTimeField()     # When it happened (indexed for fast queries)
    description = TextField()       # Human-readable summary (no secrets)
    details = JSONField()           # Structured metadata (no secrets)
```

**Key Features:**

- Timestamps indexed for quick range queries ("show me logins from last 7 days")
- Compound indexes on (event_type, timestamp) and (username, timestamp) for forensic queries
- Username field always populated—even for failed logins where the user may not exist
- User field can be null for events that occur before authentication

### Audit Logging Utility (`audit.py`)

Provides high-level functions to log events:

- `log_registration()` — New user registration
- `log_login_success()` — Successful authentication
- `log_login_failure()` — Failed login attempt
- `log_logout()` — User logout
- `log_password_change()` — User-initiated password change
- `log_password_reset_request()` — Password reset request
- `log_password_reset_confirm()` — Password reset token consumed
- `log_permission_grant()` — Permission/group granted
- `log_permission_revoke()` — Permission/group revoked

**Security Design:**
All functions extract IP and user agent from the request object automatically. No passwords, tokens, or sensitive data are ever logged.

## Integration Points

### View Integration

#### Registration (`register_view`)

```python
if form.is_valid():
    user = form.save()
    UserProfile.objects.create(user=user)
    login(request, user)
    log_registration(request, user)  # ← Audit log entry
    return redirect('kayigamba_david:dashboard')
```

#### Login Success (`login_view`)

```python
if form.is_valid():
    user = form.get_user()
    login(request, user)
    record_attempt(username, ip, succeeded=True)
    clear_failures(username, ip)
    log_login_success(request, user)  # ← Audit log entry
    messages.success(request, f'Welcome back, {user.username}!')
```

#### Login Failure (`login_view`)

```python
else:
    record_attempt(username, ip, succeeded=False)
    log_login_failure(request, username, 'invalid credentials')  # ← Audit log entry
    lockout_info = get_lockout_status(username, ip)
```

#### Logout (`logout_view`)

```python
if request.method == 'POST':
    user = request.user
    log_logout(request, user)  # ← Audit log entry
    logout(request)
    messages.info(request, 'You have been logged out.')
```

#### Password Change (`change_password_view`)

```python
if form.is_valid():
    user = form.save()
    update_session_auth_hash(request, user)
    log_password_change(request, user)  # ← Audit log entry
    messages.success(request, 'Your password has been changed successfully.')
```

#### Password Reset (Custom CBVs)

```python
class CustomPasswordResetView(PasswordResetView):
    def form_valid(self, form):
        email = form.cleaned_data.get('email', '')
        # ... get username ...
        log_password_reset_request(self.request, username, email)  # ← Audit log entry
        return super().form_valid(form)

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    def form_valid(self, form):
        user = form.save()
        log_password_reset_confirm(self.request, user)  # ← Audit log entry
        return super().form_valid(form)
```

## What Gets Logged

### Registration

```
Event: registration
User: newly created user
Description: User registration (alice)
Details:
  - email: alice@example.com
  - is_staff: false
  - is_superuser: false
IP: 192.168.1.100
User-Agent: Mozilla/5.0 ...
Timestamp: 2024-01-15 10:30:45 UTC
```

### Login Success

```
Event: login_success
User: authenticated user
Username: alice
Description: Login successful (alice)
Details:
  - is_staff: false
  - is_superuser: false
  - last_login_before: 2024-01-14 15:22:10
IP: 192.168.1.100
Timestamp: 2024-01-15 10:30:45 UTC
```

### Login Failure

```
Event: login_failure
User: null (authentication failed, user may not exist)
Username: attacker (attempted username)
Description: Login failed (attacker): invalid credentials
Details:
  - reason: invalid credentials
IP: 192.168.1.105
Timestamp: 2024-01-15 10:30:45 UTC
```

### Logout

```
Event: logout
User: authenticated user
Username: alice
Description: User logged out (alice)
Details: {} (empty)
IP: 192.168.1.100
Timestamp: 2024-01-15 11:45:30 UTC
```

### Password Change

```
Event: password_change
User: authenticated user
Username: alice
Description: Password changed (alice)
Details: {} (empty, no password info)
IP: 192.168.1.100
Timestamp: 2024-01-15 11:50:15 UTC
```

### Password Reset Request

```
Event: password_reset_request
User: null (request made before authentication)
Username: alice
Description: Password reset requested (alice)
Details:
  - email_provided: alice@example.com
IP: 192.168.1.100
Timestamp: 2024-01-15 12:00:00 UTC
```

## What Does NOT Get Logged (Security)

### Never Logged

- ❌ Raw passwords (old or new)
- ❌ Password reset tokens or links
- ❌ Session tokens or JWT secrets
- ❌ API keys or authentication credentials
- ❌ Credit card numbers or sensitive PII
- ❌ Form data beyond usernames

### Why

These are secrets that if exposed in logs could compromise the system:

- Logs may be accidentally shared or archived
- Developers with log access shouldn't see user passwords
- Compliance regulations (PCI-DSS, HIPAA) forbid logging payment data
- Log retention policies may keep data longer than intended

## Testing

### Test Coverage (10 tests)

1. **test_registration_is_logged** — Verify registration creates audit log entry with no password
2. **test_login_success_is_logged** — Verify successful login is logged
3. **test_login_failure_is_logged** — Verify failed login attempts are logged
4. **test_logout_is_logged** — Verify logout is logged
5. **test_password_change_is_logged** — Verify password change is logged without new password
6. **test_password_reset_request_is_logged** — Verify reset request is logged
7. **test_audit_log_contains_ip_and_useragent** — Verify forensics-critical data is captured
8. **test_audit_log_has_structured_data** — Verify details field has structured metadata
9. **test_audit_log_timestamp_is_recorded** — Verify timestamps are accurate
10. **test_multiple_login_attempts_are_separately_logged** — Verify each event has its own entry

Run tests:

```bash
python manage.py test kayigamba_david.tests.AuditLoggingTests
```

All tests pass with no leakage of sensitive data.

## Usage Examples

### Forensic Investigation

After a suspicious login, find all attempts from that IP:

```python
from .models import AuditLog

# Find all login attempts from suspicious IP
suspicious_attempts = AuditLog.objects.filter(
    ip_address='192.168.1.105',
    event_type__in=[
        AuditLog.EVENT_LOGIN_SUCCESS,
        AuditLog.EVENT_LOGIN_FAILURE
    ]
).order_by('-timestamp')

for log in suspicious_attempts:
    print(f"{log.timestamp}: {log.description} from {log.ip_address}")
```

### Brute Force Detection

Find repeated failed login attempts on the same account:

```python
from django.utils import timezone
from datetime import timedelta

# Look for failed logins in the last hour
one_hour_ago = timezone.now() - timedelta(hours=1)

failed = AuditLog.objects.filter(
    event_type=AuditLog.EVENT_LOGIN_FAILURE,
    username='alice',
    timestamp__gte=one_hour_ago
).count()

if failed > 10:
    alert("Possible brute force attack on alice")
```

### Privilege Change Audit

Find when a user was promoted to admin:

```python
promotion = AuditLog.objects.filter(
    event_type=AuditLog.EVENT_PERMISSION_GRANT,
    username='alice',
    details__group='Admin'
).order_by('-timestamp').first()

if promotion:
    print(f"Alice promoted to Admin on {promotion.timestamp}")
    print(f"Promoted by: {promotion.details['granted_by']}")
    print(f"From: {promotion.ip_address}")
```

### User Activity Timeline

Get complete activity for a user:

```python
user_activity = AuditLog.objects.filter(
    username='alice'
).order_by('-timestamp')[:50]  # Last 50 events

for log in user_activity:
    print(f"{log.timestamp}: {log.event_type.upper()} - {log.description}")
```

## Database Queries

The AuditLog model is optimized for forensic queries:

```sql
-- Find logins from a specific IP in date range
SELECT * FROM kayigamba_david_auditlog
WHERE ip_address = '192.168.1.100'
  AND event_type IN ('login_success', 'login_failure')
  AND timestamp BETWEEN '2024-01-01' AND '2024-01-31'
ORDER BY timestamp DESC;

-- Find all password reset attempts
SELECT * FROM kayigamba_david_auditlog
WHERE event_type LIKE 'password_reset%'
ORDER BY timestamp DESC;

-- Find audit events for a specific user (case-insensitive search)
SELECT * FROM kayigamba_david_auditlog
WHERE username = 'alice'
ORDER BY timestamp DESC;

-- Performance: Use indexes for fast queries
-- Indexes present on: (event_type, timestamp), (username, timestamp), (user_id, timestamp)
```

## Compliance Notes

### GDPR (EU General Data Protection Regulation)

- ✅ Logs user actions with timestamps (Article 5.1.f — integrity and confidentiality)
- ✅ Logs IP addresses for forensic purposes
- ⚠️ Consider log retention policy (may need to delete old logs after N days)
- ⚠️ Users may request their audit logs under GDPR subject access requests

### HIPAA (Health Insurance Portability and Accountability Act)

- ✅ Logs all access to the system (required for covered entities)
- ✅ No passwords or PHI in the logs
- ⚠️ Logs should be retained for X years per policy
- ⚠️ Restrict access to logs (not everyone can read them)

### SOC 2 Type II

- ✅ Demonstrates C1 (security monitoring and alerting)
- ✅ Event logs with timestamps for investigation
- ⚠️ Should be combined with regular log review procedures

## Best Practices

1. **Regular Review**: Schedule monthly or quarterly log reviews for suspicious patterns
2. **Don't Log Secrets**: Never add password, token, or credit card fields to audit logs
3. **Retention Policy**: Define how long logs are kept (e.g., 90 days to 2 years)
4. **Access Control**: Restrict who can view audit logs (treat like security-sensitive data)
5. **Alerting**: Set up alerts for high-risk events (multiple failures, privilege grants)
6. **Archive**: Move old logs to cold storage (S3, Azure Blob) for long-term retention
7. **Correlation**: Cross-reference with web server logs and firewall logs

## Troubleshooting

### Audit logs not appearing

1. Verify migration was applied: `python manage.py migrate`
2. Check if log entry succeeded in database: `python manage.py shell` → `AuditLog.objects.count()`
3. Verify imports are correct in views.py
4. Check for any exception during view execution

### Sensitive data accidentally logged

1. ✅ Current implementation: No passwords, tokens, or PII in logs
2. ✅ Audit log functions strip secrets before recording
3. ⚠️ If custom code logs events, be careful what you include in `details` dict

### Performance issues with large audit log table

1. Use indexes: Already added on (event_type, timestamp), (username, timestamp)
2. Archive old logs: Move logs older than 6 months to separate table or delete
3. Query optimization: Always use indexed fields in WHERE clauses
4. Monitor: Check slow query logs for table scans

## Future Enhancements

1. **Log Compression**: Archive old logs to S3/Azure with compression
2. **Real-time Alerts**: Send notifications for high-risk events (repeated failures, privilege grant)
3. **Dashboard**: Create admin dashboard showing login patterns, failed attempts, etc.
4. **SIEM Integration**: Send logs to centralized SIEM (Splunk, ELK Stack, etc.)
5. **Log Signing**: Cryptographically sign logs to prevent tampering
6. **Automated Cleanup**: Purge logs older than retention period automatically

## References

- [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [NIST: Computer Security Log Management Guidelines](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf)
- [Django: Logging Documentation](https://docs.djangoproject.com/en/6.0/topics/logging/)
