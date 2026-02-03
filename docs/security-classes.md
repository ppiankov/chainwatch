# Chainwatch Security Classes

**Status:** Extension to authority boundary detection
**Philosophy:** Irreversible architectural violations, not exploitable bugs

---

## Overview

These are not vulnerability classes. These are **root architectural violations** that make compromise inevitable, regardless of implementation quality.

Chainwatch treats these as **authority boundary violations** - once these patterns exist, the system cannot be trusted, even if no exploit has occurred yet.

**Principle:** If a system design allows irreversible trust capture, the system is already compromised.

---

## CW-01: Unbounded Authentication Artifacts

### Definition

Authentication artifacts (tokens, magic links, bot tokens) that have **no contextual boundaries**:
- Not bound to device
- Not bound to time
- Not bound to network context
- Grant full or broad access

### Why This Is Root-Level

Anyone who obtains the artifact once owns the system indefinitely.

This is not a bug. This is a **structural property** of the authentication design.

### Examples

**❌ Forbidden:**
```yaml
# Magic link with no expiration or single-use constraint
magic_link:
  ttl: null
  single_use: false
  device_binding: none

# JWT with no audience or device binding
jwt:
  audience: "*"
  device_id: null
  expires: 30_days

# Bot token with user-level permissions
bot_token:
  scope: "admin"
  context_binding: none
  revocable: false
```

**✅ Acceptable:**
```yaml
# Time-bounded, single-use, device-verified
magic_link:
  ttl: 300  # 5 minutes
  single_use: true
  device_fingerprint: required

# Narrow-scoped, short-lived, audience-bound
jwt:
  audience: "specific-service"
  device_id: required
  expires: 3600  # 1 hour

# Least-privilege, revocable
bot_token:
  scope: "read:public"
  revocable: true
  audit_trail: required
```

### Chainwatch Detection

```python
# Authority boundary violation
if auth_artifact.has_no_context_boundaries():
    return Decision.DENY
    reason = "Unbounded authentication artifact (CW-01)"
```

### Real Incident Reference

Magic links valid for 30 days without re-verification, transferable to any device.

**Result:** Single link capture = 30 days of full system access.

---

## CW-02: Irreversible Trust Escalation

### Definition

Momentary event (click link, OAuth callback, bot interaction) grants **long-term or permanent trust** without re-verification.

### Why This Is Root-Level

Violates reversibility principle. One-time capture → persistent shadow.

The boundary crossing (initial auth) cannot be un-crossed. The trust cannot be revoked unless explicitly designed.

### Examples

**❌ Forbidden:**
```python
# One magic link click = 30 day session
@app.route("/magic-login")
def magic_login(token):
    user = verify_magic_token(token)
    session.set_duration(days=30)  # ❌ One event, long trust
    session.set_user(user)
    return redirect("/dashboard")

# Telegram auth = permanent access
@telegram_bot.command("/auth")
def telegram_auth(user_id):
    create_permanent_session(user_id)  # ❌ No re-verification
```

**✅ Acceptable:**
```python
# Short session + periodic re-verification
@app.route("/magic-login")
def magic_login(token):
    user = verify_magic_token(token)
    session.set_duration(hours=1)  # ✅ Short-lived
    session.require_reverification_at(days=1)  # ✅ Renewable trust
    return redirect("/dashboard")

# Telegram auth with step-up for sensitive ops
@app.route("/sensitive-operation")
def sensitive_op():
    if session.age > threshold:
        return require_reauth()  # ✅ Trust decay
```

### Chainwatch Detection

```python
# Trust escalation boundary
if trust_duration > acceptable_threshold:
    return Decision.REQUIRE_APPROVAL
    reason = "Trust escalation without reverification boundary (CW-02)"
```

---

## CW-03: Opaque Identity Provider

### Definition

Identity provider that **lacks enterprise control surfaces**:
- No session revocation
- No MFA policies
- No device management
- No audit trail
- No compliance controls

...but grants **corporate or privileged access**.

### Why This Is Root-Level

You don't control the subject. You trust, but cannot verify or revoke.

This is not "suboptimal IdP choice." This is **loss of authority control**.

### Examples

**❌ Forbidden:**
```yaml
# Telegram as corporate IdP
identity_provider: telegram
controls:
  session_revocation: false
  mfa_policy: false
  device_binding: false
  audit_trail: false
  compliance: false
access_granted: admin_panel  # ❌ No control over who

# Email-only magic links for privileged access
auth_method: email_magic_link
verification:
  email_ownership: true  # Only check
  device: false
  location: false
  mfa: false
access_granted: production_database  # ❌ Email compromise = DB access
```

**✅ Acceptable:**
```yaml
# Corporate IdP with control surfaces
identity_provider: okta  # or any enterprise IdP
controls:
  session_revocation: true
  mfa_policy: enforced
  device_binding: required
  audit_trail: full
  compliance: soc2
access_granted: admin_panel  # ✅ Controllable

# Step-up auth for privileged access
auth_method: sso
step_up_required:
  - hardware_key
  - device_verification
  - ip_allowlist
access_granted: production_database  # ✅ Layered control
```

### Chainwatch Detection

```python
# Opaque IdP boundary
if idp.lacks_enterprise_controls() and access.is_privileged():
    return Decision.DENY
    reason = "Opaque IdP for privileged access (CW-03)"
```

### Real Incident Reference

Telegram bot as sole authentication mechanism for corporate knowledge management system.

**Result:** SIM swap attack → telegram account takeover → full corporate access.

---

## CW-04: Credential Leakage Surfaces

### Definition

Secrets or credentials that **structurally pass through leakage surfaces**:
- URLs (logs, referrer, browser history)
- HTTP headers (logs, proxies)
- Client-side storage (XSS-readable)
- Screenshots / forwarding (social)

### Why This Is Root-Level

This is not "user error" or "XSS bug." The **design itself** places secrets where they leak.

### Examples

**❌ Forbidden:**
```python
# Secret in URL
magic_link = f"https://app.com/login?token={secret}"  # ❌ Logs, referrer, history

# Secret in localStorage
localStorage.setItem('auth_token', secret)  # ❌ XSS-readable

# Basic Auth (password in every request)
auth = f"Basic {base64(username:password)}"  # ❌ Logged everywhere
```

**✅ Acceptable:**
```python
# Secret in POST body (still logged, but better)
# Or better: exchange short-lived URL token for secure cookie
response.set_cookie('session', secret, httponly=True, secure=True, samesite='strict')

# Server-side session
session_store[session_id] = user_data  # ✅ Not client-accessible

# OAuth flow (token exchange, not URL persistence)
code = exchange_for_code()
token = exchange_code_for_token(code)  # ✅ Not in URL
```

### Chainwatch Detection

```python
# Leakage surface boundary
if credential.passes_through_leakage_surface():
    return Decision.DENY
    reason = "Credential on leakage surface (CW-04)"
```

### Common Leakage Surfaces

- **URL parameters** → nginx logs, referrer headers, browser history, screenshots
- **localStorage/sessionStorage** → XSS, browser extensions, disk forensics
- **HTTP headers (non-standard)** → proxy logs, debugging tools
- **Query strings** → CDN caching, link previews, social unfurling

---

## CW-05: Container Illusion of Safety

### Definition

Container treated as **security boundary**, but lacking actual isolation:
- Running as root
- No seccomp/AppArmor/SELinux
- Read-write filesystem
- Unrestricted capabilities
- Direct access to secrets

### Why This Is Root-Level

Container compromise = system compromise. The "boundary" is illusion.

### Examples

**❌ Forbidden:**
```dockerfile
# Running as root
USER root  # ❌ No privilege separation

# No capability restrictions
docker run --cap-add=ALL  # ❌ Full capabilities

# RW filesystem
docker run -v /data:/data:rw  # ❌ Can modify host

# Secrets in environment
ENV SECRET_KEY="abc123"  # ❌ Visible to all processes
```

**✅ Acceptable:**
```dockerfile
# Non-root user
USER appuser  # ✅ Least privilege

# Dropped capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE  # ✅ Minimal

# Read-only root FS
docker run --read-only --tmpfs /tmp  # ✅ Immutable

# Secrets from secure store
# Use Docker secrets, Vault, or k8s secrets with RBAC
```

### Chainwatch Detection

```python
# Container boundary check
if container.lacks_actual_isolation():
    return Decision.DENY
    reason = "Container illusion of safety (CW-05)"
```

---

## Integration with Authority Boundaries

These security classes are **authority boundary violations**:

```
Authority Boundary Framework:

1. Instruction Admission (from v0.2.0)
   - Proxied commands
   - Injected control flow

2. Trust Artifact Boundaries (NEW - these classes)
   - CW-01: Unbounded artifacts
   - CW-02: Irreversible escalation
   - CW-03: Opaque IdP
   - CW-04: Leakage surfaces
   - CW-05: Container illusion

Both ask: "Can this trust be captured irreversibly?"
```

---

## The Unifying Principle

All five classes share one property:

**They allow one-time capture to grant persistent, unrevocable access.**

This violates Chainwatch's core principle:

> If recovery is impossible, refuse the design.

These are not bugs to fix. These are **architectures to reject**.

---

## RootOps Verdict

**Antipattern Name:** "Convenient Trust Amplifier"

**Definition:**
System where convenience of access is prioritized over trust boundaries, resulting in:
- One artifact grants full access
- Trust never expires
- Context is never re-verified
- Control is replaced with hope

**Characteristic Phrases:**
- "It's just an internal tool"
- "We have Docker"
- "We use HTTPS"
- "We added Telegram login"
- "Nobody's hacked us yet"

**Root Cause:**
Absence of irreversibility awareness in authentication design.

**RootOps Response:**
If a system relies on "nobody has attacked it yet," it is **already compromised by design**.

---

## Implementation in v0.2.0

These classes will be checked in **Stage 1: Authority Boundary** (before instruction admission).

```python
def check_authentication_architecture(system_config):
    """
    Check for root architectural violations.

    This runs BEFORE any runtime checks.
    This evaluates design, not execution.
    """
    violations = []

    if has_unbounded_artifacts(system_config):
        violations.append("CW-01: Unbounded authentication artifacts")

    if has_irreversible_escalation(system_config):
        violations.append("CW-02: Irreversible trust escalation")

    if uses_opaque_idp(system_config):
        violations.append("CW-03: Opaque identity provider")

    if has_leakage_surfaces(system_config):
        violations.append("CW-04: Credential leakage surfaces")

    if has_container_illusion(system_config):
        violations.append("CW-05: Container illusion of safety")

    if violations:
        return ArchitectureViolation(violations)

    return ArchitectureValid()
```

---

## References

- `docs/irreversible-boundaries.md` - Authority boundaries (Clawbot incident)
- `docs/design/v0.2.0-specification.md` - Authority boundary detection
- `docs/DESIGN_BASELINE.md` - Principiis obsta

---

**Status:** Security classes defined for v0.2.0+
**Philosophy:** Reject dangerous architectures, not just exploits
**Principle:** If the design allows irreversible capture, refuse the design

---

*Last updated: 2026-02-03*
