# Boundary Configuration

**Status:** v0.1.2 (basic), evolving in v0.2.0+

---

## Core Philosophy

**Boundaries are conservative by default.**

If you're unsure whether something should be a boundary, make it one.

False positive: Agent asks for approval, human proceeds.
False negative: Money gone, credentials leaked, data destroyed.

Bias toward safety.

---

## Current Model (v0.1.2)

### Configuring Boundaries

Edit `~/.chainwatch/denylist.yaml`:

```yaml
# Boundaries (hard refusal)
urls:
  - /checkout
  - /payment
  - stripe.com/checkout

files:
  - ~/.ssh/id_rsa
  - ~/.aws/credentials

commands:
  - rm -rf
  - sudo su
```

### Removing Boundaries

Comment out or delete patterns:

```yaml
urls:
  - /checkout
  # - /payment  # Commented out = not a boundary anymore
```

### Adding Boundaries

Add new patterns:

```yaml
urls:
  - /checkout
  - /my-company/internal-billing  # Your specific boundary

files:
  - ~/.ssh/id_rsa
  - /opt/company/production.key  # Your specific credential
```

### What Happens to Non-Boundaries

Resources NOT in the denylist go through normal policy evaluation:
- Risk scoring (sensitivity + volume + egress)
- Purpose-bound rules (e.g., SOC_efficiency blocks salary)
- May return ALLOW, DENY, or REQUIRE_APPROVAL based on context

**Non-boundaries are evaluated, not automatically allowed.**

---

## The "Allowed Boundary" Antipattern

**Problem:**

"I want checkout URLs to be a boundary for most agents, but allowed for my procurement agent."

**Why "allowed boundary" is wrong:**

If it's allowed, it's not a boundary. That's a contradiction.

What you actually want is **purpose-specific boundary rules**.

### Solution 1: Remove the Boundary (Not Recommended)

```yaml
urls:
  # - /checkout  # Removed completely
```

**Problem:** Now NO agent is protected. You weakened security globally to enable one agent.

### Solution 2: Purpose-Specific Configuration (v0.2.0+)

```yaml
boundaries:
  payment:
    default: deny
    exceptions:
      procurement_agent: require_approval  # This purpose can cross with approval
```

**Philosophy:**
- Boundary still exists
- Default enforcement is deny
- Specific purposes have different enforcement

This is **not implemented in v0.1.2** (coming in v0.2.0).

**⚠️ CRITICAL:** When implementing approval workflows in v0.2.0, see the warning in `docs/irreversible-boundaries.md` under "Critical Warning: Approval Boundaries". Incorrectly designed approval workflows can break Chainwatch's core philosophy by turning boundaries into model negotiation points instead of control interrupts.

### Solution 3: Just Remove and Document (v0.1.2 Workaround)

For now in v0.1.2, if you MUST allow a boundary for one purpose:

```yaml
# WORKAROUND: Boundary removed, rely on policy.py purpose rules instead
urls:
  # - /checkout  # Removed because procurement_agent needs it
  - /payment    # Keep this boundary (more critical)
```

Then add a purpose rule in your code:

```python
# In your policy wrapper or agent code
if purpose != "procurement_agent" and "/checkout" in action.resource:
    return PolicyResult(decision=Decision.DENY, reason="Checkout blocked for this purpose")
```

**This is ugly but works for v0.1.2.**

---

## Better Model: Boundary Enforcement Levels (v0.2.0+)

Instead of binary "boundary or not," support enforcement levels:

```yaml
boundaries:
  critical:  # Never cross without explicit approval
    - policy: deny
      patterns:
        - /payment/confirm
        - ~/.ssh/id_rsa

  elevated:  # Require approval
    - policy: require_approval
      patterns:
        - /checkout
        - ~/.aws/credentials

  monitored:  # Log but allow
    - policy: allow_with_logging
      patterns:
        - /cart
        - /pricing
```

**Philosophy:**
- All are boundaries (irreversibility points)
- Enforcement varies by severity
- Purpose-specific overrides possible

---

## Boundary Exceptions (v0.2.0+ Design)

When you need purpose-specific rules:

```yaml
boundaries:
  payment:
    patterns:
      - /checkout
      - /payment
    default_enforcement: deny
    exceptions:
      - purpose: procurement_agent
        enforcement: require_approval
        conditions:
          max_amount: 1000  # Approval required if >$1000
      - purpose: expense_bot
        enforcement: require_approval
        conditions:
          max_amount: 500
```

**Philosophy:**
- Boundary exists for everyone
- Some purposes have different enforcement
- Conditions can further refine (amount limits, time windows, etc.)

---

## Why Not Just "Allowlist"?

**Allowlist model:**
```yaml
allowed:
  - /products
  - /search

denied:
  - /checkout
```

**Problem:**
- Allowlist breaks on unknown resources
- Agent visits `/new-checkout-flow` → not on allowlist, but also not on denylist
- Result: undefined behavior

**Chainwatch model:**
```yaml
boundaries:  # Hard refusal points
  - /checkout

# Everything else goes through policy evaluation
```

**Philosophy:**
- Boundaries are explicit
- Non-boundaries are evaluated (not blindly allowed)
- Unknown resources get risk-scored

---

## Conservative Boundary Declaration (Best Practice)

### Start Broad

```yaml
# Initial denylist - very conservative
urls:
  - /checkout
  - /payment
  - /billing
  - /subscribe
  - /cart/confirm  # Maybe too broad?
```

### Iterate Based on Real Use

After running your agent:

```yaml
# Refined denylist - based on actual false positives
urls:
  - /checkout
  - /payment
  # /cart removed - was blocking legitimate cart viewing
```

### Document Exceptions

```yaml
# Boundaries with context
urls:
  - /checkout  # Always block - irreversible payment
  - /payment   # Always block - credential exposure risk
  # /cart NOT here - just viewing cart is reversible
  # /pricing NOT here - public information, no commitment
```

---

## Anti-Patterns to Avoid

### ❌ Allowlist Thinking

```yaml
# DON'T DO THIS
allowed_for_procurement:
  - /checkout

denied_for_everyone_else:
  - /checkout
```

**Problem:** Contradictory. Either it's a boundary or it's not.

### ❌ Empty Boundaries

```yaml
# DON'T DO THIS
urls: []
files: []
commands: []
```

**Problem:** No protection. If you don't need boundaries, don't use Chainwatch.

### ❌ Over-Specific Boundaries

```yaml
# DON'T DO THIS
urls:
  - https://example.com/checkout/step3/confirm?session=abc123
```

**Problem:** Too specific. Agent bypasses by changing session ID.

**Do this instead:**
```yaml
urls:
  - /checkout  # Catches all checkout flows
```

---

## Migration Path

### v0.1.2 (Current)
- Binary: boundary or not
- Edit YAML to add/remove
- No purpose-specific rules

### v0.2.0 (Planned)
- Enforcement levels: deny / require_approval / warn
- Purpose-specific exceptions
- Conditional boundaries (amount limits, time windows)

### v0.3.0 (Future)
- Boundary graphs
- Chain-aware boundary activation
- Composable boundary rules

---

## Example: Real-World Configuration

### Startup (Aggressive Protection)

```yaml
# Very conservative - block everything risky
urls:
  - /checkout
  - /payment
  - /billing
  - /subscribe
  - /upgrade
  - /downgrade
  - /cancel

files:
  - ~/.ssh/*
  - ~/.aws/*
  - ~/.config/gcloud/*
  - **/.env
  - **/secrets.*
  - **/credentials.*

commands:
  - rm -rf
  - sudo
  - curl.*|.*sh
  - wget.*|.*sh
```

### After 1 Month (Refined)

```yaml
# Refined based on real usage
urls:
  - /checkout
  - /payment
  # /billing removed - just viewing bills is OK
  # /subscribe removed - viewing subscription page is OK
  - stripe.com/checkout  # Added - caught a bypass attempt

files:
  - ~/.ssh/id_rsa
  - ~/.ssh/id_ed25519
  # ~/.ssh/* too broad - was blocking known_hosts
  - ~/.aws/credentials
  # **/.env too broad - was blocking .env.example files

commands:
  - rm -rf /
  - sudo su
  - sudo -i
  # 'sudo' alone too broad - was blocking sudo apt install
```

### Production (Balanced)

```yaml
# Balanced - real boundaries only
urls:
  - /checkout/confirm
  - /payment/submit
  - stripe.com/checkout

files:
  - ~/.ssh/id_rsa
  - ~/.ssh/id_ed25519
  - ~/.aws/credentials
  - ~/.config/gcloud/application_default_credentials.json

commands:
  - rm -rf /
  - dd if=/dev/zero
  - mkfs
  - sudo su
```

---

## When to Use Boundaries vs Policy Rules

### Use Boundaries For:
- Structurally irreversible actions
- Universal prohibitions (regardless of purpose)
- Things you NEVER want automated

### Use Policy Rules For:
- Context-dependent decisions
- Risk-based gating
- Purpose-specific logic

### Example

**Boundary (universal):**
```yaml
urls:
  - /payment/submit  # NEVER allow without approval
```

**Policy Rule (context-dependent):**
```python
# In policy.py
if purpose == "expense_bot" and action.resource.contains("/receipt"):
    if state.volume_bytes > 10_000_000:
        return REQUIRE_APPROVAL  # Large expense, need approval
    else:
        return ALLOW  # Small expense, auto-approve
```

---

## Summary

**v0.1.2 boundaries are configurable:**
- Edit ~/.chainwatch/denylist.yaml
- Add/remove patterns
- Comment out to disable

**"Allowed boundaries" is the wrong model:**
- Boundaries = hard refusal
- Non-boundaries = evaluated by policy
- If you need purpose-specific rules, wait for v0.2.0

**Best practice:**
- Start conservative (many boundaries)
- Iterate based on real use (remove false positives)
- Document why each boundary exists

**Boundaries are not permissions.**
They are declarations of irreversibility.

---

*Last updated: 2026-02-01*
