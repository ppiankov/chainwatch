# Chainwatch × Clawbot: Consent-First Control Roadmap

**Goal:** Give users a clear, enforceable list of things an agent cannot do without their consent.

**Principle:** Consent is expressed as a denylist, not an allowlist. Users are bad at predicting everything they want an agent to do. They are very good at stating what it must not do without asking.

## Core Philosophy

```
Clawbot thinks freely.
Chainwatch controls what reality it's allowed to touch.
```

Users do not configure policies while the agent runs. They do it once, before anything dangerous can happen.

---

## Phase 0 — Define "No Without Consent" Categories

**Status:** v0.1.0 ✅ (conceptual), v0.2.0 (enforcement)

### Canonical Consent Categories

These are universal action classes that always require explicit user consent:

1. **SPEND**
   - Purchases, subscriptions, upgrades
   - Paid trials, donations
   - Any transaction involving money

2. **IDENTITY**
   - Login/logout, password changes
   - Account recovery, MFA/OTP handling
   - Session management

3. **EXTERNAL_COMMUNICATION**
   - Sending email, messages (Slack, Discord, SMS)
   - Posting publicly
   - Contacting third parties

4. **DATA_EGRESS**
   - Uploading files
   - Sending data to external domains
   - Copy/paste out of environment

5. **SYSTEM_MUTATION**
   - Shell command execution
   - Software installation
   - Config modifications
   - git push / deploy / terraform apply

6. **PERSISTENCE**
   - Creating long-lived accounts
   - Storing credentials
   - Enabling background services

**Rule:** All of the above default to `REQUIRE_APPROVAL`.

This list alone prevents the "$3000 course" incident.

---

## Phase 1 — Browser Checkout Gate (v0.2.0)

**Target:** Prevent unauthorized spending via browser automation.

**Priority:** HIGHEST (prevents real money loss)

**Scope:** Intercept browser actions that indicate purchase intent.

### Detection Strategy

Identify checkout/payment through multiple signals:

**URL Patterns:**
- `/checkout`, `/payment`, `/billing`, `/subscribe`, `/cart/confirm`
- `/order`, `/upgrade`, `/trial-to-paid`
- Third-party payment: `stripe.com/checkout`, `paddle.com`, `shopify` checkout

**DOM/Button Text:**
- "Buy", "Pay Now", "Confirm Purchase", "Place Order"
- "Subscribe", "Upgrade", "Complete Payment"
- "Add to Cart" + amount visible

**Page Context:**
- Price visible + payment form + submit button
- Credit card input fields present
- Order summary with total

### Enforcement Actions

On detection:
1. Block navigation/click
2. Generate approval request with:
   - Detected amount (if visible)
   - Merchant/domain
   - Page title/URL
3. Require out-of-band approval: `chainwatch approve <id>`

### Deliverable

- `src/chainwatch/wrappers/browser_ops.py` - Browser action interceptor
- Detection rules for checkout patterns
- Integration test with mock purchase flow
- Demo: "Agent tries to buy course, Chainwatch blocks it"

**Success Metric:** Blocks 95%+ of e-commerce checkout attempts.

---

## Phase 2 — Machine-Readable Consent Profiles (v0.2.0)

**Target:** User-defined consent boundaries stored as configuration.

### ConsentProfile Schema

```yaml
# ~/.chainwatch/consent.yaml

consent:
  spend:
    default: require_approval
    max_unattended: 0  # No spending without approval

  identity:
    default: require_approval
    allow_readonly: true  # Can read auth status, but not modify

  external_communication:
    default: require_approval
    allowlist_domains: []  # No domains trusted by default

  data_egress:
    default: require_approval
    allow_internal: true  # Internal network OK
    allowlist_domains: []

  system_mutation:
    exec: require_approval
    install: block  # Never allow software installation
    git_push: require_approval

  persistence:
    default: block  # Never create long-lived state without approval
```

### User-Facing Setup

```bash
chainwatch init
```

Interactive questionnaire (plain English):
```
Can the agent spend money without asking you?
  [ ] Yes
  [x] No (default)

Can the agent send messages/emails on your behalf?
  [ ] Yes
  [x] No (default)

Can the agent run shell commands?
  [x] Yes
  [ ] No

...
```

Generates `~/.chainwatch/consent.yaml` automatically.

Advanced users can edit directly, but most never will.

### Pre-Built Profiles

Ship with opinionated defaults:

- `research_only` - Read-only, no writes, no external comms
- `dev_assistant` - File ops + git, but no push/deploy
- `ops_readonly` - Query prod, but no mutations
- `safe_autonomy` - Balanced autonomy with spend/identity gates
- `danger_zone` - Explicitly scary, requires manual opt-in

Users pick one on `chainwatch init`.

---

## Phase 3 — MCP Tool Gateway (v0.3.0)

**Target:** Intercept Clawbot's MCP tool calls at the protocol layer.

**Why:** MCP (Model Context Protocol) is Clawbot's tool invocation standard. Intercepting at this layer gives universal coverage.

### Architecture

```
Agent → Chainwatch MCP Gateway → Real MCP Servers/Tools
```

The gateway:
1. Receives tool call request (JSON-RPC)
2. Classifies into consent category (SPEND, DATA_EGRESS, etc.)
3. Evaluates against ConsentProfile
4. Allows / blocks / requires approval
5. Returns response or error to agent

### Tool Classification Examples

**SPEND Detection:**
- Tool: `browser.navigate` + URL contains `/checkout`
- Tool: `stripe.create_payment_intent`
- Tool: `paypal.authorize`

**DATA_EGRESS Detection:**
- Tool: `filesystem.upload` + destination external
- Tool: `http.post` + domain not in allowlist

**SYSTEM_MUTATION Detection:**
- Tool: `shell.exec`
- Tool: `package.install`
- Tool: `git.push`

### Deliverable

- `src/chainwatch/wrappers/mcp_gateway.py` - MCP protocol interceptor
- Tool-to-category mapping rules
- Approval workflow integration
- Trace event logging for all tool calls

**Success Metric:** Cover 90%+ of dangerous tool operations.

---

## Phase 4 — Chain-Aware Rules (v0.3.0)

**Target:** Enforce consent based on execution trajectory, not just isolated actions.

### The Problem

Single actions look innocent. Chains reveal intent:
- `browse` → `pricing` → `checkout` = SPEND attempt
- `research` → `aggregate` → `upload` = DATA_EGRESS
- `query` → `query` → `query` (100x) = VOLUME abuse

### Chain-Aware Rules

**Pattern: Trajectory-Based Escalation**

```python
# Example rule (conceptual)
if trace.has_visited("/pricing") and action.url_contains("/checkout"):
    return PolicyResult(
        decision=Decision.REQUIRE_APPROVAL,
        reason="Purchase trajectory detected (browse → checkout)"
    )
```

**Pattern: Volume-Based Gating**

```python
if trace.volume_external_posts > 10:
    return PolicyResult(
        decision=Decision.BLOCK,
        reason="Excessive external communication (>10 POSTs)"
    )
```

**Pattern: Sensitivity Escalation**

```python
if trace.max_sensitivity == "high" and action.egress == "external":
    return PolicyResult(
        decision=Decision.REQUIRE_APPROVAL,
        reason="High-sensitivity data + external egress"
    )
```

### Deliverable

- Extend `policy.py` with trajectory-aware rules
- Add chain pattern detection (browse → purchase)
- Integration tests with multi-step attack scenarios

**Success Metric:** Catch trajectory-based attacks that single-action policies miss.

---

## Phase 5 — Real Approval System (v0.2.0)

**Target:** Out-of-band approval that cannot be socially engineered.

### Requirements

Approval must be:
1. **Out-of-band** - Not in agent chat (agent can't see it)
2. **Action-bound** - Tied to specific operation via hash
3. **Time-limited** - Expires after 60 seconds
4. **Single-use** - Cannot be reused

### User Flow

**Agent attempts sensitive action:**

```
⚠️  Approval required

Action: SPEND
Amount: $3000 USD
Merchant: coursera.org
URL: https://coursera.org/checkout/confirm

Approve with:
  chainwatch approve cw-9f2c1a

Or deny with:
  chainwatch deny cw-9f2c1a

Expires in: 60 seconds
```

**User approves:**

```bash
$ chainwatch approve cw-9f2c1a
✓ Action approved: SPEND $3000 (coursera.org)
```

Action proceeds exactly once. Token is consumed.

**User denies or ignores:**

Action is blocked. Agent receives error:
```
EnforcementError: Purchase requires approval (denied or expired)
```

### Deliverable

- `src/chainwatch/approval.py` - Approval token management
- CLI commands: `chainwatch approve <id>`, `chainwatch deny <id>`
- Token expiry and single-use enforcement
- Approval audit log

**Success Metric:** Zero false approvals via social engineering or token reuse.

---

## Phase 6 — Chainwatch Wrapper CLI (v0.2.0)

**Target:** Users run Clawbot through Chainwatch, not directly.

### User Command

```bash
chainwatch run clawbot
```

or

```bash
chainwatch wrap clawbot --profile safe_autonomy
```

### What It Does

1. Validates `~/.chainwatch/consent.yaml` exists (if not, runs `chainwatch init`)
2. Starts Clawbot with Chainwatch intercepts enabled:
   - Browser wrapper active
   - MCP gateway active (if applicable)
   - Tool monitoring enabled
3. Begins trace for this session
4. Displays status: "Chainwatch active. Monitoring 4 boundaries."

### Session Management

```bash
# View active sessions
chainwatch sessions

# View trace for last session
chainwatch trace last

# View trace for specific session
chainwatch trace <session-id>
```

### Deliverable

- `src/chainwatch/cli.py` - Enhanced CLI with `run`, `wrap`, `sessions`, `trace` commands
- Session management and trace persistence
- Wrapper script generation for Clawbot

**Success Metric:** Users can run `chainwatch wrap clawbot` and get immediate protection.

---

## Phase 7 — Documentation That Protects Users (v0.2.0)

**Target:** Blunt, honest docs that prevent disasters.

### Required Documents

1. **`docs/incidents.md`** - Real stories of agent autonomy failures
   - $3000 course purchase
   - Unauthorized emails sent
   - Prod deployments gone wrong

2. **`docs/threat-model-clawbot.md`** - Specific risks with Clawbot
   - Separate device ≠ separate permissions
   - Default recommendations for identity isolation

3. **`README.md` update** - Add "Using with Clawbot" section
   - Installation
   - First run with `chainwatch wrap clawbot`
   - What gets blocked by default

4. **Quick Start Checklist** - One-page safety guide
   ```
   □ Run agent in separate OS user
   □ No saved payment methods in agent browser
   □ Run via `chainwatch wrap`
   □ Set consent profile (or use safe_autonomy default)
   □ Test with harmless tasks first
   ```

### Deliverable

- Clear incident documentation (not FUD, not hype)
- Integration guide for Clawbot specifically
- Threat model covering identity vs device separation
- One-page safety checklist

**Success Metric:** Users read it and change behavior (reduce "surprise" incidents).

---

## Implementation Priority

### v0.2.0 MVP (Ship First)

**Goal:** Prevent unauthorized spending.

1. ✅ Browser checkout detector (`browser_ops.py`)
2. ✅ Consent profile schema + `chainwatch init`
3. ✅ Approval system (out-of-band tokens)
4. ✅ `chainwatch wrap clawbot` CLI
5. ✅ Demo: Agent tries to purchase, blocked

**Timeline:** 2-3 weeks
**Success:** Blocks real checkout attempts in Clawbot.

### v0.3.0 (Next)

**Goal:** Expand coverage beyond browser.

1. MCP tool gateway
2. Chain-aware rules (trajectory detection)
3. Pre-built consent profiles
4. Session management and trace inspection

**Timeline:** 4-6 weeks

### v1.0.0 (Future)

**Goal:** Production-grade enforcement for teams.

1. Multi-user approval workflows
2. Policy-as-code with version control
3. Audit export (compliance logs)
4. Integration with identity providers (SSO, RBAC)

---

## What This Roadmap Explicitly Avoids

- ❌ ML-based intent inference
- ❌ Behavioral prediction or anomaly detection
- ❌ "Trust the agent" or "mostly safe" modes
- ❌ Silent auto-approval
- ❌ Vague safety language

Everything is explicit, inspectable, and deterministic.

---

## Success Criteria

**v0.2.0 ships when:**
- User can run `chainwatch wrap clawbot`
- Clawbot attempts to purchase something
- Chainwatch blocks it and requires approval
- User approves or denies out-of-band
- Trace shows the decision

**v0.3.0 ships when:**
- MCP tool calls are intercepted
- Chain-aware rules catch multi-step attacks
- Users can inspect traces and see blocked trajectories

**v1.0.0 ships when:**
- Teams deploy Chainwatch in prod
- Compliance requirements met (audit logs)
- No incidents of unauthorized actions bypassing controls

---

## Open Questions

1. **How do we handle approval for batch operations?**
   - e.g., Agent wants to process 100 files, 10 require approval
   - Answer: Batch approval tokens? Or fail-fast on first denial?

2. **What happens when approval expires mid-action?**
   - e.g., Long-running operation, approval window closes
   - Answer: Operation fails, requires re-approval

3. **How do we handle "soft" vs "hard" blocks?**
   - Some actions should be impossible (spend)
   - Others should be logged but allowed (research browsing)
   - Answer: Consent categories map to enforcement levels

---

## Next Steps

1. ✅ Create this roadmap
2. ⏭️ Implement browser checkout detector (v0.2.0 MVP)
3. ⏭️ Add consent profile schema and `chainwatch init`
4. ⏭️ Build approval system with CLI
5. ⏭️ Write Clawbot integration guide
6. ⏭️ Ship v0.2.0: "Chainwatch prevents $3000 purchase"

---

## Related Documents

- `docs/integrations/browser-checkout-gate.md` - Technical spec for checkout detection
- `docs/threat-model-clawbot.md` - Security assumptions and boundaries
- `docs/consent-profile-schema.md` - ConsentProfile YAML specification
- `docs/incidents.md` - Real-world agent autonomy failures

---

**Last Updated:** 2026-01-29
**Status:** v0.1.0 ✅ (file wrapper MVP), v0.2.0 (in progress)
