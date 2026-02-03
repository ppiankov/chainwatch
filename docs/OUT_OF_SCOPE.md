# Out of Scope

**This document defines where Chainwatch stops.**

---

## What Chainwatch Is Not

Chainwatch is **not**:

### Detection or Scanning
- Not a vulnerability scanner
- Not a codebase analyzer
- Not a static analysis tool
- Not a security audit framework
- Not a compliance checker

**Why:** These operate after code exists. Chainwatch operates before execution commits.

---

### Observability or Monitoring
- Not a monitoring system
- Not an alerting framework
- Not a dashboard builder
- Not a log aggregator
- Not a SIEM replacement
- Not an incident response tool

**Why:** These explain what happened. Chainwatch prevents what cannot be undone.

---

### Identity or Access Management
- Not an IAM system
- Not an RBAC framework
- Not a permission manager
- Not a credential vault
- Not a Zero Trust architecture

**Why:** These validate who can access what. Chainwatch prevents irreversible transitions regardless of who initiated them.

---

### Risk Scoring or Prediction
- Not a risk assessment tool
- Not a threat intelligence platform
- Not an ML-based classifier
- Not a confidence scorer
- Not a predictive security system

**Why:** These assign probabilities. Chainwatch enforces structural boundaries.

---

### Post-Execution Security
- Not a DLP system (data already leaked)
- Not a WAF (request already processed)
- Not an EDR (code already executed)
- Not a backup system (data already destroyed)
- Not forensics (damage already done)

**Why:** These operate after the irreversible transition. Chainwatch refuses before crossing.

---

## What Chainwatch Only Does

Chainwatch **only**:

1. **Reasons about execution chains before commitment**
   - Not individual actions in isolation
   - Not retrospective analysis
   - Not probabilistic prediction

2. **Enforces irreversible boundaries**
   - Execution boundaries (actions that cannot be undone)
   - Authority boundaries (instructions that cannot be un-accepted)

3. **Rejects forbidden architectures**
   - At design time, not runtime
   - Before code is written, not after deployment
   - Structurally, not statistically

4. **Refuses continuation**
   - Hard stop (DENY)
   - Human override (REQUIRE_APPROVAL)
   - Never negotiates with models
   - Never "warns and allows"

---

## Explicit Non-Goals

### Chainwatch will never:

- ❌ Add machine learning or heuristics
- ❌ Score "risk levels" probabilistically
- ❌ Optimize for user convenience
- ❌ Reduce friction at boundaries
- ❌ Ask models if actions are safe
- ❌ Build dashboards for visualization
- ❌ Generate alerts for monitoring
- ❌ Perform root cause analysis
- ❌ Recommend remediation actions
- ❌ Replace existing security tools
- ❌ Become "AI-powered security"

### Chainwatch will always:

- ✅ Remain deterministic
- ✅ Enforce structural boundaries
- ✅ Refuse before damage
- ✅ Operate upstream of execution
- ✅ Preserve silence as success
- ✅ Stay boring and correct

---

## If You Need...

**If you need vulnerability detection** → Use a scanner (Semgrep, Snyk, etc.)

**If you need monitoring** → Use observability tools (Prometheus, Datadog, etc.)

**If you need IAM** → Use identity platforms (Okta, Auth0, etc.)

**If you need DLP** → Use data loss prevention (network DLP, endpoint DLP)

**If you need compliance** → Use compliance frameworks (SOC2, ISO 27001 tooling)

**If you need incident response** → Use SIEM/SOAR platforms

**If you need all of the above** → Use a security stack

**If you need to prevent irreversible actions in execution chains** → Use Chainwatch

---

## Scope Boundary

```
┌─────────────────────────────────────────┐
│  Traditional Security (Post-Hoc)        │
│  - Detection after execution            │
│  - Alerts after damage                  │
│  - Analysis after compromise            │
│                                         │
│  Tools: SIEM, DLP, EDR, etc.           │
└─────────────────────────────────────────┘

         ↑ Chainwatch does NOT operate here


┌─────────────────────────────────────────┐
│  Chainwatch (Pre-Commitment)            │
│  - Refusal before execution             │
│  - Boundary before damage               │
│  - Architecture before implementation   │
│                                         │
│  Invariant: If irreversible, refuse    │
└─────────────────────────────────────────┘

         ↑ Chainwatch ONLY operates here
```

---

## The Litmus Test

**Question:** "Can Chainwatch help with...?"

**Answer:** Ask yourself:

1. Does it involve **preventing** an irreversible transition?
   - If yes → possibly in scope
   - If no → out of scope

2. Does it require analysis **after** the action occurred?
   - If yes → out of scope
   - If no → possibly in scope

3. Does it require probabilistic/ML-based reasoning?
   - If yes → out of scope
   - If no → possibly in scope

4. Does it involve **observing** rather than **refusing**?
   - If yes → out of scope
   - If no → possibly in scope

**If unsure:** Out of scope.

---

## Why This Boundary Exists

Chainwatch is about **restraint**, not **expansion**.

Adding features outside this scope would:
- Dilute the core principle
- Introduce non-determinism
- Create "observability theater"
- Weaken enforcement semantics
- Make Chainwatch "yet another security tool"

**The boundary is the feature.**

---

## Evolution Within Scope

Chainwatch **will** evolve:

- ✅ More boundary types (v0.2.0: authority boundaries)
- ✅ More enforcement mechanisms (approval workflows)
- ✅ More architectural violations (security classes)
- ✅ Better integration points (HTTP proxy, agent runtimes)
- ✅ Formal verification (monotonicity proofs)

Chainwatch **will not** evolve into:
- ❌ A platform
- ❌ An ecosystem
- ❌ A marketplace
- ❌ A vendor
- ❌ "Chainwatch Cloud"

---

## Final Statement

**Chainwatch does one thing:**

> Refuses irreversible transitions before they occur.

**Everything else is out of scope.**

---

**If a feature cannot be explained as "refusing irreversible X before Y," it does not belong in Chainwatch.**

This is not rigidity. This is integrity.

---

*Last updated: 2026-02-03*
