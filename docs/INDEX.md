# Chainwatch Documentation Guide

**Navigation hub for all Chainwatch concepts and specifications.**

---

## Quick Navigation

**I want to...**

- **...understand what Chainwatch is** → Start with [README.md](../README.md)
- **...understand the core philosophy** → Read [irreversible-boundaries.md](#irreversible-boundaries)
- **...see the evolution roadmap** → Read [monotonic-irreversibility.md](#monotonic-irreversibility)
- **...implement v0.2.0** → Read [design/v0.2.0-specification.md](#v020-specification)
- **...configure boundaries** → Read [boundary-configuration.md](#boundary-configuration)
- **...use Chainwatch today** → Read [Quick Start](../README.md#quick-start) and [getting-started.md](#getting-started)
- **...understand RootOps** → Read [DESIGN_BASELINE.md](#design-baseline) and [rootops-antipatterns.md](#rootops-antipatterns)
- **...learn about forbidden architectures** → Read [security-classes.md](#security-classes)

---

## Start Here (Recommended Order)

For newcomers, read in this order:

1. [README.md](../README.md) - Project overview
2. [DESIGN_BASELINE.md](#design-baseline) - Principiis obsta
3. [irreversible-boundaries.md](#irreversible-boundaries) - Core concept (650+ lines)
4. [monotonic-irreversibility.md](#monotonic-irreversibility) - Evolution path (350+ lines)
5. [Quick Start](../README.md#quick-start) - Install and demo

**Then explore based on interest:**
- Implementation → [design/v0.2.0-specification.md](#v020-specification)
- Configuration → [boundary-configuration.md](#boundary-configuration)
- RootOps → [security-classes.md](#security-classes), [rootops-antipatterns.md](#rootops-antipatterns)

---

## Foundation Documents

### Design Baseline

**File:** `DESIGN_BASELINE.md`

**Principiis obsta** — resist the beginnings.

The shared design principle across chainwatch, kubenow, infranow:
- Intervene at the root of events, not aftermath
- Prevent irreversible outcomes at execution time
- Silence when systems are healthy

**Key principle:**
> If an outcome cannot be undone, the system should refuse to proceed.

**When to read:** First, to understand the invariant governing all decisions.

---

### Irreversible Boundaries

**File:** `irreversible-boundaries.md` (650+ lines)

**Core concept:** Some transitions cannot be undone.

**What it covers:**
- Two classes of boundaries: Execution AND Authority
- Execution: actions that cannot be undone (payment, credentials, destruction)
- Authority: instructions that cannot be un-accepted (proxied commands, injection)
- Real incident: Clawbot attack (2026) as authority boundary violation
- Critical warnings: how approval workflows can break philosophy
- Why "never ask the model if safe"

**Key quote:**
> "The system NEVER asks the model whether an irreversible action OR instruction is safe."

**When to read:** Second, to understand what Chainwatch actually does.

---

### Monotonic Irreversibility

**File:** `monotonic-irreversibility.md` (350+ lines)

**Core concept:** Chainwatch should never become smarter — only more conservative.

**What it covers:**
- Single axis of evolution: Local → Historical → Structural irreversibility awareness
- Correctness ladder: SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE (one-way only)
- v0.2.0 design: monotonic boundary accumulation (not graphs yet)
- Anti-patterns: what NOT to build (ML, prediction, negotiation)
- Why Chainwatch optimizes for "correct under uncertainty and hostile conditions"

**Key quote:**
> "Chainwatch should never become smarter — only more conservative as execution progresses."

**When to read:** Third, to understand the evolution path and anti-patterns.

---

### Boundary Configuration

**File:** `boundary-configuration.md`

**What it covers:**
- How to configure boundaries (edit YAML)
- Anti-pattern: "allowed boundaries" (philosophically wrong)
- Conservative defaults and iteration strategy
- When to use boundaries vs policy rules
- Future: purpose-specific boundaries (v0.2.0+)

**Key quote:**
> "Boundaries are not permissions. They are declarations of irreversibility."

**When to read:** When you need to customize boundaries for your use case.

---

## Implementation Guides

### Getting Started

**File:** `getting-started.md`

Quick onboarding for first-time users:
- Installation steps
- First integration example with FileGuard
- How policy works
- File classification logic
- Next steps

**When to read:** After understanding philosophy, before implementing.

---

### v0.2.0 Specification

**File:** `design/v0.2.0-specification.md` (1000+ lines)

**Status:** Design complete, ready to implement

**What it covers:**
- Two-stage boundary enforcement (authority BEFORE execution)
- Zone taxonomy (commercial, credential, egress, sensitive data)
- Authority boundary detection (proxy relay, context crossing, temporal violations)
- TraceState schema evolution
- Approval workflow design (out-of-band, single-use tokens, model-blind)
- Monotonicity guarantees and testing requirements
- Clawbot attack prevention proof

**Key principle:**
> "This is not v0.1.1 with approvals. This is a fundamental architectural shift."

**When to read:** Before implementing v0.2.0.

**See also:** `design/README.md` for design specification guidelines.

---

### Testing Guide

**File:** `testing-guide.md`

Instructions for testing with external agents:
- Testing with Aider, OpenHands, or other Python-based agents
- Creating custom test scenarios
- What works now vs what needs HTTP proxy mode (v0.2.0)

---

## RootOps and Security

### Security Classes

**File:** `security-classes.md`

**Five forbidden architectures (CW-01 through CW-05):**

- **CW-01: Unbounded Authentication Artifacts** - tokens without context
- **CW-02: Irreversible Trust Escalation** - one capture → long access
- **CW-03: Opaque Identity Provider** - no enterprise controls
- **CW-04: Credential Leakage Surfaces** - secrets in URLs/logs
- **CW-05: Container Illusion of Safety** - Docker as false boundary

**What it covers:**
- Root architectural violations, not exploitable bugs
- Why each is unfixable by patches
- Examples (forbidden vs acceptable)
- Chainwatch detection logic
- Real incident references

**Key insight:**
> "These are not vulnerability classes. These are forbidden architectures."

**When to read:** When designing authentication systems or evaluating agent security.

---

### RootOps Antipatterns

**File:** `rootops-antipatterns.md`

**The "Convenient Trust Amplifier" antipattern:**

System where convenience > boundaries, resulting in:
- One artifact grants full access
- Trust never expires
- Context never re-verified
- Control replaced with hope

**What it covers:**
- Definition of RootOps (operate on root causes, not symptoms)
- The antipattern definition
- Real incident analysis: AI agent knowledge base
- 5 attack scenarios (all inevitable by design)
- Detection checklist
- Related principles: zero-knowledge, Principiis obsta

**Key quote:**
> "If a system relies on 'nobody has attacked it yet,' it is already compromised by design."

**When to read:** Before building any authentication or access control system.

---

## Background and Context

### Core Idea

**File:** `core-idea.md`

Original concept: execution chains as first-class entities for security enforcement.

---

### FAQ

**File:** `FAQ.md`

Common questions:
- Why no ML for enforcement?
- Why Chainwatch exists
- How it differs from existing tools

---

### Threat Model

**File:** `threat-model.md`

What Chainwatch protects against and what it doesn't.

---

### Roadmap (Clawbot)

**File:** `roadmap-clawbot.md`

Integration strategy with Clawbot and autonomous agents.

---

## Integration Guides

**Directory:** `integrations/`

- `file-ops-wrapper.md` - FileGuard capabilities and limitations
- `clawbot-denylist.md` - Clawbot integration today
- `browser-checkout-gate.md` - v0.2.0 browser wrapper spec

---

## Decision Records

**Directory:** `decisions/`

- `001-first-integration.md` - Why file wrapper first
- `002-file-classification.md` - Path-based classification rationale

---

## Document Hierarchy

```
Foundation (Philosophy - WHY)
├── DESIGN_BASELINE.md          [Principiis obsta]
├── irreversible-boundaries.md  [Core concept]
└── monotonic-irreversibility.md [Evolution path]
       ↓
Design (What & How)
├── design/v0.2.0-specification.md [Implementation blueprint]
└── boundary-configuration.md      [Configuration guide]
       ↓
Security (Forbidden Architectures)
├── security-classes.md         [CW-01 through CW-05]
└── rootops-antipatterns.md     [Convenient Trust Amplifier]
       ↓
Implementation (Usage)
├── getting-started.md          [Onboarding]
├── testing-guide.md            [Testing]
└── integrations/               [Integration guides]
```

**Rule:** Read philosophy before implementing. Always.

---

## Key Principles (Summary)

From all philosophical documents:

1. **Two classes of boundaries:**
   - Execution: actions that cannot be undone
   - Authority: instructions that cannot be un-accepted

2. **Monotonicity:**
   - Boundaries accumulate, never disappear
   - Irreversibility only increases, never decreases
   - One-way: SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE

3. **Control, not observability:**
   - Refuse execution when boundaries crossed
   - Not detection, not logging — enforcement

4. **No model negotiation:**
   - System never asks model if action/instruction is safe
   - Boundaries are absolute, not negotiable
   - Approval is human override, not model bypass

5. **Evolution axis:**
   - Single axis: Local → Historical → Structural irreversibility
   - Never smarter — only more conservative

6. **Structural, not statistical:**
   - Deterministic rules, not ML
   - Pattern matching, not prediction
   - Boolean logic, not confidence scores

---

## For Contributors

**Before adding features:**
1. Does it align with philosophy? (read irreversible-boundaries.md)
2. Does it fit evolution path? (read monotonic-irreversibility.md)
3. Is it explicitly deferred? (read design/v0.2.0-specification.md non-goals)

**Red flags (stop immediately):**
- Adding ML or heuristics
- Letting model influence boundary decisions
- Softening boundaries based on context
- Making boundaries negotiable
- Reducing friction for user convenience

**Green lights:**
- Deterministic state transitions
- Pattern-based detection
- Hard refusals at boundaries
- Out-of-band human approval
- Conservative defaults

---

## Version Status

- **v0.1.2 (current):** Conceptual foundation complete
- **v0.2.0 (designed):** Specification complete, ready to implement
- **v0.3.0+ (planned):** See monotonic-irreversibility.md evolution path

---

**Last updated:** 2026-02-03

**Maintained by:** Philosophy-first development process

**Questions?** See `FAQ.md` or open an issue on GitHub.
