# Chainwatch Documentation Index

**Complete guide to Chainwatch's conceptual foundation and design.**

---

## Start Here

**New to Chainwatch?** Read in this order:

1. **README.md** (project root) - Quick overview and installation
2. **DESIGN_BASELINE.md** (below) - Shared principle: Principiis obsta
3. **Core Philosophy** (below) - Understand the foundational ideas
4. **Evolution Path** (below) - See where we're going and why
5. **Design Specifications** (when ready to implement) - Implementation blueprints

---

## Design Baseline (The Foundation)

### Principiis obsta
**File:** `DESIGN_BASELINE.md`

**Principiis obsta** — resist the beginnings.

Chainwatch intervenes early, at the point where small, acceptable actions begin to form irreversible outcomes. It operates at the root of events, not their aftermath.

**Key principle:**
> If an outcome cannot be undone, the system should refuse to proceed.

**Shared across projects:**
- Chainwatch - Execution chain control for AI agents
- kubenow - Cluster health intervention (not exploration)
- infranow - Metric-driven triage (silence as success)

**When to read:** First, to understand the invariant that governs all design decisions.

**See also:** `SHARED_PRINCIPLE.md` - How this principle applies across all projects

---

## Core Philosophy (The "Why")

These documents explain **why Chainwatch exists** and **what principles guide all decisions**.

### 1. Irreversible Boundaries (650+ lines)
**File:** `irreversible-boundaries.md`

**What it covers:**
- Two classes of boundaries: Execution and Authority
- Why some actions cannot be undone (payment, credentials, destruction)
- Why some instructions cannot be un-accepted (proxied commands, injection)
- Real incident: Clawdbot attack (2025) as authority boundary violation
- Critical warnings: how approval workflows can break everything
- Terminology: DENY vs REQUIRE_APPROVAL
- Out-of-band approval requirements

**Key quote:**
> "The system NEVER asks the model whether an irreversible action OR instruction is safe."

**When to read:** First, to understand what Chainwatch is actually doing.

---

### 2. Monotonic Irreversibility (350+ lines)
**File:** `monotonic-irreversibility.md`

**What it covers:**
- Single axis of evolution: Local → Historical → Structural irreversibility awareness
- Correctness ladder: SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE (one-way only)
- v0.2.0 design principles: monotonic boundary accumulation (not graphs)
- Anti-patterns: what NOT to build (ML, prediction, negotiation)
- Why Chainwatch should never become smarter — only more conservative

**Key quote:**
> "Chainwatch optimizes for: Correct under uncertainty and hostile conditions."

**When to read:** After irreversible-boundaries.md, to understand the evolution path.

---

### 3. Boundary Configuration
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

## Design Specifications (The "What" and "How")

These documents specify **exactly what to build** and **how to build it**.

### v0.2.0 Specification (500+ lines)
**File:** `design/v0.2.0-specification.md`

**Status:** Design complete, ready to implement

**What it covers:**
- Zone taxonomy (commercial, credential, egress, sensitive data)
- Authority boundary detection (proxy relay, context crossing, temporal violations)
- TraceState schema evolution (irreversibility_level, zones_entered, authority_context)
- Transition tables and rules (deterministic, no ML)
- Approval workflow design (out-of-band, single-use tokens, model-blind)
- Monotonicity guarantees and testing requirements
- Success criteria

**Key principle:**
> "All anti-patterns and warnings from philosophical docs baked into specification."

**When to read:** Before implementing v0.2.0.

**See also:** `design/README.md` for design specification guidelines.

---

## Implementation Guides

### Current Implementation (v0.1.2)

- `v0.1.1-denylist-usage.md` - Using boundary protection today
- `integrations/file-ops-wrapper.md` - FileGuard capabilities
- `integrations/clawbot-denylist.md` - Clawbot integration
- `testing-guide.md` - Testing with external agents

### Conceptual Background

- `core-idea.md` - Original concept: execution chains as first-class entities
- `mvp-event.md` - Event schema specification
- `position/execution-chain-as-entity.md` - Why existing tools fail

### Decisions

- `decisions/001-first-integration.md` - Why file wrapper first
- `decisions/002-file-classification.md` - Path-based classification rationale

---

## Quick Reference

### "I want to..."

**...understand Chainwatch's philosophy:**
→ Start with `irreversible-boundaries.md`

**...see the evolution roadmap:**
→ Read `monotonic-irreversibility.md`

**...implement v0.2.0:**
→ Read philosophy first, then `design/v0.2.0-specification.md`

**...configure boundaries:**
→ Read `boundary-configuration.md`

**...use Chainwatch today (v0.1.2):**
→ Read `v0.1.1-denylist-usage.md` and README Quick Start

**...integrate with Clawbot:**
→ Read `integrations/clawbot-denylist.md`

**...understand why no ML:**
→ Read `FAQ.md` and `monotonic-irreversibility.md` anti-patterns

---

## Document Hierarchy

```
Philosophy (WHY)
    ├── irreversible-boundaries.md    [Execution + Authority boundaries]
    ├── monotonic-irreversibility.md  [Evolution axis, anti-patterns]
    └── boundary-configuration.md     [Configuration guide]
           ↓
Design (WHAT & HOW)
    └── design/
        └── v0.2.0-specification.md   [Implementation blueprint]
           ↓
Implementation (USAGE)
    ├── v0.1.1-denylist-usage.md     [Current usage]
    ├── integrations/                 [Integration guides]
    └── testing-guide.md              [Testing]
```

**Rule:** Always read philosophy before implementing. Design specifications reference philosophy, not replace it.

---

## Key Principles (Summary)

From all philosophical documents:

1. **Two classes of boundaries:**
   - Execution: actions that cannot be undone
   - Authority: instructions that cannot be un-accepted

2. **Monotonicity:**
   - Boundaries accumulate, never disappear
   - Irreversibility only increases, never decreases
   - One-way transitions: SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE

3. **Control, not observability:**
   - System refuses execution when boundaries crossed
   - Not detection, not logging — enforcement

4. **No model negotiation:**
   - System never asks model if action/instruction is safe
   - Boundaries are absolute, not negotiable
   - Approval is human override, not model bypass

5. **Evolution axis:**
   - Single axis: Local → Historical → Structural irreversibility awareness
   - Never become smarter — only more conservative

6. **Structural, not statistical:**
   - Deterministic rules, not ML
   - Pattern matching, not prediction
   - Boolean logic, not confidence scores

---

## For Contributors

**Before adding features:**
1. Check if it aligns with philosophy (read irreversible-boundaries.md)
2. Check if it fits evolution path (read monotonic-irreversibility.md)
3. Check if it's explicitly deferred (read design/v0.2.0-specification.md non-goals)

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

- **v0.1.2 (current):** Conceptual foundation complete, pattern-based boundaries
- **v0.2.0 (designed):** Specification complete, ready to implement
- **v0.3.0+ (planned):** See monotonic-irreversibility.md evolution path

---

**Last updated:** 2026-02-01

**Maintained by:** Philosophy-first development process

**Questions?** See `FAQ.md` or open an issue on GitHub.
