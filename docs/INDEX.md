# Chainwatch Documentation Guide

**Navigation hub for all Chainwatch concepts and specifications.**

---

## Quick Navigation

**I want to...**

- **...understand what Chainwatch is** → Start with [README.md](../README.md)
- **...understand the core philosophy** → Read [irreversible-boundaries.md](#irreversible-boundaries)
- **...understand the governance doctrine** → Read [governance-doctrine.md](#governance-doctrine)
- **...see the evolution roadmap** → Read [monotonic-irreversibility.md](#monotonic-irreversibility)
- **...implement v0.2.0** → Read [design/v0.2.0-specification.md](#v020-specification)
- **...understand enforcement rules** → Read [design/three-laws.md](#three-laws-of-root-actions)
- **...understand what is protected** → Read [design/invariants.md](#five-invariant-categories)
- **...configure enforcement modes** → Read [design/enforcement-modes.md](#enforcement-modes)
- **...configure boundaries** → Read [boundary-configuration.md](#boundary-configuration)
- **...configure agent identity** → See [Agent Identity & Sessions](#agent-identity--sessions)
- **...configure budget limits** → See [Budget Enforcement](#budget-enforcement)
- **...use the Go SDK** → See [Go SDK](#go-sdk)
- **...use the Python SDK** → See [Python SDK](#python-sdk)
- **...set up MCP integration** → See [MCP Tool Server](#mcp-tool-server)
- **...set up gRPC policy server** → See [Central Policy Server](#central-policy-server-grpc)
- **...run adversarial tests** → Read [design/fieldtest-test-plan.md](#fieldtest-test-plan)
- **...write agent-ready tasks** → Read [design/agent-task-quality.md](#agent-task-quality)
- **...use Chainwatch today** → Read [Quick Start](../README.md#quick-start) and [getting-started.md](#getting-started)
- **...understand RootOps** → Read [DESIGN_BASELINE.md](#design-baseline) and [rootops-antipatterns.md](#rootops-antipatterns)
- **...learn about forbidden architectures** → Read [security-classes.md](#security-classes)
- **...see implementation progress** → Read [work-orders.md](work-orders.md)

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

## Governance

### Governance Doctrine

**File:** `governance-doctrine.md`

**Autonomy, Contained.** Full root-capable autonomy inside enforceable human guardrails.

**What it covers:**
- Positioning: confidence scaffolding, not adversarial security
- First principle: "First, do no irreversible harm"
- Nuclear launch cycle (dual-authorization for irreversible actions)
- Refusal character: calm, predictable, explainable, actionable
- Ecosystem position (Runforge, Chainwatch, Spectre family)

**Key quote:**
> "Guardrails cannot be modified by the same automation cycle they govern."

**When to read:** To understand what Chainwatch stands for and how it fits the ecosystem.

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

**Status:** Core implemented (CW-01 through CW-17 complete)

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

## Implemented Features

### Evaluation Pipeline

The policy evaluation pipeline runs in this fixed order:

```
Step 1:    Denylist check → deny (tier 3)
Step 2:    Zone escalation → update state
Step 3:    Tier classification → safe(0) / elevated(1) / guarded(2) / critical(3)
Step 3.5:  Agent enforcement → scope, purpose, sensitivity, per-agent rules (CW-16)
Step 3.75: Budget enforcement → per-agent session resource caps (CW-17)
Step 4:    Purpose-bound rules → first match wins
Step 5:    Tier enforcement → mode + tier → decision
```

### Five Interception Points

All implemented, all wired to the same evaluation pipeline:

| Interception Point | Package | CLI Command | WO |
|---|---|---|---|
| Subprocess wrapper | `internal/cmdguard/` | `chainwatch exec` | CW-03 |
| HTTP forward proxy | `internal/proxy/` | `chainwatch proxy` | CW-02 |
| MCP tool server | `internal/mcp/` | `chainwatch mcp` | CW-08 |
| LLM response interceptor | `internal/intercept/` | `chainwatch intercept` | CW-11 |
| gRPC policy server | `internal/server/` | `chainwatch serve` | CW-15 |

### SDKs

| SDK | Package | Integration Style | WO |
|---|---|---|---|
| Go SDK | `sdk/go/chainwatch/` | In-process (zero overhead) | CW-10 |
| Python SDK | `sdk/python/chainwatch_sdk/` | Subprocess (calls CLI) | CW-09 |

### Agent Identity & Sessions

**Package:** `internal/identity/`

Per-agent, per-session enforcement. Agents register in `policy.yaml` with allowed purposes, resource scopes, sensitivity caps, and per-agent rules. Unknown agents are denied (fail-closed). Configured via `agents:` section in policy.yaml and `--agent` CLI flag.

### Budget Enforcement

**Package:** `internal/budget/`

Per-agent session caps on bytes, rows, and duration. When a budget is exceeded, the next action is denied. Configured via `budgets:` section in policy.yaml. Lookup order: agent-specific → global `"*"` fallback → skip. View with `chainwatch budget status`.

### Audit & Compliance

| Feature | Package | CLI Command | WO |
|---|---|---|---|
| Hash-chained audit log | `internal/audit/` | `chainwatch audit verify/tail` | CW-12 |
| Session replay | `internal/audit/` + `internal/cli/` | `chainwatch replay <trace-id>` | CW-13 |
| Alert webhooks | `internal/alert/` | Configured in policy.yaml | CW-14 |

### Additional Features

| Feature | Package | CLI Command | WO |
|---|---|---|---|
| Safety profiles | `internal/profile/` | `chainwatch profile list/check/apply` | CW-05 |
| Approval workflow | `internal/approval/` | `chainwatch approve/deny/pending` | CW-06 |
| Break-glass override | `internal/breakglass/` | `chainwatch break-glass` | CW-23.2 |
| Root access monitor | `internal/monitor/` | `chainwatch root-monitor` | CW-07 |

---

## Enforcement Design

### Three Laws of Root Actions

**File:** `design/three-laws.md`

Asimov-inspired, implementable enforcement rules:
- Law 1: No catastrophic blast radius (refuse/escalate destructive actions)
- Law 2: Obey only within declared intent + policy (scope enforcement)
- Law 3: Protect itself non-destructively (tamper-evident, break-glass)

**When to read:** To understand the enforcement rule hierarchy.

---

### Five Invariant Categories

**File:** `design/invariants.md`

What chainwatch protects:
- A: Guardrail integrity (block changes to chainwatch itself)
- B: Verification integrity (block test/CI reduction)
- C: Permission budget (escalate privilege increases)
- D: Change budget (escalate oversized work orders)
- E: Reversibility requirement (escalate if no rollback path)

Also defines the **mutation manifest** format for agent work orders.

**When to read:** To understand what invariants enforcement checks against.

---

### Enforcement Modes

**File:** `design/enforcement-modes.md`

Three operational modes:
- **Advisory** — observe + score + warn (easy adoption)
- **Guarded** (default) — block high-risk, confirm medium, allow low
- **Locked** — strict allowlists only (regulated environments)

Includes mode transition rules and configuration examples.

**When to read:** When deploying chainwatch and choosing strictness level.

---

### Cybercancer Prevention

**File:** `design/cybercancer-prevention.md`

Detecting mutations that erode system integrity:
- Constraint weakening, blast radius expansion, reversibility destruction
- Intent obfuscation, self-protection attacks
- Structural diff analysis (deterministic, no ML)

**When to read:** To understand long-term integrity protection.

---

### Fieldtest Test Plan

**File:** `design/fieldtest-test-plan.md`

Battlefield testing: chainwatch vs. autonomous agents with root access:
- 5 test rounds (legitimate work → direct attack → reboot survival)
- Adversary roster (Ansible, Terraform, eBPF, polite root agent)
- VM setup and scoring criteria

**When to read:** Before running adversarial validation.

---

### Agent Task Quality

**File:** `design/agent-task-quality.md`

Standards for agent-executable work orders:
- Contract-style documentation (inputs, outputs, side effects, failure modes)
- Structured I/O constraints
- Think/do split (cheap model plans, expensive model executes)
- Work order templates (refactor, bugfix, migration, investigation)
- Agentic leverage levels (1-5)

**When to read:** When writing skills, work orders, or task definitions.

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
- `browser-checkout-gate.md` - Browser wrapper spec
- `agent-runtime-hooks.md` - Agent runtime integration patterns
- `http-proxy.md` - HTTP proxy integration
- `output-interception.md` - LLM response interception
- `tool-wrapper.md` - Tool wrapping patterns

---

## Decision Records

**Directory:** `decisions/`

- `001-first-integration.md` - Why file wrapper first
- `002-file-classification.md` - Path-based classification rationale

---

## Document Hierarchy

```
Governance (Positioning - WHO)
└── governance-doctrine.md         [Autonomy, Contained]
       ↓
Foundation (Philosophy - WHY)
├── DESIGN_BASELINE.md             [Principiis obsta]
├── irreversible-boundaries.md     [Core concept]
└── monotonic-irreversibility.md   [Evolution path]
       ↓
Enforcement Design (WHAT)
├── design/three-laws.md           [Three Laws of Root Actions]
├── design/invariants.md           [Five Invariant Categories]
├── design/enforcement-modes.md    [Advisory / Guarded / Locked]
├── design/cybercancer-prevention.md [Mutation detection]
└── design/agent-task-quality.md   [Work order standards]
       ↓
Design (HOW)
├── design/v0.2.0-specification.md [Implementation blueprint]
└── boundary-configuration.md      [Configuration guide]
       ↓
Security (Forbidden Architectures)
├── security-classes.md            [CW-01 through CW-05]
└── rootops-antipatterns.md        [Convenient Trust Amplifier]
       ↓
Validation
└── design/fieldtest-test-plan.md   [Adversarial testing]
       ↓
Implementation (Usage)
├── getting-started.md             [Onboarding]
├── testing-guide.md               [Testing]
├── integrations/                  [Integration guides]
└── work-orders.md                 [Full implementation roadmap]
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

- **v0.1.x:** Conceptual foundation, pattern-based boundaries
- **v0.2.0 (current):** Monotonic state machine, 5 interception points, agent identity, budget enforcement, audit log, SDKs, gRPC server — Phases 0-3 complete (CW-01 through CW-17)
- **Next:** Phase 4 (rate limiting, policy simulator, CI gate, policy diff) and Phase 5 (profile marketplace, agent certification)
- **v0.3.0+ (planned):** See monotonic-irreversibility.md evolution path

---

**Last updated:** 2026-02-16

**Maintained by:** Philosophy-first development process

**Questions?** See `FAQ.md` or open an issue on GitHub.
