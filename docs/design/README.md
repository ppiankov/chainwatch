# Design Specifications

This directory contains **implementation blueprints** for Chainwatch versions.

These are not philosophical documents. These are concrete specifications that can be implemented from.

## Purpose

Design specifications serve to:
1. **Lock in the design** before implementation starts
2. **Prevent drift** from core philosophy during coding
3. **Provide reference** for implementation decisions
4. **Enable verification** that implementation matches design

## Structure

Each specification includes:
- **Zone/Boundary taxonomy** - concrete definitions
- **Detection mechanisms** - structural rules, not heuristics
- **State schema** - exact fields and invariants
- **Transition logic** - deterministic state updates
- **Approval workflows** - out-of-band mechanisms
- **Testing requirements** - verification criteria
- **Non-goals** - explicit deferrals
- **Success criteria** - when is it done?

## Available Specifications

### v0.2.0 - Monotonic Boundary Accumulation
**File:** `v0.2.0-specification.md` (500+ lines)

**Status:** Design complete, ready to implement

**Core features:**
- Zone-based execution boundaries
- Authority boundary detection
- Monotonic state transitions
- Out-of-band approval workflow

**Philosophy references:**
- `docs/irreversible-boundaries.md` - Why (both execution and authority)
- `docs/monotonic-irreversibility.md` - Evolution path and anti-patterns

## How to Use

**Before implementing v0.X.0:**
1. Read the philosophical documents first (understand why)
2. Read the specification (understand what and how)
3. Implement according to spec (don't deviate)
4. Verify against success criteria
5. Test against monotonicity invariants

**If you find yourself:**
- Adding ML or heuristics → STOP, re-read philosophy
- Letting model influence decisions → STOP, re-read approval warnings
- Softening boundaries → STOP, re-read monotonic-irreversibility.md
- Adding features not in spec → STOP, defer to next version

## Relationship to Other Docs

```
docs/
├── Core Philosophy (WHY)
│   ├── irreversible-boundaries.md
│   ├── monotonic-irreversibility.md
│   └── boundary-configuration.md
│
├── Design Specs (WHAT & HOW)
│   └── design/
│       └── v0.2.0-specification.md
│
└── Integration Guides (USAGE)
    ├── integrations/
    └── testing-guide.md
```

Philosophy → Design → Implementation

Never skip the philosophy.

---

*Last updated: 2026-02-01*
