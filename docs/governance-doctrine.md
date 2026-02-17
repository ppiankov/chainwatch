# Governance Doctrine

**Autonomy, Contained.**

Full root-capable autonomy inside enforceable human guardrails.

---

## Position

Chainwatch is not adversarial security. It is **confidence scaffolding**.

Users should feel safe giving agents root access — not because the agent is trustworthy, but because the system prevents catastrophic outcomes structurally.

Chainwatch does not judge intent. It enforces boundaries.

---

## First Principle

**"First, do no irreversible harm."**

A Hippocratic oath for the cyber age. Agents may do anything — except cross points of no return without explicit, out-of-band human authorization.

---

## Nuclear Launch Cycle

Irreversible actions follow a dual-authorization model:

1. **Agent proposes** — declares intent, scope, risk, rollback path
2. **System evaluates** — checks against invariants and boundaries
3. **Human authorizes** — out-of-band, single-use, time-limited token
4. **System executes** — only after all gates pass
5. **System verifies** — post-execution integrity check

No single actor (agent, system, or human) can unilaterally cross an irreversible boundary. This is not bureaucracy — it is structural safety.

---

## Refusal Character

Refusals must be:

- **Calm** — no drama, no sermon
- **Predictable** — same input always produces same refusal
- **Explainable** — precise reason, not vague warning
- **Actionable** — tells the user what would be needed to proceed

Example: `Refused: Action modifies protected control plane component. Request break-glass token to override.`

If chainwatch is too strict, users bypass it. If too lax, users ignore it. The sweet spot is **calm refusal + precise explanation**.

---

## Anti-Daktaklakpak DNA

Avoid rigid logic + self-importance + no context. Preserve:

1. **Reversibility** — always leave a way back
2. **Human override** — break-glass, not brick-wall
3. **Auditability** — every decision traceable
4. **Humility** — do not worship efficiency above safety

---

## Ecosystem Position

```
AttentionFirst
  ├── Philosophy / Principles (Principiis obsta)
  ├── Runforge (Execution — deterministic AI orchestration)
  ├── Chainwatch (Guardrails — runtime control plane)
  └── Spectre family (Schema drift detection)
```

Chainwatch is the guardrails layer. It does not execute work (that's Runforge). It does not detect drift (that's Spectre). It **enforces boundaries at runtime**.

---

## What Chainwatch Is NOT

- Not a prompt firewall or jailbreak detector
- Not an IAM/RBAC replacement
- Not an observability platform
- Not adversarial red-team tooling
- Not a compliance checkbox

---

## Related Documents

- [Three Laws of Root Actions](design/three-laws.md) — implementable enforcement rules
- [Five Invariant Categories](design/invariants.md) — what chainwatch protects
- [Enforcement Modes](design/enforcement-modes.md) — advisory, guarded, locked
- [Cybercancer Prevention](design/cybercancer-prevention.md) — mutation detection
- [Fieldtest Test Plan](design/fieldtest-test-plan.md) — battlefield testing
- [DESIGN_BASELINE.md](DESIGN_BASELINE.md) — Principiis obsta
- [irreversible-boundaries.md](irreversible-boundaries.md) — core concept
