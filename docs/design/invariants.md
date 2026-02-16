# Five Invariant Categories

What chainwatch protects. These are the concrete enforcement domains that map to the Three Laws.

---

## Category A — Guardrail Integrity

**Principle:** Guardrails cannot be modified by the same automation cycle they govern.

### Protected Assets
- Chainwatch rules, config, and policy files
- Audit log storage and format
- Enforcement mode settings
- Boundary definitions

### Enforcement
- **Block** any change to chainwatch config from an automated agent
- **Block** any attempt to disable or downgrade enforcement mode
- **Escalate** manual changes with audit trail

### Killer Rule

> "Guardrails cannot be modified by the same automation cycle they govern."

This is the single most important invariant. If an agent can modify its own guardrails, the guardrails are theater.

---

## Category B — Verification Integrity

**Principle:** The verification system must not be weakened by the system it verifies.

### Protected Assets
- Test coverage (must not decrease)
- CI configuration (jobs must not be removed)
- Verify commands and their exit codes
- Linting and type-checking rules

### Enforcement
- **Escalate** reduction of test coverage below threshold
- **Escalate** CI config changes that remove jobs
- **Escalate** changes to verify command definitions
- **Block** deletion of test files without corresponding source deletion

---

## Category C — Permission Budget

**Principle:** Privileges must not grow without explicit human authorization.

### Protected Assets
- RBAC roles and bindings
- File write scope (which directories are writable)
- Network egress rules (which hosts are reachable)
- Secret access (which secrets are readable)

### Enforcement
- **Escalate** any increase to RBAC permissions
- **Escalate** expansion of file write scope
- **Escalate** new network egress destinations
- **Block** root persistence (cron jobs, systemd units, sudoers changes)

---

## Category D — Change Budget

**Principle:** Oversized changes signal lost control.

### Thresholds (configurable)
- Single work order touches > N files (default: 20)
- Single work order modifies > M lines (default: 500)
- Single work order edits policy/authz/identity/terraform files

### Enforcement
- **Escalate** work orders exceeding file/line thresholds
- **Escalate** any modification to policy, authorization, identity, or infrastructure-as-code files
- **Log** change velocity (changes per hour) for trend analysis

---

## Category E — Reversibility Requirement

**Principle:** Every change must have a rollback path.

### Requirements
- Database migrations must have a down migration
- Deployment changes must have a rollback step
- Configuration changes must preserve the previous value
- File modifications must be backed up or version-controlled

### Enforcement
- **Escalate** if no rollback mechanism is declared
- **Escalate** if backup step is missing for destructive operations
- **Block** irreversible operations without break-glass token

---

## Mutation Manifest

To enforce these invariants, agents must produce a **mutation manifest** per work order:

| Field | Description |
|-------|-------------|
| `intent` | What the agent is trying to accomplish |
| `scope` | Which repos, files, services are affected |
| `risk` | Self-declared: low / medium / high |
| `rollback` | How to undo the change |
| `verification` | Commands to run to verify correctness |

Chainwatch uses this manifest as a **diff lens** — if the actual diff contradicts the declared intent, escalate.

---

## Mutation-Chainwatch Integration Model

```
1. Plan phase     → Agent proposes diffs + mutation manifest
2. Check phase    → Chainwatch evaluates diff + manifest against invariants
3. Apply phase    → Only after Pass or Escalate-and-Confirm
4. Verify phase   → Tests, lint, runtime smoke
5. Commit phase   → Signed, traceable, auditable
```

---

## Related Documents

- [Three Laws of Root Actions](three-laws.md) — the principles these invariants implement
- [Cybercancer Prevention](cybercancer-prevention.md) — detecting invariant erosion
- [Governance Doctrine](../governance-doctrine.md) — positioning
