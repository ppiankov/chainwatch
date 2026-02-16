# Cybercancer Prevention

Detecting and preventing mutations that erode system integrity over time.

---

## What Is Cybercancer?

In engineering terms, cybercancer is any mutation that:

1. **Weakens constraints** — tests removed, checks bypassed, policies relaxed
2. **Increases blast radius** — more privileges, wider scopes, broader access
3. **Breaks reversibility** — no rollback path, no backup, no undo
4. **Hides intent** — obfuscated diffs, "refactor" that sneaks policy changes
5. **Self-protects** — disables chainwatch, disables audit, removes monitoring

These mutations are individually small and often "reasonable." Their danger is cumulative — each one makes the next easier, until the system has no immune response left.

---

## The Killer Rule

> "Guardrails cannot be modified by the same automation cycle they govern."

If an agent can weaken its own constraints, the constraints are theater. This is not a policy — it is an architectural invariant.

---

## Mutation Signatures

### 1. Constraint Weakening

**Signatures:**
- Test files deleted without corresponding source deletion
- CI jobs removed or disabled
- Lint rules relaxed or suppressions added
- Error handling changed from fail to warn
- Validation removed from input boundaries

**Detection:** Diff analysis against Category B (Verification Integrity) invariants.

### 2. Blast Radius Expansion

**Signatures:**
- RBAC permissions added
- File write scope expanded
- Network egress rules broadened
- Secret access grants increased
- Wildcard patterns introduced in allowlists

**Detection:** Diff analysis against Category C (Permission Budget) invariants.

### 3. Reversibility Destruction

**Signatures:**
- Database migration without down migration
- Config change without backup or version control
- Deployment without rollback mechanism
- Data deletion without recovery path

**Detection:** Mutation manifest analysis against Category E (Reversibility Requirement) invariants.

### 4. Intent Obfuscation

**Signatures:**
- Large "refactor" commits that include policy changes
- Renamed files that change behavior
- Comments that contradict code
- Metadata changes bundled with logic changes

**Detection:** Diff analysis — if declared intent is "refactor" but diff touches policy/authz/identity files, escalate.

### 5. Self-Protection

**Signatures:**
- Changes to chainwatch config, rules, or enforcement mode
- Attempts to stop, disable, or replace chainwatch process
- Modifications to audit log storage or format
- Changes to monitoring or alerting configuration

**Detection:** Category A (Guardrail Integrity) invariants — hardest boundary.

---

## Detection Model

Chainwatch does not use ML or heuristics for cybercancer detection. It uses **structural diff analysis**:

```
1. Agent produces diff + mutation manifest
2. Chainwatch classifies each changed file by category (A-E)
3. Chainwatch checks diff against invariant rules
4. Violations → escalate or deny
5. Clean diffs → allow
```

This is deterministic. Same diff always produces same result.

---

## Analogy

Cybercancer is to software systems what cancer is to biological systems:
- Mutations that bypass normal control mechanisms
- Each mutation makes the next easier
- The system loses the ability to detect or respond
- By the time symptoms appear, the damage is systemic

Chainwatch is the immune system — not a cure, but early detection and structural prevention.

---

## Related Documents

- [Five Invariant Categories](invariants.md) — the categories that cybercancer erodes
- [Three Laws of Root Actions](three-laws.md) — Law 3 (self-protection)
- [Governance Doctrine](../governance-doctrine.md) — positioning
