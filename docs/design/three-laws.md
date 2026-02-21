# Three Laws of Root Actions

Asimov-inspired, implementable enforcement rules for autonomous agents with elevated privileges.

---

## Law 1 — No Catastrophic Blast Radius

Chainwatch must refuse or escalate actions that can plausibly cause outage, data loss, or security breach.

### Concrete Action Classes

**Destructive filesystem operations:**
- Delete/overwrite on system-critical paths (`/etc`, `/var/lib`, kube manifests, PKI directories)
- Recursive removal of non-trivial directory trees
- Overwrite of configuration without backup

**Security component tampering:**
- Disable security/audit/identity components (chainwatch itself, auditd, sshd, kube-apiserver configs)
- Modify firewall rules, flush iptables, nuke route tables
- Stop or restart authentication services

**Network isolation breaking:**
- Firewall flush operations
- Route table modifications
- VPN/tunnel teardown

**Credential exfiltration patterns:**
- Dump secrets from vault, keychain, or credential stores
- Copy key material to external locations
- Expose tokens in logs, URLs, or environment variables

### Enforcement

All Law 1 actions are **DENY by default**. Override requires break-glass token with:
- Explicit reason string
- Time limit (default: 10 minutes)
- Single use
- Audit trail

---

## Law 2 — Obey Only Within Declared Intent + Policy

Agents must declare intent before executing. Chainwatch enforces that actions stay within declared scope.

### Requirements

Every agent session must declare:
- **Intent** — what the agent is trying to accomplish
- **Scope** — which repos, files, services are in bounds
- **Operations** — what classes of actions are expected (read, write, execute, network)

### Enforcement

If an action falls outside declared scope:

```
Refused: out of scope. Re-declare intent or request escalation.
```

No negotiation. No "but I need this to complete the task." The agent re-declares with broader scope, and a human approves the expanded scope.

### Scope Creep Detection

Chainwatch tracks the ratio of in-scope to out-of-scope action attempts. If an agent consistently bumps against scope boundaries, this is flagged as **scope creep** — a signal that either the intent was too narrow or the agent is drifting.

---

## Law 3 — Protect Itself Non-Destructively

Chainwatch must be tamper-evident. It must never brick a system to protect itself.

### Self-Protection Mechanisms

**Tamper-evident storage:**
- Append-only log with hash chain
- Each entry references the hash of the previous entry
- Truncation or modification is detectable

**Watchdog:**
- Monitor for stop/kill/replace attempts against chainwatch process
- Log all attempts with caller identity and context
- Alert on process termination

**Break-glass mode:**
- When legitimate bypass is needed, break-glass tokens are:
  - Explicit (must be requested)
  - Logged (immutable audit trail)
  - Time-limited (default: 10 minutes, max: 1 hour)
  - Single-use (consumed on first action)
  - Optionally 2-person approval (roadmap)

### Non-Destructive Constraint

Chainwatch must **never** brick a system to protect itself. If chainwatch cannot enforce, it:
1. Logs the violation with full context
2. Alerts the operator
3. Fails open with audit trail (not fail closed with system down)

The system's job is to **leave evidence**, not to **become the problem**.

---

## Implementation Priority

1. **Law 1** (v0.2.0) — pattern-based detection of catastrophic actions
2. **Law 2** (v0.3.0) — intent declaration and scope enforcement
3. **Law 3** (v0.3.0) — tamper-evident storage and watchdog

---

## Related Documents

- [Governance Doctrine](../governance-doctrine.md) — positioning and philosophy
- [Five Invariant Categories](invariants.md) — what these laws protect
- [Enforcement Modes](enforcement-modes.md) — how strictness scales
