# Enforcement Modes

Three operational modes that scale enforcement strictness to deployment context.

---

## Advisory Mode

**Purpose:** Easy adoption. Observe, score, warn — never block.

### Behavior
- All actions are **allowed**
- Boundary crossings are **logged** with severity
- Warnings emitted to operator
- No enforcement decisions applied

### Use Case
- First deployment in a new environment
- Understanding what agents actually do before enforcing
- Building confidence in boundary definitions before enforcement
- Generating audit data for policy tuning

### Risk
- No protection. Advisory mode is **observation only**.
- Must not remain in advisory mode permanently — it is a stepping stone.

---

## Guarded Mode (Default)

**Purpose:** Balanced enforcement. Block high-risk, confirm medium-risk, allow low-risk.

### Behavior
- **High-risk actions** (Law 1 violations) → **DENY**
- **Medium-risk actions** (scope boundary, permission increase) → **REQUIRE_APPROVAL**
- **Low-risk actions** (within declared scope and policy) → **ALLOW**

### Approval Flow
- Medium-risk actions trigger out-of-band approval request
- Approval is single-use, time-limited, logged
- Agent cannot observe or influence the approval process
- Timeout defaults to deny

### Use Case
- Standard operating mode for most environments
- Development and staging environments with real data
- Production environments with moderate autonomy

---

## Locked Mode

**Purpose:** Strict allowlists only. Everything not explicitly allowed is denied.

### Behavior
- Only actions matching an explicit allowlist are **permitted**
- Everything else is **DENY** with audit log
- No approval flow — either allowed or denied
- Break-glass token required for any exception

### Allowlist Structure
```yaml
locked_mode:
  allow:
    - action: file_read
      scope: /app/data/**
    - action: http_get
      scope: https://api.internal/**
    - action: execute
      scope: /usr/bin/python3
```

### Use Case
- Regulated environments (finance, healthcare, government)
- Production environments with high blast radius
- Environments where agent autonomy must be minimized
- Post-incident lockdown

---

## Mode Transitions

```
Advisory → Guarded → Locked
   ↑                    |
   └────────────────────┘
        (break-glass)
```

### Rules
- **Escalation** (Advisory → Guarded → Locked) can be automated
- **De-escalation** (Locked → Guarded → Advisory) requires human authorization
- Mode changes are logged with operator identity and reason
- Agents cannot change enforcement mode (Category A invariant)

---

## Configuration

```yaml
enforcement:
  mode: guarded  # advisory | guarded | locked

  guarded:
    high_risk: deny
    medium_risk: require_approval
    low_risk: allow
    approval_timeout: 300  # seconds

  locked:
    allowlist_file: /etc/chainwatch/allowlist.yaml
    break_glass:
      max_duration: 600  # seconds
      require_reason: true
      two_person: false  # roadmap
```

---

## Related Documents

- [Three Laws of Root Actions](three-laws.md) — what determines risk level
- [Five Invariant Categories](invariants.md) — what is protected in each mode
- [Governance Doctrine](../governance-doctrine.md) — positioning
