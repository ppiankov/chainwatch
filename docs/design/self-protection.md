# Self-Protection — Law 3 Implementation

Chainwatch structurally prevents agents from reading, modifying, or exfiltrating its own configuration, credentials, and identity files.

---

## Self-Targeting Detection

Any action whose resource or tool name contains a self-targeting pattern is automatically classified as **Tier 3 (Critical)** and denied by default. This is structural — no policy rule, profile, or purpose can override it.

### Protected Patterns

| Pattern | Protects |
|---|---|
| `chainwatch` | Binary, config, process references |
| `.chainwatch/` | Config directory (`~/.chainwatch/`) |
| `chainwatch.yaml` | Policy and config files |
| `nullbot` | Binary, env file, systemd unit, config |
| `.groq-key` | LLM API key fallback file |

### Examples

```
cat ~/config/nullbot.env          → blocked (contains "nullbot")
rm /usr/local/bin/chainwatch      → blocked (contains "chainwatch")
cat /tmp/.groq-key                → blocked (contains ".groq-key")
systemctl stop nullbot            → blocked (contains "nullbot")
cat ~/.chainwatch/policy.yaml     → blocked (contains ".chainwatch/")
ls /tmp/reports                   → allowed (no self-targeting pattern)
```

### Tool Name Check

Actions are also blocked if the **tool name** contains `chainwatch` or `nullbot`, regardless of the resource being accessed.

---

## Env Variable Exfiltration Prevention

API keys are loaded from environment variables (`NULLBOT_API_KEY`, `GROQ_API_KEY`). The denylist blocks commands that dump environment variables:

| Blocked Command | Vector |
|---|---|
| `printenv` | Dumps all environment variables |
| `/proc/self/environ` | Reads process environment via procfs |
| `/proc/*/environ` | Reads any process environment via procfs |

Note: bare `env` is intentionally not blocked — it appears as a substring in too many legitimate contexts (`environment`, `envelope`, etc.).

---

## Profile Execution Boundaries

The `clawbot` and `vm-cloud` profiles add file-level blocks for nullbot identity files:

- `**/nullbot.env` — environment file with API keys
- `**/.groq-key` — LLM key fallback file

Policy rules also block access to resources matching `*nullbot*config*`.

---

## Defense Layers

Self-protection operates at three independent layers:

1. **Self-targeting (Tier 3)** — broadest, pattern-based, fail-closed
2. **Denylist** — blocks specific exfiltration commands
3. **Profile boundaries** — blocks specific files and resource patterns

An attacker must bypass all three layers to access nullbot credentials. Each layer uses different matching logic (substring, regex, glob), making evasion significantly harder.

---

## Design Principles

- **Structural, not negotiable** — self-targeting cannot be overridden by purpose or approval
- **Fail-closed** — broad substring matching is intentionally conservative
- **Non-destructive** — chainwatch denies the action and logs it; it never bricks the system
- **Audit trail** — all denied actions are recorded with reason and context

---

## Related Documents

- [Three Laws of Root Actions](three-laws.md) — foundational philosophy (Law 3)
- [Five Invariant Categories](invariants.md) — Category A: Guardrail Integrity
- [Enforcement Modes](enforcement-modes.md) — how tier 3 maps to deny decisions
