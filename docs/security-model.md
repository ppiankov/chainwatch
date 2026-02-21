# Security Model

How chainwatch and nullbot enforce safety boundaries. This document describes the architectural invariants, privilege model, and what is structurally impossible by design.

---

## Privilege Model

Nullbot runs as a dedicated system user (`nullbot`) with:

- No login shell
- No sudo access
- No home directory write access beyond its state directories
- Systemd hardening (PrivateTmp, ProtectSystem=strict, NoNewPrivileges, MemoryDenyWriteExecute)
- CPU, memory, and task limits enforced by cgroup

Every command nullbot executes passes through `chainwatch exec`, which evaluates the command against policy before allowing execution. Chainwatch is not optional. Without it, nullbot cannot run a single command.

---

## Enforcement Architecture

Chainwatch evaluates commands through five independent layers. An attacker must bypass all five to exfiltrate credentials or cause damage:

1. **Self-targeting detection** — commands that reference chainwatch or nullbot identity files are denied at the highest severity tier. This is structural and cannot be overridden by policy, profile, or approval.

2. **Denylist** — known-dangerous command patterns (recursive deletion, pipe-to-shell, environment dumping, credential access) are blocked before execution.

3. **Profile boundaries** — each agent profile declares which files, directories, and operations are in scope. Out-of-scope access is denied.

4. **Environment sanitization** — spawned subprocesses receive a sanitized environment with sensitive variables stripped. Even if a command bypasses other layers, it cannot read API keys from its own environment.

5. **Output scanning** — command output is scanned for credential patterns before results leave the process. Detected secrets are redacted and an audit entry is recorded.

Each layer uses different matching logic (substring, pattern, glob, prefix, output inspection), making coordinated evasion significantly harder.

---

## Invariants

These properties hold at all times and cannot be weakened by the agent, by policy configuration, or by human approval:

### Guardrails cannot be modified by the automation they govern

An agent cannot modify chainwatch policy, disable enforcement, or alter its own boundaries. This is the single most important invariant. If an agent can edit its own guardrails, the guardrails are theater.

### Self-targeting is non-negotiable

Commands that target chainwatch or nullbot identity are classified at the highest severity tier and denied. No approval, purpose, or break-glass token overrides self-targeting. The agent cannot read its own config, dump its own environment, access its own API keys, or modify its own binary.

### Nullbot does not modify configuration files

Nullbot does not write to system configuration, chainwatch policy, or its own settings. It gathers evidence, proposes remediation, and executes approved commands. It does not reconfigure systems.

### Approval does not bypass enforcement

When a human approves a work order, the approved commands still pass through chainwatch policy evaluation. Approval authorizes the intent, not the specific commands. Destructive commands are still denied even within an approved work order.

### Binary integrity is verified at startup

Chainwatch verifies its own binary against a build-time hash at startup. If the binary has been tampered with, the process refuses to start. This prevents an attacker from replacing the binary to disable all other layers.

### Audit trail is tamper-evident

The audit log is append-only with SHA-256 hash chaining. Each entry references the hash of the previous entry. Truncation, modification, or deletion is detectable. File permissions restrict access to the owning user.

---

## What Is Impossible by Design

These outcomes are structurally prevented, not merely discouraged:

| Outcome | Prevention mechanism |
|---|---|
| Agent reads its own API keys | Self-targeting + env sanitization + output scanning |
| Agent modifies chainwatch policy | Self-targeting (highest tier, non-overridable) |
| Agent disables its own enforcement | Self-targeting + binary integrity |
| Agent leaks credentials in output | Output scanning with redaction |
| Subprocess inherits sensitive env vars | Environment sanitization strips them |
| Agent runs without chainwatch | Binary architecture requires chainwatch as execution wrapper |
| Tampered binary runs undetected | Build-time hash verification at startup |
| Audit log is silently modified | SHA-256 hash chain; any edit breaks the chain |

---

## What Is Out of Scope

Chainwatch is a deterministic policy engine, not a general-purpose security system. These threats are explicitly not addressed:

- **Compromised host OS.** If the kernel is compromised, all bets are off. Chainwatch assumes the host OS is trusted.
- **Correctly-configured policy.** Chainwatch enforces whatever policy is configured. A misconfigured policy can allow dangerous commands. The installer provides safe defaults, but operators must review.
- **Novel encoding or steganography.** Output scanning catches common credential formats. It does not detect secrets hidden in compressed data, images, or novel encodings. Chainwatch is not a DLP system.
- **Human-approved destructive actions.** If a human approves a work order that causes damage through allowed commands, chainwatch does not prevent it. Approval is a human decision with human responsibility.
- **Side-channel exfiltration.** Timing attacks, covert channels through exit codes, or DNS-based exfiltration are not addressed. These require network-level controls outside chainwatch's scope.
- **Supply chain attacks on dependencies.** Chainwatch verifies its own binary integrity but does not audit its build dependencies.

---

## Break-Glass

When legitimate bypass of a denied action is needed, operators can issue a break-glass token:

- Must be explicitly requested (never automatic)
- Logged immutably in the audit trail
- Time-limited (default: 10 minutes)
- Single-use (consumed on first action)
- Does not override self-targeting (nothing does)

Break-glass exists because real operations sometimes require actions that look dangerous. The goal is to make the bypass auditable and bounded, not to prevent it entirely.

---

## Design Principles

- **Structural, not negotiable.** Safety boundaries are enforced by architecture, not by prompts or conventions.
- **Fail-closed.** When in doubt, deny. Conservative matching is intentional.
- **Non-destructive.** Chainwatch denies actions and logs them. It never bricks the system to protect itself.
- **Evidence over intervention.** The system leaves a clear trail. It is a mirror, not an oracle.
- **Determinism over ML.** Policy evaluation is deterministic. No training data, no probabilistic scoring, no model drift.

---

## Related

- [Deployment Guide](deployment.md) — installation and configuration
- [Operator Workflow](operator-workflow.md) — how work orders flow through the system
