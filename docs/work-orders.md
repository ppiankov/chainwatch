# Work Orders — chainwatch

## WO-CW01: v0.2.0 Core — Monotonic State Machine ✅

**Goal:** Implement the two-stage boundary enforcement from `docs/design/v0.2.0-specification.md`.

### Implementation
- `internal/model/boundary.go` — BoundaryZone constants (Safe, Sensitive, Commitment, Irreversible)
- `internal/zone/detect.go` — `DetectZones()` with 8 fine-grained zone patterns
- `internal/zone/level.go` — `ComputeIrreversibilityLevel()` with monotonic enforcement
- `internal/authority/check.go` — `CheckAdmission()` for Stage 1 boundary checks
- `internal/policy/evaluate.go` — zone-aware risk evaluation replacing flat scoring

---

## WO-CW02: HTTP Proxy Wrapper ✅

**Goal:** Add an HTTP proxy that intercepts agent outbound requests and enforces policy.

### Implementation
- `internal/proxy/server.go` — MITM-free forward proxy with HTTP and HTTPS CONNECT tunneling
- `internal/cli/proxy.go` — `chainwatch proxy --port 8888` CLI command
- Denylist enforcement on both plain HTTP and CONNECT requests
- Policy evaluation before forwarding; blocks on Deny or RequireApproval decisions

---

## WO-CW03: Subprocess Wrapper ✅

**Goal:** Intercept subprocess/shell commands agents execute.

### Implementation
- `internal/cmdguard/guard.go` — `Guard` with `Run()` and `Check()` for command interception
- `internal/cmdguard/action.go` — action builder from command invocations
- `internal/cli/exec.go` — `chainwatch exec` CLI command with `--dry-run` mode
- Policy evaluation and denylist check before execution; captures stdout/stderr/exit code

---

## WO-CW04: Declarative Policy YAML ✅

**Goal:** Move policy rules from hardcoded constants to YAML config.

### Implementation
- `internal/policy/config.go` — `PolicyConfig` with `Thresholds`, `SensitivityWeights`, YAML loading
- `internal/policy/risk.go` — risk scoring from config values
- `internal/cli/init_policy.go` — `chainwatch init-policy` generates default YAML
- `LoadConfig()` reads `~/.chainwatch/policy.yaml` with fallback to defaults

---

## WO-CW05: Clawbot Safety Profile ✅

**Goal:** Ship a pre-built denylist + policy profile for Clawbot-style AI agents.

### Implementation
- `internal/profile/profile.go` — profile loading (built-in + user-defined)
- `internal/profile/builtin.go` — embedded clawbot profile
- `internal/profile/apply.go` — runtime application to guard/proxy configs
- `internal/profile/profiles/clawbot.yaml` — authority boundaries (injection, escalation) + execution boundaries (payments, credentials, dangerous commands)
- `internal/cli/profile.go` — `chainwatch profile list|check|apply` commands

---

## WO-CW06: Approval Workflow CLI

**Goal:** Interactive approval flow for require-approval decisions.

### Context
`RequireApproval` decision type exists in `internal/model/types.go`. Both proxy and guard generate `ApprovalKey` in trace records and block with HTTP 403 / `BlockedError`. Missing: CLI commands to manage approvals.

### Steps
1. Create `internal/approval/store.go` — file-based approval state (`~/.chainwatch/pending/`)
2. Create `internal/cli/approve.go` — `chainwatch approve <key>` grants one-time approval
3. Add `--duration 5m` flag for time-limited approval
4. Create `internal/cli/pending.go` — `chainwatch pending` lists pending approvals
5. Create `internal/cli/deny.go` — `chainwatch deny <key>` explicitly denies
6. Wire approval store into guard and proxy decision paths
7. Approval state is per-session (not persistent across restarts)

### Tests
- Pending approval blocks execution
- Approved key allows execution (once)
- Time-limited approval expires
- Denial is recorded in trace

### Acceptance
- `make go-test` passes with -race
- End-to-end: agent hits approval boundary → human approves → agent continues

---

## WO-CW07: Root Access Monitor — Constant Enforcement Daemon

**Goal:** A persistent monitor that blocks root-level system operations in real time, not after the fact.

### Context
Clawbot runs on a VM with root access. This means the agent can `sudo`, write to `/etc/`, create systemd services, modify firewall rules, change file ownership, install packages — all irreversible. CW03 (cmdguard) catches shell commands routed through `chainwatch exec`, but a determined agent (or injected instruction) can spawn processes directly. The root monitor is a separate enforcement layer: a daemon that watches for root-level operations regardless of how they're triggered.

### Architecture
Lightweight daemon process (not the same as the proxy or guard):
```
chainwatch root-monitor --pid <agent-pid>
```
Monitors the agent process tree and blocks:

### Blocked Operations
- `sudo` / `su` / `doas` — privilege escalation
- `chmod 777` / `chmod +s` — permission weakening
- `chown root` — ownership escalation
- Writes to `/etc/`, `/usr/lib/systemd/`, `/var/spool/cron/`
- `systemctl enable/start` — service persistence
- `iptables` / `nft` / `ufw` — firewall modification
- `useradd` / `usermod` / `passwd` — account manipulation
- `mount` / `umount` — filesystem manipulation
- Package managers: `apt install`, `yum install`, `pip install --system`
- `curl | sh` / `wget | bash` — remote code execution

### Enforcement Mechanism
- Linux: `seccomp-bpf` filter on agent process tree (blocks at kernel level, no bypass)
- Fallback: `ptrace`-based syscall interception (works without seccomp)
- Fallback: polling `/proc/<pid>/` for open files and new child processes (least secure, most portable)
- All blocked attempts logged to trace with full command, PID, timestamp

### Steps
1. Create `internal/monitor/daemon.go` — daemon loop, process tree tracking
2. Create `internal/monitor/seccomp.go` — seccomp-bpf rules via `golang.org/x/sys/unix` (Linux only)
3. Create `internal/monitor/procwatch.go` — `/proc` polling fallback
4. Create `internal/cli/root_monitor.go` — `chainwatch root-monitor --pid <pid> --profile clawbot`
5. Integrate with profile package (CW05) for rule set
6. Grace period: allow `sudo` only if pre-approved via CW06 approval workflow

### Tests
- `sudo ls` blocked immediately
- `chmod 777 /etc/passwd` blocked
- `curl ... | sh` blocked
- Normal agent operations (read files, HTTP GET, write to workdir) unaffected
- Monitor survives agent crash/restart
- Trace captures all blocked attempts

### Acceptance
- `make go-test` passes with -race
- `chainwatch root-monitor --pid $$ --profile clawbot` starts and enforces
- Demo: agent attempts `sudo rm -rf /tmp/test` → blocked, logged, agent continues

---

## Non-Goals

- No ML or probabilistic safety models
- No LLM content analysis
- No "warn mode" that allows irreversible actions through
- No web UI (CLI only for v0.x)
- No multi-tenant or SaaS features
- No proprietary runtime hooks (insert at tool/network/output boundaries only)
