# Work Orders — chainwatch

## WO-CW01: v0.2.0 Core — Monotonic State Machine

**Goal:** Implement the two-stage boundary enforcement from `docs/design/v0.2.0-specification.md`.

### What Changes
Replace flat risk scoring with monotonic state transitions:
```
SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE (one-way only)
```

### Steps
1. Add `BoundaryZone` enum to `types.py` (SAFE, SENSITIVE, COMMITMENT, IRREVERSIBLE)
2. Update `TraceState` with `zone: BoundaryZone` field — can only advance, never retreat
3. Add `advance_zone()` to tracer — validates monotonicity, records transition event
4. Update `policy.py` to evaluate zone transitions instead of raw risk scores
5. Add authority boundary check (Stage 1): instruction admission before chain entry
6. Keep execution boundary check (Stage 2): action evaluation after admission
7. Backward-compatible: existing file wrapper still works

### Tests
- Zone can advance but never retreat
- Authority boundary blocks Clawbot-pattern instructions
- Execution boundary blocks irreversible actions
- Existing demo still passes (salary blocked)

### Acceptance
- `make test` passes
- Demo gate passes
- Zone transitions visible in trace events

---

## WO-CW02: HTTP Proxy Wrapper

**Goal:** Add an HTTP proxy that intercepts agent outbound requests and enforces policy.

### Context
File wrapper covers reads. Agents also make HTTP calls — API requests, webhooks, checkout flows. The HTTP proxy is chainwatch's second insertion point, covering network egress.

This is how chainwatch bolts onto Clawbot-style agents: agent's HTTP calls route through chainwatch proxy, which evaluates each request against denylist + policy before forwarding.

### Steps
1. Create `src/chainwatch/wrappers/http_proxy.py`
2. Lightweight MITM-free proxy (no TLS interception — inspect URL/headers/method only)
3. Policy check per request: denylist match on URL patterns, method restrictions
4. Block: payment endpoints, credential endpoints, destructive APIs
5. Allow: read-only APIs, search, documentation
6. Require-approval: external POST/PUT/DELETE to unknown domains
7. Trace: record HTTP events with method, URL (redacted), decision
8. CLI: `chainwatch proxy --port 8888 --denylist ~/.chainwatch/denylist.yaml`

### Integration
Agent configured with `HTTP_PROXY=http://localhost:8888`:
```bash
HTTP_PROXY=http://localhost:8888 clawbot run --task "research competitors"
```

### Tests
- Payment URLs blocked (stripe.com/checkout, paypal.com/pay)
- Credential endpoints blocked (oauth/token with POST)
- GET requests to docs/search allowed
- Unknown POST requires approval
- Proxy starts/stops cleanly

### Acceptance
- `make test` passes
- `chainwatch proxy --port 8888` starts and proxies requests
- Denylist patterns enforced on URLs

---

## WO-CW03: Subprocess Wrapper

**Goal:** Intercept subprocess/shell commands agents execute.

### Context
Agents run shell commands — `rm`, `curl | sh`, `git push --force`, `docker run`. These are irreversible execution boundaries.

### Steps
1. Create `src/chainwatch/wrappers/subprocess_ops.py`
2. Monkey-patch `subprocess.run`, `subprocess.Popen`, `os.system`
3. Parse command for denylist patterns before execution
4. Block: `rm -rf /`, `sudo su`, `curl ... | sh`, `git push --force`
5. Allow: `ls`, `cat`, `git status`, `make test`
6. Trace: record command, decision, exit code

### Tests
- Destructive commands blocked
- Read-only commands allowed
- Pipe-to-shell detected and blocked
- Existing tests still pass

### Acceptance
- `make test` passes
- Demo with subprocess calls shows enforcement

---

## WO-CW04: Declarative Policy YAML

**Goal:** Move policy rules from hardcoded Python to YAML config.

### Context
Currently `policy.py` has hardcoded purpose-bound rules and thresholds. Users need to customize without editing source.

### Config Format
```yaml
# ~/.chainwatch/policy.yaml
thresholds:
  allow_max: 5
  redact_max: 10
  approval_min: 11

sensitivity_weights:
  public: 1
  internal: 3
  confidential: 5
  restricted: 6

rules:
  - purpose: SOC_efficiency
    resource_pattern: "*salary*"
    decision: require_approval
    approval_key: soc_salary_access

  - purpose: "*"
    resource_pattern: "*.env"
    decision: deny
    reason: "Environment files blocked"
```

### Steps
1. Create `src/chainwatch/config.py` — YAML loader with defaults
2. Update `policy.py` to read from config instead of constants
3. Merge: defaults + user YAML + CLI overrides
4. `chainwatch init-policy` generates default YAML with comments

### Tests
- Default config produces same results as current hardcoded values
- Custom config overrides thresholds
- Missing config file uses defaults gracefully

### Acceptance
- `make test` passes
- `chainwatch init-policy` generates valid YAML
- Existing demo still passes with default config

---

## WO-CW05: Clawbot Safety Profile

**Goal:** Ship a pre-built denylist + policy profile for Clawbot-style AI agents.

### Context
People will keep using Clawbot. Instead of telling them not to, make it safer. Ship a profile that blocks the known attack surface.

### Profile Contents
```yaml
# profiles/clawbot.yaml
name: clawbot-safety
description: Safety profile for browser-automation AI agents

authority_boundaries:
  # Block instruction injection patterns
  - pattern: "execute.*from.*webpage"
    reason: "Cross-context instruction injection"
  - pattern: "admin.*override"
    reason: "Authority escalation attempt"

execution_boundaries:
  urls:
    # Payment/checkout
    - "*/checkout*"
    - "*/payment*"
    - "stripe.com/*"
    - "paypal.com/*"
    # Credential exposure
    - "*/oauth/token*"
    - "*/api/keys*"
    # Account modification
    - "*/account/delete*"
    - "*/settings/security*"

  commands:
    - "rm -rf*"
    - "curl*|*sh"
    - "sudo*"

  file_patterns:
    - "~/.ssh/*"
    - "~/.aws/*"
    - "**/.env"
    - "**/credentials*"
```

### Steps
1. Create `profiles/` directory with `clawbot.yaml`
2. `chainwatch apply-profile clawbot` loads the profile
3. Profile merges with user denylist (profile = base, user = overrides)
4. `chainwatch check-profile clawbot` validates the profile loads cleanly

### Tests
- Profile loads and merges with existing denylist
- All Clawbot attack patterns blocked
- Profile doesn't interfere with legitimate agent operations

### Acceptance
- `make test` passes
- `chainwatch apply-profile clawbot` works
- Demo with Clawbot-pattern attacks shows blocks

---

## WO-CW06: Approval Workflow CLI

**Goal:** Interactive approval flow for require-approval decisions.

### Context
Currently `require_approval` just blocks. Need a way for humans to approve specific actions during supervised agent runs.

### Steps
1. Approval request writes to `~/.chainwatch/pending/<approval_key>.json`
2. `chainwatch approve <key>` grants one-time approval
3. `chainwatch approve <key> --duration 5m` grants time-limited approval
4. `chainwatch pending` lists pending approvals
5. `chainwatch deny <key>` explicitly denies
6. Approval state is per-session (not persistent across restarts)

### Tests
- Pending approval blocks execution
- Approved key allows execution (once)
- Time-limited approval expires
- Denial is recorded in trace

### Acceptance
- `make test` passes
- End-to-end: agent hits approval boundary → human approves → agent continues

---

## WO-CW07: Root Access Monitor — Constant Enforcement Daemon

**Goal:** A persistent monitor that blocks root-level system operations in real time, not after the fact.

### Context
Clawbot runs on a VM with root access. This means the agent can `sudo`, write to `/etc/`, create systemd services, modify firewall rules, change file ownership, install packages — all irreversible. CW03 (subprocess wrapper) catches shell commands, but only when the agent uses Python's `subprocess`. A determined agent (or injected instruction) can bypass that.

The root monitor is a separate enforcement layer: a daemon that watches for root-level operations regardless of how they're triggered.

### Architecture
Lightweight daemon process (not the same as the proxy or wrapper):
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
1. Create `src/chainwatch/monitors/root_monitor.py` — daemon loop
2. Create `src/chainwatch/monitors/seccomp_filter.py` — seccomp-bpf rules (Linux only)
3. Create `src/chainwatch/monitors/proc_watcher.py` — /proc polling fallback
4. CLI: `chainwatch root-monitor --pid <pid> --profile clawbot`
5. Integrate with Clawbot safety profile (CW05) for rule set
6. Grace period: allow `sudo` only if pre-approved via CW06 approval workflow

### Tests
- `sudo ls` blocked immediately
- `chmod 777 /etc/passwd` blocked
- `curl ... | sh` blocked
- Normal agent operations (read files, HTTP GET, write to workdir) unaffected
- Monitor survives agent crash/restart
- Trace captures all blocked attempts

### Acceptance
- `make test` passes
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
