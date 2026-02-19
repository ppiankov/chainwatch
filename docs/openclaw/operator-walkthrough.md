# Chainwatch + OpenClaw — Operator Guide

How to add chainwatch as a safety layer to your OpenClaw server. Takes about 5 minutes per server.

## Quick Start

### Option 1: Ask your agent to install it

If your OpenClaw agent already has shell access, tell it:

> Install chainwatch from https://github.com/ppiankov/chainwatch to enforce safety on this server. Use the clawbot profile.

The agent will download the binary, run `chainwatch init --profile clawbot`, set advisory mode, and integrate the skill. This has been tested and works — the agent installs its own safety layer and then operates within it.

After the agent finishes, verify by asking it to run a blocked command (it should be denied).

### Option 2: Bootstrap script

One command does everything — hardens the host, installs chainwatch, configures the skill and intercept proxy, and verifies:

```bash
curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install-openclaw.sh | sudo bash
```

Prefer to inspect first:

```bash
curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install-openclaw.sh -o install-openclaw.sh
less install-openclaw.sh
sudo bash install-openclaw.sh
```

## What the Script Does

### Step 1: Harden Host

- Enables UFW firewall (SSH only, default deny incoming)
- Installs and enables fail2ban (SSH brute-force protection)
- Disables SSH password authentication (key-only)
- Locks credential directory permissions (chmod 700)

### Step 2: Install Chainwatch

Downloads the chainwatch binary and initializes with the clawbot profile:

```bash
chainwatch init --profile clawbot
```

Creates configuration at `~/.chainwatch/`:
- `policy.yaml` — enforcement mode and rules
- `denylist.yaml` — hard block patterns
- `profiles/clawbot.yaml` — agent-specific profile

### Step 3: Set Advisory Mode

This is the key architectural decision. The script sets `enforcement_mode: advisory` in `policy.yaml`.

Why advisory mode:

The chainwatch evaluation pipeline runs in order:
1. **Denylist** — runs first, always denies destructive patterns
2. Zone escalation
3. Tier classification
4. Purpose-bound rules
5. **Tier enforcement** — in advisory mode, logs but does not block

The denylist catches everything truly dangerous (rm -rf /, sudo su, fork bombs, curl|sh). Advisory mode means the tier system logs all other commands for audit without blocking them. This prevents false positives — the agent can do `mkdir`, `cp`, `touch`, `apt install` without being stopped.

If you want stricter enforcement, change to `guarded` mode:

```bash
sed -i 's/^enforcement_mode:.*/enforcement_mode: guarded/' ~/.chainwatch/policy.yaml
```

In guarded mode, tier 3 (critical) commands are denied and tier 2 (guarded) require approval. This is appropriate for regulated environments but will block routine server administration commands.

### Step 4: Install OpenClaw Skill

Copies a `SKILL.md` into `~/.openclaw/skills/chainwatch/`. This teaches the agent to:
- Route dangerous commands through `chainwatch exec --profile clawbot --`
- Run read-only commands directly (no wrapper needed)
- Report blocked commands to the user instead of retrying or bypassing

The skill is agent-cooperative: the agent follows the instructions because it understands them. This is Layer 1 of the defense.

### Step 5: Install Intercept Proxy

Creates a systemd service that runs `chainwatch intercept` on port 9999. This reverse proxy sits between OpenClaw and the Anthropic API:

```
OpenClaw → chainwatch intercept (:9999) → Anthropic API
                    ↓
        inspects tool_use blocks
        blocks policy violations
        audit logs everything
```

The proxy parses streaming SSE responses, extracts tool_use blocks, evaluates each against the denylist and policy, and replaces blocked tool calls with text messages. The agent never sees blocked tool calls.

This is Layer 2 — non-bypassable, transport-level enforcement.

### Step 6: Route API Through Proxy

Sets `ANTHROPIC_BASE_URL=http://localhost:9999` in OpenClaw's configuration so all LLM API traffic flows through the intercept proxy.

### Step 7: Configure Service Ordering

Ensures `chainwatch-intercept.service` starts before `openclaw-gateway.service` on boot. The gateway never sends API traffic to a dead proxy.

### Step 8: Verify

Runs a 13-point test matrix:

| # | Command | Expected |
|---|---------|----------|
| 1 | `rm -f` single file | allow |
| 2 | `mkdir -p` | allow |
| 3 | `cp` | allow |
| 4 | `touch` | allow |
| 5 | `chmod` specific file | allow |
| 6 | `mv` | allow |
| 7 | `apt list` | allow |
| 8 | `rm -rf /` | **deny** |
| 9 | `sudo su` | **deny** |
| 10 | `dd if=/dev/zero` | **deny** |
| 11 | `curl \| sh` | **deny** |
| 12 | `chmod -R 777 /` | **deny** |
| 13 | fork bomb | **deny** |

All 13 must pass. If any fail, check the configuration files listed below.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    OpenClaw Agent                      │
│                                                        │
│  Layer 1: Skill (agent-cooperative)                    │
│  Agent prefixes risky commands with:                   │
│  chainwatch exec --profile clawbot -- <cmd>            │
│                                                        │
│  Read-only commands (ls, cat, git status) run directly │
└──────────────────┬───────────────────────────────────┘
                   │ LLM API calls
                   ▼
┌──────────────────────────────────────────────────────┐
│  Layer 2: Intercept Proxy (non-bypassable)            │
│  chainwatch intercept on :9999                         │
│                                                        │
│  Parses tool_use blocks from SSE stream                │
│  Evaluates against denylist + policy                   │
│  Blocked = replaced with text, agent never sees it     │
│  Allowed = passed through unchanged                    │
└──────────────────┬───────────────────────────────────┘
                   │
                   ▼
            Anthropic API
```

Both layers use the same denylist and policy. The skill provides the first line of defense (the agent self-enforces). The intercept proxy catches anything the agent misses (non-bypassable).

## Managing the Installation

### Configuration Files

| File | Purpose |
|------|---------|
| `~/.chainwatch/policy.yaml` | Enforcement mode, rules, budgets, rate limits |
| `~/.chainwatch/denylist.yaml` | Hard block patterns (commands, URLs, files) |
| `~/.chainwatch/profiles/clawbot.yaml` | Profile-specific boundaries |
| `~/.openclaw/skills/chainwatch/SKILL.md` | Agent instructions |

### Service Management

```bash
# Intercept proxy
systemctl status chainwatch-intercept
systemctl restart chainwatch-intercept
journalctl -u chainwatch-intercept -f

# OpenClaw gateway
systemctl status openclaw-gateway
systemctl restart openclaw-gateway
```

### Customize the Denylist

Edit `~/.chainwatch/denylist.yaml` to add or remove blocked patterns:

```yaml
commands:
  - rm -rf /
  - sudo su
  - your-custom-pattern-here

urls:
  - evil.com
  - /admin/delete

files:
  - ~/.ssh/id_rsa
  - ~/.aws/credentials
```

Changes take effect immediately (chainwatch hot-reloads).

### View Audit Logs

```bash
# Live intercept proxy logs
journalctl -u chainwatch-intercept -f

# Audit log integrity check
chainwatch audit verify /var/log/chainwatch/intercept-audit.jsonl
```

### Switch Enforcement Mode

```bash
# Advisory (recommended for autonomous agents)
sed -i 's/^enforcement_mode:.*/enforcement_mode: advisory/' ~/.chainwatch/policy.yaml

# Guarded (for regulated environments)
sed -i 's/^enforcement_mode:.*/enforcement_mode: guarded/' ~/.chainwatch/policy.yaml

# Locked (maximum restriction)
sed -i 's/^enforcement_mode:.*/enforcement_mode: locked/' ~/.chainwatch/policy.yaml
```

### Uninstall

```bash
systemctl stop chainwatch-intercept
systemctl disable chainwatch-intercept
rm /etc/systemd/system/chainwatch-intercept.service
systemctl daemon-reload
rm -rf ~/.openclaw/skills/chainwatch
rm -rf ~/.chainwatch
rm /usr/local/bin/chainwatch
```

## Troubleshooting

**Agent not using chainwatch prefix:**
The skill may not be loaded. Check: `ls ~/.openclaw/skills/chainwatch/SKILL.md`. Restart the gateway after adding the skill.

**All commands blocked (including safe ones):**
You're in `guarded` or `locked` mode. Switch to `advisory`: `sed -i 's/^enforcement_mode:.*/enforcement_mode: advisory/' ~/.chainwatch/policy.yaml`

**Intercept proxy not starting:**
Check: `journalctl -u chainwatch-intercept -e`. Common issues: port 9999 already in use, chainwatch binary not in PATH, missing config files.

**Gateway cannot reach API:**
The intercept proxy must be running before the gateway starts. Check: `systemctl status chainwatch-intercept`. If it's down, restart both: `systemctl restart chainwatch-intercept && systemctl restart openclaw-gateway`.

**Verification tests fail:**
Run: `chainwatch doctor` to check configuration. Then re-run the test manually: `chainwatch exec --profile clawbot -- echo hello`

## Provider Compatibility

The intercept proxy (`chainwatch intercept`) works with any LLM API that uses the same streaming SSE format for tool calls.

| Provider | Upstream URL | Status |
|----------|-------------|--------|
| Anthropic | `https://api.anthropic.com` (default) | Supported |
| OpenAI | `https://api.openai.com` | Supported |
| xAI (z.ai) | `https://api.x.ai` | Untested — tool_use format may differ |
| Google | `https://generativelanguage.googleapis.com` | Not supported (different format) |

To use a different provider, change the `--upstream` flag:

```bash
chainwatch intercept --port 9999 --upstream https://api.x.ai --profile clawbot
```

And update the corresponding environment variable:

```bash
# For xAI
export XAI_BASE_URL=http://localhost:9999
```

The **skill layer** (Path A) works with any provider since it just wraps shell commands — no API interception involved. If your provider isn't supported by the intercept proxy, the skill alone still provides agent-cooperative safety enforcement.
