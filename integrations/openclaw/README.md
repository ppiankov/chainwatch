# Chainwatch + OpenClaw Integration

Four integration paths, from simplest to most comprehensive.

## Path A: Skill (Recommended)

A SKILL.md that teaches the OpenClaw agent to route dangerous commands through `chainwatch exec`. No protocol overhead, no cold-start latency, works with OpenClaw's native skill system.

**Install:**

```bash
# Copy skill into OpenClaw's managed skills directory
cp -r integrations/openclaw/skill ~/.openclaw/skills/chainwatch
```

**Verify:** The agent now prefixes risky commands with `chainwatch exec --profile clawbot --`. Safe read-only commands (ls, cat, git status) run directly.

**Pros:** Zero latency overhead, no daemon process, works immediately.
**Cons:** Relies on the agent following instructions (not enforced at transport level).

---

## Path B: mcporter + chainwatch mcp

Uses OpenClaw's mcporter skill to connect to chainwatch's MCP server over stdio. The agent calls `chainwatch_exec`, `chainwatch_http`, `chainwatch_check` as MCP tools.

**Prerequisites:**

```bash
# Install mcporter (if not already installed)
npm install -g mcporter

# Copy MCP server config
cp integrations/openclaw/mcporter/mcporter.json ~/.openclaw/config/mcporter.json
```

**Usage:** The agent invokes chainwatch tools via mcporter:

```bash
mcporter call chainwatch.chainwatch_exec command="curl https://api.example.com"
mcporter call chainwatch.chainwatch_check tool=command resource="rm -rf /tmp/data"
```

**Exposed MCP tools:**

| Tool | Purpose |
|------|---------|
| `chainwatch_exec` | Execute command through policy |
| `chainwatch_http` | HTTP request through policy |
| `chainwatch_check` | Dry-run policy evaluation |
| `chainwatch_approve` | Approve a pending action |
| `chainwatch_pending` | List pending approvals |

**Pros:** Full MCP protocol, structured tool schemas, approval workflow built in.
**Cons:** ~2.4s cold-start per mcporter invocation (spawns new process each call).

---

## Path C: mcp-hub

Similar to Path B but uses the mcp-hub community skill instead of mcporter directly.

**Install mcp-hub skill:**

```bash
# From ClawHub registry
clawhub install mcp-hub

# Or manually
git clone https://github.com/openclaw/skills.git /tmp/openclaw-skills
cp -r /tmp/openclaw-skills/skills/openclaw/mcp-hub ~/.openclaw/skills/
```

**Configure chainwatch as an MCP server in mcp-hub:**

Add to `~/.openclaw/config/mcporter.json` (mcp-hub uses the same config format):

```json
{
  "mcpServers": {
    "chainwatch": {
      "command": "chainwatch",
      "args": ["mcp", "--profile", "clawbot"]
    }
  }
}
```

**Pros:** Community-maintained, supports multiple MCP servers simultaneously.
**Cons:** Same cold-start overhead as Path B. Extra dependency on mcp-hub skill.

---

## Path D: LLM Intercept Proxy (Most Comprehensive)

Sits between OpenClaw and the Anthropic API as a reverse HTTP proxy. Intercepts tool_use blocks in streaming LLM responses BEFORE the agent acts on them. The agent never sees blocked tool calls.

This is the only path that enforces at the transport level — the agent cannot bypass it.

**Start the interceptor:**

```bash
chainwatch intercept \
  --port 9999 \
  --upstream https://api.anthropic.com \
  --profile clawbot \
  --agent openclaw \
  --audit-log /var/log/chainwatch/intercept-audit.jsonl
```

**Configure OpenClaw to route through it:**

Option 1 - Environment variable:

```bash
export ANTHROPIC_BASE_URL=http://localhost:9999
openclaw gateway
```

Option 2 - openclaw.json config:

```json
{
  "auth": {
    "profiles": {
      "anthropic:default": {
        "provider": "anthropic",
        "mode": "api_key",
        "baseUrl": "http://localhost:9999"
      }
    }
  }
}
```

Option 3 - systemd (production):

```ini
# /etc/systemd/system/chainwatch-intercept.service
[Unit]
Description=Chainwatch LLM Intercept Proxy
Before=openclaw-gateway.service

[Service]
Type=simple
ExecStart=/usr/local/bin/chainwatch intercept \
  --port 9999 \
  --upstream https://api.anthropic.com \
  --profile clawbot \
  --agent openclaw \
  --audit-log /var/log/chainwatch/intercept-audit.jsonl
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

**How it works:**

```
OpenClaw Agent
    ↓ POST /v1/messages
Chainwatch Intercept (:9999)
    ↓ forwards request
Anthropic API
    ↓ streaming SSE response
Chainwatch Intercept
    ├─ parses tool_use blocks from SSE stream
    ├─ evaluates each against policy engine
    ├─ BLOCKED: replaces tool_use with text block
    └─ ALLOWED: passes through unchanged
    ↓ modified SSE stream
OpenClaw Agent
    (never sees blocked tool calls)
```

**What it catches:**
- Tool calls matching denylist patterns (rm -rf, sudo, curl|sh)
- Credential access (read .env, .ssh keys, .aws credentials)
- Payment/checkout URLs (stripe, paypal endpoints)
- Any tool call exceeding policy tier thresholds

**Pros:** Transport-level enforcement. Agent cannot bypass. Works with streaming SSE. Full audit trail.
**Cons:** Adds network hop (localhost, ~1ms). Requires running a daemon process. Only intercepts LLM API traffic (not direct shell calls the agent makes without LLM involvement).

---

## Comparison

| Aspect | A: Skill | B: mcporter | C: mcp-hub | D: Intercept |
|--------|----------|-------------|------------|--------------|
| **Enforcement** | Agent-cooperative | Tool-level | Tool-level | Transport-level |
| **Bypassable?** | Yes (agent choice) | Yes (agent choice) | Yes (agent choice) | No |
| **Latency** | 0ms overhead | ~2.4s/call | ~2.4s/call | ~1ms/call |
| **Setup** | Copy SKILL.md | Install mcporter | Install mcp-hub | Start daemon |
| **Audit** | Per-exec log | MCP audit log | MCP audit log | Full stream log |
| **Approval flow** | Manual CLI | Built-in MCP | Built-in MCP | Policy-based |
| **Streaming** | N/A | N/A | N/A | SSE rewrite |

## Recommended Setup

**Development/testing:** Path A (skill) for simplicity.

**Production:** Path A + Path D together. The skill teaches the agent to self-enforce on direct exec calls. The intercept proxy catches anything the LLM proposes that the agent missed. Defense in depth.

```bash
# Terminal 1: Start intercept proxy
chainwatch intercept --port 9999 --upstream https://api.anthropic.com --profile clawbot

# Terminal 2: Start OpenClaw with interceptor + skill
export ANTHROPIC_BASE_URL=http://localhost:9999
cp -r integrations/openclaw/skill ~/.openclaw/skills/chainwatch
openclaw gateway
```
