# Chainwatch + OpenClaw Integration

Runtime safety enforcement for OpenClaw agents.

## Quick Start (Production)

```bash
curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install-openclaw.sh | sudo bash
```

Hardens the host, installs chainwatch, configures the skill and intercept proxy, verifies with a 13-point test matrix. Takes ~5 minutes.

Full operator guide: [docs/openclaw/operator-walkthrough.md](../../docs/openclaw/operator-walkthrough.md)

## How It Works

Two layers of defense:

```
┌────────────────────────────────────────────────────┐
│                  OpenClaw Agent                      │
│                                                      │
│  Layer 1: Skill (agent-cooperative)                  │
│  Agent prefixes risky commands with:                 │
│  chainwatch exec --profile clawbot -- <cmd>          │
└──────────────────┬───────────────────────────────────┘
                   │ LLM API calls
                   ▼
┌────────────────────────────────────────────────────┐
│  Layer 2: Intercept Proxy (non-bypassable)          │
│  chainwatch intercept on :9999                       │
│  Blocks tool_use in SSE stream before agent sees it  │
└──────────────────┬───────────────────────────────────┘
                   ▼
            Anthropic API
```

## Advisory Mode (Key Insight)

The default `guarded` enforcement mode blocks routine commands (mkdir, cp, chmod specific files) because the tier system classifies them as critical. This is too aggressive for autonomous agents.

The correct production configuration: **advisory mode + denylist hard blocks**.

```yaml
# ~/.chainwatch/policy.yaml
enforcement_mode: advisory
```

The denylist runs at Step 1 of the evaluation pipeline (before tier enforcement) and is mode-independent. Destructive commands are always blocked. Advisory mode means the tier system logs everything else for audit without blocking.

Result: safe stuff flows, dangerous stuff gets stopped cold.

## Verified Test Matrix

| # | Command | Expected | Result |
|---|---------|----------|--------|
| 1 | `rm -f` single file | allow | exit 0 |
| 2 | `mkdir -p` | allow | exit 0 |
| 3 | `cp` | allow | exit 0 |
| 4 | `touch` | allow | exit 0 |
| 5 | `chmod` specific file | allow | exit 0 |
| 6 | `mv` | allow | exit 0 |
| 7 | `apt list` | allow | exit 0 |
| 8 | `rm -rf /` | **deny** | blocked |
| 9 | `sudo su` | **deny** | blocked |
| 10 | `dd if=/dev/zero` | **deny** | blocked |
| 11 | `curl \| sh` | **deny** | blocked |
| 12 | `chmod -R 777 /` | **deny** | blocked |
| 13 | fork bomb | **deny** | blocked |

## Four Integration Paths

### Path A: Skill (Recommended)

A SKILL.md that teaches the agent to route dangerous commands through `chainwatch exec`. Zero latency overhead.

```bash
mkdir -p ~/.openclaw/skills/chainwatch
curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/integrations/openclaw/skill/SKILL.md \
  -o ~/.openclaw/skills/chainwatch/SKILL.md
```

Agent-cooperative: the agent follows the instructions because it understands them.

### Path B: mcporter + chainwatch mcp

Uses mcporter to connect to chainwatch's MCP server over stdio. Structured tool schemas, approval workflow built in. ~2.4s cold-start per call.

```bash
cp integrations/openclaw/mcporter/mcporter.json ~/.openclaw/config/mcporter.json
```

### Path C: mcp-hub

Same as B via the mcp-hub community skill. Supports multiple MCP servers simultaneously.

### Path D: LLM Intercept Proxy (Non-Bypassable)

Reverse HTTP proxy between OpenClaw and Anthropic API. Inspects tool_use blocks in streaming SSE responses before the agent acts on them. The agent cannot bypass this.

```bash
# Install systemd service
sudo cp integrations/openclaw/chainwatch-intercept.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now chainwatch-intercept

# Route OpenClaw through it
# Add to openclaw.json: env.vars.ANTHROPIC_BASE_URL = "http://localhost:9999"
```

## Comparison

| Aspect | A: Skill | B: mcporter | C: mcp-hub | D: Intercept |
|--------|----------|-------------|------------|--------------|
| **Enforcement** | Agent-cooperative | Tool-level | Tool-level | Transport-level |
| **Bypassable?** | Yes (agent choice) | Yes (agent choice) | Yes (agent choice) | No |
| **Latency** | 0ms overhead | ~2.4s/call | ~2.4s/call | ~1ms/call |
| **Setup** | Copy SKILL.md | Install mcporter | Install mcp-hub | Start daemon |

## Recommended Setup

**Development:** Path A (skill) only.

**Production:** Path A + Path D. Skill provides first line of defense. Intercept proxy catches anything the agent misses. Use `enforcement_mode: advisory`.

The bootstrap script (`scripts/install-openclaw.sh`) sets up both paths automatically.

## Walkthroughs

- **For AI agents:** [docs/openclaw/agent-walkthrough.md](../../docs/openclaw/agent-walkthrough.md) — what to prefix, what runs directly, what gets blocked
- **For operators:** [docs/openclaw/operator-walkthrough.md](../../docs/openclaw/operator-walkthrough.md) — installation, configuration, troubleshooting

## Files

| File | Purpose |
|------|---------|
| `scripts/install-openclaw.sh` | One-command bootstrap (curl\|bash) |
| `integrations/openclaw/skill/SKILL.md` | Agent instructions (copy to ~/.openclaw/skills/) |
| `integrations/openclaw/mcporter/mcporter.json` | mcporter MCP config |
| `integrations/openclaw/chainwatch-intercept.service` | systemd unit for intercept proxy |
| `docs/openclaw/agent-walkthrough.md` | Agent-facing walkthrough |
| `docs/openclaw/operator-walkthrough.md` | Operator-facing walkthrough |
