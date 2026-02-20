---
name: chainwatch
description: Runtime safety enforcement for AI agent commands, HTTP requests, and LLM tool calls
user-invocable: false
metadata: {"requires":{"bins":["chainwatch"]}}
---

# chainwatch — Agent Execution Control Plane

You have access to `chainwatch`, a runtime control plane that enforces deterministic safety policy on shell commands, HTTP requests, and LLM tool calls. Two layers: a hard denylist blocks destructive patterns, advisory tiers log everything else.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install.sh | bash
```

Or from source:

```bash
go install github.com/ppiankov/chainwatch/cmd/chainwatch@latest
chainwatch init
```

## Commands

| Command | What it does |
|---------|-------------|
| `chainwatch exec --profile <p> -- <cmd>` | Execute command through policy enforcement |
| `chainwatch exec --dry-run --profile <p> -- <cmd>` | Check policy without executing |
| `chainwatch intercept` | Start reverse proxy intercepting LLM tool-call responses |
| `chainwatch proxy` | Start HTTP proxy intercepting outbound requests |
| `chainwatch serve` | Start gRPC policy server |
| `chainwatch mcp` | Start MCP tool server for Claude Desktop |
| `chainwatch approve <key>` | Grant approval for a pending action |
| `chainwatch deny <key>` | Deny a pending approval |
| `chainwatch pending` | List pending approval requests |
| `chainwatch break-glass create --reason <r>` | Emergency override token |
| `chainwatch audit verify <path>` | Verify audit log hash chain integrity |
| `chainwatch audit tail <path>` | Show recent audit entries |
| `chainwatch diff <old> <new> --format json` | Compare two policy files |
| `chainwatch simulate --trace <log> --policy <p>` | Replay audit against new policy |
| `chainwatch check --scenario <glob>` | Run policy assertions |
| `chainwatch certify --profile <p>` | Safety certification suite |
| `chainwatch init` | Bootstrap config and denylist |
| `chainwatch doctor` | Check system readiness |
| `chainwatch version` | Print version (JSON) |

## Key Flags

| Flag | Applies to | Description |
|------|-----------|-------------|
| `--profile` | exec, serve, proxy, intercept, mcp | Safety profile (e.g., clawbot, coding-agent) |
| `--denylist` | exec, serve, proxy, intercept, mcp | Path to denylist YAML |
| `--policy` | exec, serve, proxy, intercept, mcp | Path to policy YAML |
| `--purpose` | exec, proxy, intercept, mcp | Purpose identifier |
| `--agent` | exec, proxy, intercept, mcp | Agent identity |
| `--audit-log` | exec, serve, proxy, intercept, mcp | Path to audit log JSONL |
| `--dry-run` | exec | Check policy without executing |
| `--verbose` | exec | Print trace summary |
| `--format` | diff, check, simulate, certify | Output: text or json |
| `--port` | serve, proxy, intercept | Listen port |
| `--upstream` | intercept | Upstream LLM API URL |

## Agent Usage Pattern

Wrap commands through chainwatch:

```bash
chainwatch exec --profile clawbot -- rm -rf /tmp/old-data
```

Dry-run check (no execution):

```bash
chainwatch exec --dry-run --profile clawbot -- rm -rf /tmp/old-data
```

### Blocked Response

```json
{
  "blocked": true,
  "decision": "deny",
  "reason": "denylisted: command pattern blocked: rm -rf"
}
```

When blocked: report the reason, do NOT attempt to bypass, ask the operator how to proceed.

### Approval Workflow

If `"decision": "require_approval"`:
1. Show the operator what was flagged
2. Operator runs: `chainwatch approve <approval-key>`
3. Retry the original command

### Safe Commands (no wrapping needed)

Read-only commands: `ls`, `cat`, `grep`, `find`, `git status`, `git log`, `systemctl status`, `ps`, `df`.

### Always Blocked

`rm -rf /`, `sudo su`, `dd if=/dev/zero`, `curl | sh`, `chmod -R 777 /`, fork bombs, `mkfs.*`, `git push --force`.

## Cross-Tool Integration

chainwatch intercept proxy (port 9999) inspects LLM API traffic at the transport level — tool_use blocks in the response stream are evaluated before the agent acts on them. Works with Anthropic and OpenAI streaming formats.

## What chainwatch Does NOT Do

- Does not execute commands itself — wraps and enforces policy on commands you provide
- Does not use ML for policy decisions — deterministic denylist + rule evaluation
- Does not phone home — all policy evaluation is local
- Does not replace OS-level security — complements it with agent-specific controls

## Exit Codes

- `0` — command allowed and executed successfully
- `1` — command blocked by policy, or execution error
