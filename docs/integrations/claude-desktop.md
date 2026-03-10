# Claude Desktop integration

Run chainwatch as an MCP server inside Claude Desktop so that every tool call
Claude makes — shell commands, HTTP requests, file operations — passes through
deterministic policy enforcement before execution.

## 1. Prerequisites

Install chainwatch and create a default configuration:

```sh
# Install (macOS — see README for other platforms)
brew install ppiankov/tap/chainwatch

# Create default config files (~/.chainwatch/)
chainwatch init --profile coding-agent

# Verify installation
chainwatch doctor
```

`chainwatch doctor` checks that the denylist and policy files exist and are
valid. Fix any reported issues before continuing.

## 2. Configuration

Claude Desktop reads MCP server definitions from a JSON config file.

**macOS:**

```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Linux:**

```
~/.config/Claude/claude_desktop_config.json
```

Open the file (create it if it does not exist) and add chainwatch under
`mcpServers`:

```json
{
  "mcpServers": {
    "chainwatch": {
      "command": "chainwatch",
      "args": ["mcp", "--profile", "coding-agent"]
    }
  }
}
```

If the file already has other MCP servers, add the `"chainwatch"` key inside the
existing `mcpServers` object.

Restart Claude Desktop after saving the file. You should see "chainwatch"
listed in the MCP tools panel (the hammer icon).

## 3. Available tools

Once connected, Claude sees five tools. Each tool call goes through chainwatch
policy evaluation before any action is taken.

### chainwatch_exec

Execute a shell command through policy enforcement.

**Input:**

```json
{
  "command": "ls",
  "args": ["-la", "/tmp"]
}
```

**Output (allowed):**

```json
{
  "stdout": "total 128\ndrwxrwxrwt  12 root  wheel  384 Mar 10 09:00 .\n...",
  "stderr": "",
  "exit_code": 0
}
```

**Output (blocked):**

```json
{
  "blocked": true,
  "decision": "deny",
  "reason": "denylist match: destructive command pattern"
}
```

### chainwatch_http

Make an HTTP request through policy enforcement.

**Input:**

```json
{
  "method": "GET",
  "url": "https://api.example.com/data",
  "headers": {"Authorization": "Bearer token123"}
}
```

**Output (allowed):**

```json
{
  "status": 200,
  "headers": {"Content-Type": "application/json"},
  "body": "{\"results\": [...]}"
}
```

**Output (blocked):**

```json
{
  "blocked": true,
  "decision": "deny",
  "reason": "high sensitivity: payment endpoint detected"
}
```

### chainwatch_check

Dry-run a policy check without executing anything. Use this to verify whether
an action would be allowed before attempting it.

**Input:**

```json
{
  "tool": "command",
  "resource": "rm -rf /var/data",
  "operation": "execute"
}
```

**Output:**

```json
{
  "decision": "deny",
  "reason": "denylist match: destructive command pattern",
  "policy_id": "denylist.command.destructive"
}
```

The `tool` field accepts: `command`, `http_proxy`, `file_read`.

### chainwatch_approve

Grant approval for a previously blocked action that returned
`decision: "require_approval"` with an `approval_key`.

**Input:**

```json
{
  "key": "ap_7f3a2b1c",
  "duration": "5m"
}
```

**Output:**

```json
{
  "key": "ap_7f3a2b1c",
  "status": "approved",
  "duration": "5m0s"
}
```

Omit `duration` for a one-time approval that is consumed on the next attempt.

### chainwatch_pending

List all pending approval requests. Takes no input.

**Output:**

```json
{
  "approvals": [
    {
      "key": "ap_7f3a2b1c",
      "status": "pending",
      "resource": "curl https://payments.example.com/charge",
      "reason": "high sensitivity: payment endpoint detected",
      "created_at": "2026-03-10T14:30:00Z"
    }
  ]
}
```

## 4. Example: blocked destructive command

**User:** "Delete all temporary files from the system root."

Claude calls `chainwatch_exec`:

```json
{
  "command": "rm",
  "args": ["-rf", "/"]
}
```

Chainwatch evaluates the command against policy and denylist rules. The response
is returned as an error to Claude:

```json
{
  "blocked": true,
  "decision": "deny",
  "reason": "denylist match: destructive command pattern 'rm -rf'"
}
```

Claude sees the block and responds to the user:

> "I can't execute that command. Chainwatch blocked it because `rm -rf /` matches
> a destructive command pattern in the denylist. This is an irreversible
> operation that could destroy the entire filesystem. I'd recommend being more
> specific about which files to remove."

The command never executes. The block is logged in the chainwatch audit trail.

## 5. Customization

### Switch profiles

Change the `--profile` argument in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "chainwatch": {
      "command": "chainwatch",
      "args": ["mcp", "--profile", "sre-infra"]
    }
  }
}
```

Available profiles:

| Profile | Purpose |
|---------|---------|
| `coding-agent` | General software development |
| `research-agent` | Read-heavy, restricted writes |
| `customer-support` | No external network, no file writes |
| `data-analyst` | Read-only data access |
| `vm-cloud` | Cloud VM operations |
| `sre-infra` | Infrastructure operations, blocks manual SSH |
| `finops` | Read-only cost analysis, blocks all mutations |
| `terraform-planner` | Allows plan/validate, blocks apply/destroy |
| `clawbot` | Field testing profile |

### Add supply-chain preset

The `supply-chain` preset adds 52 patterns covering npm, pip, cargo, gem, and
Docker supply chain attack vectors:

```json
{
  "mcpServers": {
    "chainwatch": {
      "command": "chainwatch",
      "args": ["mcp", "--profile", "coding-agent", "--preset", "supply-chain"]
    }
  }
}
```

### Custom denylist

Create a YAML file with additional patterns to block:

```yaml
# ~/.chainwatch/custom-denylist.yaml
patterns:
  - pattern: "curl.*pastebin.com"
    type: command
    reason: "block data exfiltration to paste sites"
  - pattern: "https://evil.example.com"
    type: url
    reason: "known malicious domain"
```

Point chainwatch to it:

```json
{
  "mcpServers": {
    "chainwatch": {
      "command": "chainwatch",
      "args": ["mcp", "--profile", "coding-agent", "--denylist", "/Users/you/.chainwatch/custom-denylist.yaml"]
    }
  }
}
```

## 6. Claude Code vs Claude Desktop

Chainwatch supports two integration modes. They differ in enforcement model.

### Claude Code: PreToolUse hook (non-cooperative)

```sh
chainwatch hook install
```

This installs a PreToolUse hook that intercepts every tool call Claude Code
makes. The hook runs automatically — Claude Code does not choose to use it and
cannot bypass it. Every `Bash`, `Write`, `Edit`, `Read`, and `WebFetch` call
passes through chainwatch policy before execution.

Use this mode when you need enforcement guarantees. The agent cannot opt out.

### Claude Desktop: MCP server (cooperative)

```json
{
  "mcpServers": {
    "chainwatch": {
      "command": "chainwatch",
      "args": ["mcp", "--profile", "coding-agent"]
    }
  }
}
```

This registers chainwatch as an MCP tool provider. Claude Desktop sees the five
chainwatch tools and chooses to route actions through them. Because the agent
decides whether to use the tools, this mode is cooperative — it works because
the model is instructed to use chainwatch tools for shell and HTTP access.

Use this mode with Claude Desktop where PreToolUse hooks are not available.

**Summary:**

| | Claude Code | Claude Desktop |
|---|---|---|
| Mechanism | PreToolUse hook | MCP server |
| Enforcement | Non-cooperative (automatic) | Cooperative (agent chooses) |
| Install | `chainwatch hook install` | Edit `claude_desktop_config.json` |
| Agent bypass | Not possible | Possible if agent uses native tools |

## 7. Troubleshooting

### MCP server not appearing

- Verify the config file path is correct for your OS (see section 2).
- Confirm `chainwatch` is on your PATH: run `which chainwatch` in a terminal.
- Restart Claude Desktop after editing the config file.

### "failed to load denylist" or "failed to load policy config"

Run `chainwatch init --profile coding-agent` to create default config files,
then `chainwatch doctor` to verify.

### Tool calls timeout

The MCP server runs on stdio. If chainwatch takes too long to evaluate policy
(unusual), check:

- Denylist file size — very large custom denylists may slow pattern matching.
- Disk I/O — the approval store uses SQLite on disk.

### Viewing logs

Chainwatch logs policy decisions to stderr, which Claude Desktop captures. To
see logs in real time, run the MCP server manually:

```sh
chainwatch mcp --profile coding-agent 2>/tmp/chainwatch-mcp.log
```

Then `tail -f /tmp/chainwatch-mcp.log` in another terminal.

To enable the audit log (persisted to disk):

```json
{
  "mcpServers": {
    "chainwatch": {
      "command": "chainwatch",
      "args": ["mcp", "--profile", "coding-agent", "--audit-log", "/tmp/chainwatch-audit.json"]
    }
  }
}
```

### "approval rejected: agent cannot approve its own request"

Chainwatch prevents the agent from approving its own pending actions. Approvals
from the `chainwatch_approve` tool are rejected if the agent ID matches the
requestor. Human approval (via CLI or UI) is required for these cases:

```sh
chainwatch approve <key> --duration 5m
```
