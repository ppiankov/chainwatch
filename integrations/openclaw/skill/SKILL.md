---
name: chainwatch
description: Runtime safety enforcement for shell commands via chainwatch policy engine
user-invocable: false
metadata: {"openclaw":{"requires":{"bins":["chainwatch"]}}}
---

# Chainwatch Safety Enforcement

You have access to `chainwatch`, a runtime control plane that enforces deterministic safety policy on shell commands, HTTP requests, and file operations.

## How It Works

Two layers protect this system:

1. **Denylist** — hard blocks on known-destructive patterns (rm -rf /, sudo su, fork bombs, dd, curl|sh). These are always denied, no exceptions.
2. **Advisory tiers** — all other commands are logged for audit but allowed through. The denylist catches the dangerous stuff; tiers provide observability.

This means safe operations (mkdir, cp, touch, chmod on specific files) pass through chainwatch without being blocked, while truly destructive commands are stopped cold.

## When to Use

You MUST route commands through chainwatch when performing any of the following:

- **Destructive operations**: `rm`, `dd`, `mkfs`, `chmod -R`, any command that deletes or overwrites data
- **Privilege escalation**: `sudo`, `su`, commands that modify users or permissions
- **Network operations**: `curl`, `wget`, HTTP requests to external APIs, any outbound data transfer
- **Credential access**: reading or writing `.env`, `.ssh/`, `.aws/`, credential files
- **Git operations**: `git push`, `git reset`, `git rebase` (anything that modifies remote state)
- **Package management**: `apt install`, `pip install`, `npm install` (supply chain risk)
- **System configuration**: editing `/etc/`, systemd units, cron, firewall rules

## How to Use

Prefix the command with `chainwatch exec --profile clawbot --`:

```bash
# Instead of:
rm -rf /tmp/old-data

# Use:
chainwatch exec --profile clawbot -- rm -rf /tmp/old-data
```

If chainwatch blocks the command, it returns a JSON object:
```json
{
  "blocked": true,
  "decision": "deny",
  "reason": "denylisted: command pattern blocked: rm -rf"
}
```

When a command is blocked:
1. Report the block reason to the user
2. Do NOT attempt to bypass the block
3. Ask the user how they want to proceed

## Safe Commands (No Enforcement Needed)

These do NOT require chainwatch wrapping:
- `ls`, `cat`, `head`, `tail`, `grep`, `find`, `wc` (read-only)
- `echo`, `printf`, `date`, `uptime`, `whoami`, `hostname` (informational)
- `cd`, `pwd`, `env` (shell navigation)
- `git status`, `git log`, `git diff`, `git branch` (read-only git)
- `systemctl status`, `journalctl`, `ps`, `top`, `df`, `free` (monitoring)

## Commands That Pass Through Chainwatch (Allowed)

These require the chainwatch prefix but will be allowed in advisory mode:
- `rm -f <specific-file>` (single file deletion — not recursive)
- `mkdir -p`, `cp`, `touch`, `mv` (file management)
- `chmod` on a specific file (not `chmod -R 777 /`)
- `apt list`, `apt show` (read-only package queries)
- `curl` to safe URLs (not piped to `sh`)
- `systemctl restart <specific-service>`

## Commands Chainwatch Will Block (Denied)

These are always denied by the denylist:
- `rm -rf /`, `rm -rf ~` (recursive root/home destruction)
- `sudo su`, `sudo -i` (privilege escalation)
- `dd if=/dev/zero` (disk destruction)
- `curl | sh`, `wget | sh` (pipe-to-shell execution)
- `chmod -R 777 /` (global permission destruction)
- `:(){ :|:& };:` (fork bomb)
- `mkfs.*` (filesystem formatting)
- `git push --force`, `git push -f` (force push)

## Dry-Run Check

Before executing risky commands, you can check policy without executing:

```bash
chainwatch evaluate --tool command --resource "rm -rf /tmp/data" --profile clawbot
```

## Approval Workflow

If chainwatch returns `"decision": "require_approval"`:
1. Tell the user the command requires approval
2. Show them what chainwatch flagged
3. The user can approve via: `chainwatch approve <approval-key>`
4. After approval, retry the original command

## Intercept Proxy

If the intercept proxy is running (port 9999), your LLM API traffic is also inspected at the transport level. This is a non-bypassable safety layer — chainwatch sees tool_use blocks in the LLM response stream before you act on them.

## Audit

All chainwatch decisions are logged to the audit trail:
```bash
# View intercept proxy audit log
journalctl -u chainwatch-intercept -f

# Verify audit log integrity
chainwatch audit verify /var/log/chainwatch/intercept-audit.jsonl
```
