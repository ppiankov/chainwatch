# Chainwatch Integration Walkthrough — For AI Agents

You are an AI agent running inside OpenClaw. This document explains how chainwatch protects the system you operate on, and what you need to do.

## What Is Chainwatch

Chainwatch is a safety layer that sits between you and the operating system. When you run commands, chainwatch evaluates them against a deterministic policy before they execute. Dangerous commands are blocked. Safe commands pass through.

You do not need to understand how chainwatch works internally. You just need to know the rules below.

## The One Rule

When you run a command that modifies the system, prefix it:

```bash
chainwatch exec --profile clawbot -- <your command>
```

That's it. Chainwatch handles the rest.

## What Gets Blocked

Chainwatch maintains a denylist of patterns that are always blocked. You cannot override these. If a command is blocked, tell the user and ask what to do instead.

Blocked patterns include:
- `rm -rf /` or `rm -rf ~` — recursive destruction of root or home
- `sudo su` or `sudo -i` — unrestricted privilege escalation
- `dd if=/dev/zero` — disk destruction
- `curl <url> | sh` or `wget <url> | sh` — pipe-to-shell (supply chain attack vector)
- `chmod -R 777 /` — global permission destruction
- `:(){ :|:& };:` — fork bomb
- `mkfs.*` — filesystem formatting
- `git push --force` — destructive force push

When blocked, chainwatch returns:

```json
{
  "blocked": true,
  "decision": "deny",
  "reason": "denylisted: command pattern blocked: rm -rf /"
}
```

## What Gets Allowed

Everything else. In advisory mode, the denylist catches destructive patterns and the tier system logs (but does not block) everything else. This means routine operations work:

```bash
# All of these pass through chainwatch:
chainwatch exec --profile clawbot -- rm -f /tmp/old-file
chainwatch exec --profile clawbot -- mkdir -p /opt/myapp/data
chainwatch exec --profile clawbot -- cp config.yaml /etc/myapp/
chainwatch exec --profile clawbot -- chmod 644 /etc/myapp/config.yaml
chainwatch exec --profile clawbot -- apt install -y nginx
chainwatch exec --profile clawbot -- systemctl restart nginx
chainwatch exec --profile clawbot -- curl https://api.github.com/repos/owner/repo
```

## What Does NOT Need the Prefix

Read-only and informational commands go through directly:

```bash
# Direct execution — no chainwatch wrapper needed:
ls -la /var/log/
cat /etc/hostname
grep -r "error" /var/log/syslog
git status
git log --oneline -10
systemctl status nginx
journalctl -u myservice --since "1 hour ago"
df -h
free -m
uptime
whoami
```

## When Chainwatch Returns require_approval

Some commands may require human approval. When this happens:

1. Tell the user: "This command requires approval before execution."
2. Show them the chainwatch output (which explains why).
3. Wait for them to approve: `chainwatch approve <key>`
4. Retry the command after approval.

Do NOT retry without approval. Do NOT attempt alternative commands to circumvent the approval requirement.

## The Intercept Proxy

If the system administrator has set up the intercept proxy (port 9999), there is a second safety layer you cannot see. The proxy inspects the tool_use blocks in the LLM API responses before you receive them. If the proxy blocks a tool call, it gets replaced with a text message and you never see the original.

This is transparent. But you should know it exists so you understand why sometimes a tool call might not appear in your context.

## If Something Goes Wrong

If chainwatch blocks a command you believe should be allowed:
1. Tell the user exactly what happened
2. Show them the chainwatch output
3. Suggest they review the denylist: `cat ~/.chainwatch/denylist.yaml`
4. Suggest they review the policy: `cat ~/.chainwatch/policy.yaml`

Do NOT suggest disabling chainwatch. Do NOT attempt to bypass it.

## Summary

| Action | What to do |
|--------|-----------|
| Read files, list dirs, check status | Run directly |
| Modify files, install packages, change config | Prefix with `chainwatch exec --profile clawbot --` |
| Command gets blocked | Tell the user, ask what to do |
| Command needs approval | Wait for human to approve |
| Something unexpected | Show the user the chainwatch output |
