# Getting Started with Chainwatch

This guide walks you from zero to a working chainwatch setup in under five minutes.

## Prerequisites

- **Go 1.25+** (for building from source) or download a prebuilt binary
- **macOS, Linux, or WSL** (Windows native is not supported)

## Installation

### Option 1: Quick Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/ppiankov/chainwatch/main/scripts/install.sh | bash
```

Downloads the binary, runs `chainwatch init`, and verifies with `chainwatch doctor`.

### Option 2: Go Install

```bash
go install github.com/ppiankov/chainwatch/cmd/chainwatch@latest
chainwatch init
```

### Option 3: GitHub Release

```bash
# Linux (amd64)
curl -sL https://github.com/ppiankov/chainwatch/releases/latest/download/chainwatch-linux-amd64 -o chainwatch
chmod +x chainwatch && sudo mv chainwatch /usr/local/bin/

# macOS (Apple Silicon)
curl -sL https://github.com/ppiankov/chainwatch/releases/latest/download/chainwatch-darwin-arm64 -o chainwatch
chmod +x chainwatch && sudo mv chainwatch /usr/local/bin/
```

Then bootstrap:

```bash
chainwatch init
```

## First Run

Initialize with a profile. Profiles configure enforcement rules for specific agent types.

```bash
chainwatch init --profile coding-agent
```

This creates `~/.chainwatch/` with:
- `policy.yaml` -- enforcement rules and thresholds
- `denylist.yaml` -- hard-blocked patterns (commands, URLs, files)
- `profiles/` -- profile configurations

## Verify Your Setup

```bash
chainwatch doctor
```

Doctor checks that configuration files exist, policy parses correctly, and the denylist loads without errors.

## Try It

### Wrap a safe command

```bash
chainwatch exec -- echo "hello world"
```

This runs through the policy engine and is allowed -- no dangerous patterns matched.

### Wrap a dangerous command

```bash
chainwatch exec -- rm -rf /
# Decision: deny | Reason: Denylisted: command matches pattern: rm -rf
```

The command is blocked before execution. The denylist matched `rm -rf` and returned a hard deny.

### Check policy without executing

```bash
chainwatch exec --dry-run --profile coding-agent -- curl https://api.example.com/data
```

The `--dry-run` flag evaluates policy and prints the decision without executing the command.

## Add Supply Chain Protection

The `supply-chain` preset adds 52 patterns that block common supply chain attack vectors: `npm publish`, `pip --index-url` from untrusted sources, `cargo publish`, `docker push`, credential file access, and more.

```bash
chainwatch init --preset supply-chain
```

Combine with a profile:

```bash
chainwatch init --profile coding-agent --preset supply-chain
```

## Integrate with Claude Code

Install chainwatch as a native PreToolUse hook. Every tool call (Bash, Write, Edit, WebFetch, MCP tools) is evaluated against policy before execution.

```bash
chainwatch hook install --profile coding-agent
```

With supply chain protection:

```bash
chainwatch hook install --profile coding-agent --preset supply-chain
```

This writes a hook to `.claude/settings.local.json` (project-scoped, gitignored). The agent cannot bypass enforcement -- blocked tool calls never execute.

## Test Your Policy

Validate that your policy and denylist are well-formed:

```bash
chainwatch certify
```

Check a specific action against current policy:

```bash
chainwatch check --tool command --resource "npm publish" --operation execute
```

## Next Steps

- **Choose a profile** -- see [profiles guide](profiles.md) for all 9 built-in profiles
- **Approval workflow** -- `chainwatch pending`, `chainwatch approve`, `chainwatch deny`
- **MCP integration** -- `chainwatch mcp` for Claude Desktop and other MCP-compatible agents
- **FAQ** -- common questions answered in [FAQ](../FAQ.md)
- **Architecture** -- see the [README](../../README.md) for integration modes, SDKs, and policy configuration
