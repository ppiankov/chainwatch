<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.png">
    <img src="assets/logo-light.png" alt="chainwatch" width="128">
  </picture>
</p>

<p align="center"><em>Autonomy, Contained.</em></p>

# Chainwatch

[![CI](https://github.com/ppiankov/chainwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/chainwatch/actions/workflows/ci.yml)
[![Go 1.25+](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Runtime control plane for AI agent safety. Intercepts tool calls at irreversible boundaries — payments, credentials, data destruction, external communication — and enforces deterministic policy decisions.

## What This Is

A single Go binary that wraps agent tool invocations, evaluates deterministic policy, and enforces decisions (allow, deny, require-approval) at boundaries agents cannot bypass.

## What This Is NOT

- Not an ML-based anomaly detector
- Not a logging/observability layer (enforcement, not detection)
- Not an LLM guardrail for prompt content
- Not a permissions system (enforces boundaries, not roles)
- Not a web UI or SaaS product (CLI only)

## Installation

### From Source

```bash
go install github.com/ppiankov/chainwatch/cmd/chainwatch@latest
```

### From GitHub Release

Download the binary for your platform from [Releases](https://github.com/ppiankov/chainwatch/releases):

```bash
# Linux (amd64)
curl -sL https://github.com/ppiankov/chainwatch/releases/latest/download/chainwatch-linux-amd64 -o chainwatch
chmod +x chainwatch
sudo mv chainwatch /usr/local/bin/

# macOS (Apple Silicon)
curl -sL https://github.com/ppiankov/chainwatch/releases/latest/download/chainwatch-darwin-arm64 -o chainwatch
chmod +x chainwatch
sudo mv chainwatch /usr/local/bin/
```

### From Source (Development)

```bash
git clone https://github.com/ppiankov/chainwatch.git
cd chainwatch
go build -o chainwatch ./cmd/chainwatch
```

## Quick Start

### 1. Wrap a Command

```bash
# Safe command — allowed
chainwatch exec -- echo "hello world"

# Dangerous command — blocked
chainwatch exec -- rm -rf /
# Decision: deny | Reason: Denylisted: command matches pattern: rm -rf
```

### 2. Use a Built-in Profile

```bash
# Enforce clawbot safety profile
chainwatch exec --profile clawbot -- curl https://api.example.com/data

# Available profiles: clawbot, devin, manus, soc-analyst, data-pipeline
```

### 3. Initialize Policy

```bash
# Generate default policy and denylist configs
chainwatch init-policy
chainwatch init-denylist
```

## Architecture

```
Agent ──► chainwatch ──► Tool
              │
         ┌────┴────┐
         │  Policy  │  Deterministic rules, thresholds, denylist
         │  Engine  │  YAML-configurable, hot-reloadable
         └────┬────┘
              │
         allow / deny / require-approval
```

### Integration Modes

| Mode | Command | Use Case |
|------|---------|----------|
| **CLI wrapper** | `chainwatch exec -- <cmd>` | Single agent, simplest setup |
| **gRPC server** | `chainwatch serve` | Multi-agent, SDK integration |
| **HTTP proxy** | `chainwatch proxy` | Intercept agent HTTP traffic |
| **LLM intercept** | `chainwatch intercept` | Extract tool calls from streaming LLM responses |
| **MCP server** | `chainwatch mcp` | Claude Desktop integration |

### CLI Commands

**Enforcement:** `exec`, `serve`, `proxy`, `intercept`, `mcp`, `evaluate`

**Approval workflow:** `approve`, `deny`, `pending`

**Emergency override:** `breakglass create`, `breakglass consume`, `breakglass revoke`, `breakglass list`

**Audit:** `audit verify`

**Policy tools:** `policy diff`, `policy simulate`, `policy gate`, `certify`

**Setup:** `init-denylist`, `init-policy`, `version`

## Policy Configuration

Chainwatch uses deterministic YAML-based policy. No ML or statistical models.

### Denylist (Hard Boundaries)

```yaml
# ~/.chainwatch/denylist.yaml
commands:
  - "rm -rf"
  - "sudo su"
  - "curl * | sh"
urls:
  - "evil.com"
  - "*.onion"
files:
  - "~/.ssh/id_rsa"
  - "~/.aws/credentials"
```

### Policy Rules

```yaml
# ~/.chainwatch/policy.yaml
enforcement_mode: guarded

thresholds:
  allow_max: 5
  approval_min: 11

rules:
  - purpose: "SOC_efficiency"
    resource_pattern: "*salary*"
    decision: deny
    reason: "salary data blocked for SOC purpose"

  - purpose: "*"
    resource_pattern: "*credentials*"
    decision: require_approval
    reason: "credential access requires approval"
    approval_key: cred_access
```

### Approval Workflow

```bash
# Agent hits require_approval → operator approves
chainwatch pending                          # List pending approvals
chainwatch approve salary_access --ttl 5m   # Approve with TTL
chainwatch deny salary_access               # Deny

# Emergency override
chainwatch breakglass create --reason "incident response"
chainwatch exec --breakglass <token> -- <cmd>
```

## SDKs

### Go SDK

```go
import "github.com/ppiankov/chainwatch/sdk/go/chainwatch"

client, _ := chainwatch.New("localhost:9090")
defer client.Close()

result, _ := client.Evaluate(&model.Action{
    Tool:      "command",
    Resource:  "rm -rf /tmp/data",
    Operation: "execute",
}, "general", "")

if result.Decision == model.Deny {
    fmt.Println("Blocked:", result.Reason)
}
```

### Python SDK

```python
from chainwatch_sdk import ChainwatchSDK

cw = ChainwatchSDK()
result = cw.evaluate(tool="command", resource="rm -rf /", operation="execute")
if result["decision"] == "deny":
    print(f"Blocked: {result['reason']}")
```

## Development

```bash
make go-test     # Run Go tests with -race
make test        # Run Python tests
make dogfight    # Run adversarial test suite (5 rounds)
make bench       # Run benchmarks
make fuzz        # Run fuzz tests (30s per target)
```

## Core Philosophy

**Principiis obsta** — resist the beginnings.

- Deterministic policy, not ML predictions
- Enforcement at irreversible boundaries, not after
- The system NEVER asks the model whether an irreversible action is safe
- Monotonic risk: SAFE -> SENSITIVE -> COMMITMENT -> IRREVERSIBLE (one-way)
- Fail-closed: unreachable server = deny

See [docs/irreversible-boundaries.md](docs/irreversible-boundaries.md) and [docs/DESIGN_BASELINE.md](docs/DESIGN_BASELINE.md).

## Known Limitations

- **CLI-only** — no web UI or dashboard
- **Single-node** — no distributed coordination or multi-tenant support
- **Process polling** — `exec` mode uses process-level wrapping, not seccomp/eBPF
- **Python SDK** — subprocess-based (wraps the Go binary, not a native library)
- **No content inspection** — classification based on resource names, not file contents

## License

[Apache 2.0](LICENSE)
