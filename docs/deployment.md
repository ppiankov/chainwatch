# Deployment Guide

## Single-Agent CLI

Simplest setup. Wrap commands directly:

```bash
chainwatch exec -- <command>
chainwatch exec --profile clawbot -- <command>
```

Bootstrap all configuration at once:

```bash
chainwatch init                     # creates policy.yaml, denylist.yaml, profiles/
chainwatch init --profile clawbot   # also writes a profile
chainwatch doctor                   # verify setup
```

Or generate individual configs:

```bash
chainwatch init-policy     # creates ~/.chainwatch/policy.yaml
chainwatch init-denylist   # creates ~/.chainwatch/denylist.yaml
```

Custom paths:

```bash
chainwatch exec --policy /etc/chainwatch/policy.yaml \
                --denylist /etc/chainwatch/denylist.yaml \
                -- <command>
```

## gRPC Multi-Agent

Start the gRPC server for multi-agent environments:

```bash
chainwatch serve --port 9090 \
  --policy /etc/chainwatch/policy.yaml \
  --denylist /etc/chainwatch/denylist.yaml \
  --audit-log /var/log/chainwatch/audit.jsonl
```

Connect from Go SDK:

```go
client, _ := chainwatch.New("localhost:9090")
result, _ := client.Evaluate(&model.Action{
    Tool: "command", Resource: "rm -rf /", Operation: "execute",
}, "general", "")
```

The server supports:
- Hot-reloading policy/denylist on file change (fsnotify)
- Per-trace session accumulation with TTL eviction
- Append-only audit log with SHA-256 hash chain
- Webhook alerting on policy violations

## MCP (Claude Desktop)

Add to Claude Desktop's MCP configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

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

This exposes chainwatch as MCP tools that Claude can call before executing actions.

## HTTP Proxy

Intercept and enforce policy on agent HTTP traffic:

```bash
chainwatch proxy --port 8080 \
  --target https://api.example.com \
  --policy /etc/chainwatch/policy.yaml
```

Configure agent to use `http://localhost:8080` as its HTTP endpoint. All requests are evaluated against policy before forwarding.

## LLM Intercept Proxy

Extract and enforce on tool calls from streaming LLM responses:

```bash
chainwatch intercept --port 8081 \
  --target https://api.openai.com \
  --policy /etc/chainwatch/policy.yaml
```

Supports streaming SSE responses from OpenAI and Anthropic APIs. Tool calls are extracted from `tool_use` content blocks and evaluated before the agent acts on them.

## Docker

```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o chainwatch ./cmd/chainwatch

FROM alpine:3.21
COPY --from=build /app/chainwatch /usr/local/bin/chainwatch
COPY policy.yaml /etc/chainwatch/policy.yaml
COPY denylist.yaml /etc/chainwatch/denylist.yaml
ENTRYPOINT ["chainwatch"]
CMD ["serve", "--port", "9090", "--policy", "/etc/chainwatch/policy.yaml", "--denylist", "/etc/chainwatch/denylist.yaml"]
```

```bash
docker build -t chainwatch .
docker run -p 9090:9090 chainwatch
```

## Audit Verification

Verify the integrity of the append-only audit log:

```bash
chainwatch audit verify /var/log/chainwatch/audit.jsonl
```

This checks the SHA-256 hash chain for tampering. Any modified or deleted entries break the chain.

## Profiles

Built-in agent profiles configure appropriate denylist and policy defaults:

| Profile | Description |
|---------|-------------|
| `clawbot` | Autonomous coding agent (conservative) |
| `devin` | Software engineering agent |
| `manus` | General-purpose agent |
| `soc-analyst` | Security operations |
| `data-pipeline` | ETL/data processing |

Usage: `chainwatch exec --profile clawbot -- <cmd>`
