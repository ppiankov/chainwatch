# RES-10: OpenClaw Exec Hook Feasibility

**Date:** 2026-03-09
**Status:** Complete
**Verdict:** No `exec.wrapper` config exists. MCP is the strongest integration today. Intercept proxy remains the only non-bypassable path. Feature request recommended.

## Question

Can OpenClaw (formerly Cline) add an `exec.wrapper` or `tools.exec.wrapper` config that routes all tool execution through an external binary like chainwatch? If not, what integration paths exist today?

## Background

The February 2026 Cline supply chain attack (CVE pending, ~4,000 machines compromised) demonstrated that AI coding agents with unrestricted tool execution are a structural vulnerability. The attack used prompt injection in a GitHub issue title to trigger `npm install` from an attacker-controlled repo, exfiltrating npm publish tokens via preinstall scripts.

Chainwatch enforces policy at the execution boundary. The question is whether OpenClaw can be configured to route tool calls through chainwatch *structurally* (not cooperatively).

## Findings

### 1. No `exec.wrapper` Config Exists

OpenClaw's settings schema has no `tools.exec.wrapper`, `exec.command.prefix`, or equivalent configuration. The tool execution path is:
- `ToolExecutor` dispatches to tool-specific handlers
- `execute_command` tool runs shell commands via Node.js `child_process`
- No hook point between the LLM's tool call decision and the actual `spawn()`

There is no way to configure OpenClaw to prefix all commands with an external binary.

### 2. Plugin System — Diagnostic Only

OpenClaw has a plugin/extension system with `before_tool_call` and `after_tool_call` hooks. However:
- Hooks are **diagnostic only** — they receive tool call info but cannot abort execution
- No return value mechanism to block or modify the tool call
- Designed for logging and telemetry, not enforcement

### 3. Internal Hook Bridge (In Progress)

PR #29590 introduces an internal hook bridge with `agent:tool:start` and `agent:tool:end` events. This is closer to what chainwatch needs, but:
- Events are fire-and-forget (no abort callback)
- Not yet merged as of March 2026
- Even when merged, would need an abort mechanism added

### 4. Feature Request: Issue #7597

Issue #7597 tracks "tool execution hook events with abort callback" — the exact capability chainwatch needs. Status: open, no assignee, moderate community interest. This is the right upstream target.

### 5. MCP Integration (Works Today)

MCP (Model Context Protocol) servers can expose chainwatch as a tool provider:
- `chainwatch mcp` already serves the evaluate/exec tools via MCP
- OpenClaw connects to MCP servers natively
- The LLM can be instructed (via system prompt or SKILL.md) to route commands through chainwatch

**Limitation:** This is cooperative enforcement. The LLM chooses whether to use the chainwatch MCP tool or call `execute_command` directly. A prompt injection that overrides the system prompt bypasses this entirely — which is exactly what happened in the Cline attack.

### 6. Intercept Proxy (Non-Bypassable)

`chainwatch intercept` sits between the LLM API and the agent, extracting tool calls from streaming responses:
- Parses SSE streams for tool_use blocks
- Evaluates policy before the agent receives the tool call
- Can inject deny responses into the stream

This is the only integration that cannot be bypassed by the agent or by prompt injection, because chainwatch controls the communication channel, not the agent.

## Integration Path Comparison

| Path | Exists Today | Bypassable | Enforcement |
|------|-------------|------------|-------------|
| `exec.wrapper` config | No | No | Structural |
| Plugin hooks | Yes | N/A | Diagnostic only |
| Internal hook bridge | PR open | TBD | Fire-and-forget |
| Issue #7597 (abort hooks) | Requested | No | Structural (if built) |
| MCP server | Yes | Yes (cooperative) | Policy-gated |
| Intercept proxy | Yes | No | Structural |
| CLI wrapper (manual) | Yes | Yes (user discipline) | Per-command |

## Recommendations

1. **File upstream feature request** for `tools.exec.wrapper` config on OpenClaw repo, referencing the Cline attack as motivation. Link to issue #7597 as the hook mechanism that would enable it.

2. **Document intercept proxy as primary integration** for security-critical deployments. MCP is convenient but cooperative — intercept proxy is the only path that survives prompt injection.

3. **Ship MCP integration guide** as the easy on-ramp. Most users will accept cooperative enforcement; security-critical users upgrade to intercept proxy.

4. **Monitor PR #29590 and issue #7597** — if abort callbacks land, chainwatch can implement a native OpenClaw plugin that provides structural enforcement without the proxy overhead.

## Decision

No blocking dependency on upstream. Chainwatch's intercept proxy already provides non-bypassable enforcement. MCP provides a cooperative path that works today. The `exec.wrapper` feature request is a nice-to-have that would simplify deployment but is not required for security.
