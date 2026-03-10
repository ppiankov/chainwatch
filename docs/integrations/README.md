# Integration strategies

Chainwatch is a runtime control plane for AI agents.
Because agent runtimes differ widely in openness and extensibility,
there is no single universal insertion point.

This directory documents *realistic* integration strategies,
their guarantees, and their trade-offs.

These documents are design investigations, not commitments.
Only one strategy will be implemented first.

Independent security audits of AI agents demonstrate that many frameworks allow agents to
invoke dangerous operations (e.g. code execution, browser automation, file writes, external
network access) with little or no gating, verification, or contextual enforcement. In such
environments, attempting to secure agent internals is neither feasible nor sufficient.

Chainwatch therefore focuses on enforcing policy at boundaries agents cannot bypass —
tools, network access, and output paths — where execution can be intercepted, evaluated
in context, and controlled in real time.

## Guides

| Guide | Integration model | Enforcement |
|-------|-------------------|-------------|
| [Claude Desktop](claude-desktop.md) | MCP server (cooperative) | Agent routes actions through chainwatch tools |
| [Agent runtime hooks](agent-runtime-hooks.md) | PreToolUse hook (non-cooperative) | Automatic interception of all tool calls |
| [HTTP proxy](http-proxy.md) | Network proxy | All outbound HTTP passes through policy |
| [Tool wrapper](tool-wrapper.md) | Function wrapping | Wraps individual tool functions |
| [File ops wrapper](file-ops-wrapper.md) | Monkey-patch builtins.open | All file I/O passes through policy |
| [Browser checkout gate](browser-checkout-gate.md) | Browser automation | Intercepts checkout flows |
| [Output interception](output-interception.md) | Output filter | Scans agent output before delivery |
| [Denylist presets](clawbot-denylist.md) | Pattern library | Pre-built denylist patterns |
