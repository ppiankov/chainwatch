# Tool-level wrapper integration

## Where interception happens
At the boundary between the agent runtime and its tools.
Chainwatch replaces or wraps tool functions exposed to the agent.

## What Chainwatch sees
- Tool name and parameters
- Structured inputs/outputs
- Clear resource identity
- Natural place to attach ResultMeta

## What Chainwatch can control
- Block tool execution
- Modify tool parameters
- Redact tool outputs
- Require approval before execution

## What Chainwatch cannot control
- Agent reasoning steps
- Implicit actions not exposed as tools
- Internal model behavior

## When this makes sense
- Claude Code custom tools
- OpenCode plugins
- Any agent framework with explicit tool calls

## Notes
This is the preferred MVP strategy.
It provides strong control with minimal intrusion into agent internals.
