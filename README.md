# Chainwatch (prototype)

Chainwatch is a runtime control plane for AI agents.

AI agents need broad, dynamic access to tools and data to be useful. Existing security controls
(IAM, PAM, NGFW, DLP) validate identity and individual actions, but cannot observe or enforce safety
across the full execution chain of an autonomous agent.

This creates a gap where an agent can:
- access more data than required,
- combine sensitive datasets (mosaic risk),
- and produce unsafe outputs,
without violating any single control.

Chainwatch explores a new control point: **chain-aware runtime enforcement**.

## What it does (goal)
- Intercepts agent tool/data actions
- Correlates actions into execution chains (traces)
- Evaluates policy using evolving chain context
- Enforces decisions mid-execution:
  - allow / deny
  - allow with redaction
  - require approval
  - rewrite outputs

## What it is not
- A prompt firewall or jailbreak detector
- An IAM/RBAC replacement
- A full agent framework
- A production security product (yet)

## Status
Experimental prototype. Expect breaking changes and blunt edges.

## Concept
Treat each agent task as a distributed trace:
request -> tool calls -> data transforms -> output.
We evaluate risk and enforce policy based on the accumulated context of the trace, not isolated events.
- docs/core-idea.md
- docs/mvp-event.md

## Development rules

- Chainwatch prioritizes runtime control over detection or observability.
- Connectors may be sloppy; the core must be deterministic.
- If an action cannot be intercepted and blocked, it is out of scope.
- Policy decisions must be explainable to a human without statistics.
