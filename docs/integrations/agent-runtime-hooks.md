# Agent runtime hooks (not currently feasible)

## Summary
Direct integration inside proprietary agent runtimes (e.g. Claude Code, Claude Co-Worker)
is currently not feasible.

## Reasons
- No supported interception hooks
- Closed execution models
- Security controls are not first-class concerns

## Implication
Chainwatch must operate at boundaries the agent cannot bypass:
tools, network, or output.

## Status
Explicit non-goal for v0.
