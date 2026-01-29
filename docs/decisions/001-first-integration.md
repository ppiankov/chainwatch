# Decision 001: First integration strategy

## Decision
Implement tool-level wrapper integration first.

## Rationale
- Strongest control guarantees
- Clear semantics
- Minimal agent-runtime dependency
- Best demo-to-effort ratio

## Alternatives considered
- HTTP proxy (weaker semantics)
- Output interception (too late in chain)
- Runtime hooks (not feasible)

## Status
Accepted.
