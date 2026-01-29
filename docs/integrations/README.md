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
