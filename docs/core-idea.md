# Core idea

AI agents require broad, dynamic access to tools and data. Traditional security controls validate
identities and individual requests, but they do not preserve or reason about the *end-to-end execution chain*.

Chainwatch treats each agent task as a trace:
request -> tool calls -> data transforms -> output.

We enrich each step with security semantics (purpose, sensitivity, volume, egress) and evaluate policy
against the evolving trace context — then enforce decisions at runtime (block, modify, redact, approve, rewrite output).

This is a control plane, not observability.
