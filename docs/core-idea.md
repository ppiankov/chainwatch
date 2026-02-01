# Core idea

AI agents require broad, dynamic access to tools and data. Traditional security controls validate
identities and individual requests, but they do not preserve or reason about the *end-to-end execution chain*.

Chainwatch treats each agent task as a trace:
request -> tool calls -> data transforms -> output.

We enrich each step with security semantics (purpose, sensitivity, volume, egress) and evaluate policy
against the evolving trace context — then enforce decisions at runtime (block, modify, redact, approve, rewrite output).

This is a control plane, not observability.

## Irreversible Boundaries

Some actions are irreversible: once executed, no subsequent policy can undo their effects.

Chainwatch treats these transitions as **hard execution boundaries** where the system must refuse
continuation regardless of model intent.

Examples:
- Payment commitment (money leaves account)
- Credential exposure (secrets cannot be "unread")
- Data destruction (deleted files cannot be recovered)
- External communication (sent messages cannot be recalled)

The denylist is not a security feature — it is a declaration of **points beyond which execution
must not proceed** without explicit human consent.

See `docs/irreversible-boundaries.md` for detailed explanation.
