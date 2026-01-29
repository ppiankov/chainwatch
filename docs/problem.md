# Problem

AI agents execute multi-step plans across heterogeneous systems. To be useful, they require broad
permissions and autonomy. Traditional security controls evaluate:
- identity/authentication,
- individual requests,
- static policies at system boundaries.

They generally do not preserve or reason about the **end-to-end execution chain** and the **context
accumulated across steps**.

## Failure modes
- Scope creep: the same user request triggers wildly different access patterns over time.
- Mosaic risk: combining datasets creates higher sensitivity than each dataset alone.
- Invisible policy violations: each individual call is authorized, but the final output is not safe.

## Requirements for a new control point
- Preserve chain context across boundaries (user -> agent -> tools/services -> models)
- Attach security semantics to actions (sensitivity, purpose, egress)
- Enforce at runtime: block/modify/redact/approve/rewrite
