# TODO / Next steps

This document defines the immediate, non-negotiable next steps for Chainwatch.
If something is not listed here, it is intentionally out of scope.

## Ground rules (do not violate these)
- This is a control plane, not observability.
- Enforcement > detection.
- Deterministic, explainable behavior > probabilistic ML.
- If control is not actually intercepting execution, it does not count.

---

## Core invariants (do not break)

### Connector contract (MANDATORY)
Connectors MUST do exactly two things:
1. Set `action.result_meta` with best-effort values:
   - sensitivity: low | medium | high
   - tags: list of strings
   - rows, bytes (approximate is fine)
   - egress: internal | external
   - destination: string (best-effort)
2. Call `action.normalize_meta()` before returning control.

Nothing else.
All sloppiness is allowed *before* normalization.
Nothing sloppy is allowed *after*.

The core stays deterministic even if the world stays messy (it will).

---

## Immediate next milestone: control that actually works

### 1. Pick ONE real interception point
Do not add more than one.

Options (pick exactly one):
- HTTP tool calls via local proxy
- Tool wrapper inside an agent framework
- MCP server proxy
- File / output write path

Goal:
- Intercept
- Build an Action
- Normalize ResultMeta
- Run policy
- Enforce (deny / redact / approve)

If it doesn’t block something real, it doesn’t count.

---

### 2. Wire tracer → policy → enforcement end-to-end
- Use `TraceAccumulator.record_action()`
- Ensure decisions are attached to events
- Ensure denied actions never execute

No dashboards.
No exporters.
No Jaeger.

---

### 3. Make the demo scenario real
From `docs/demo-scenario.md`:
- Run the SOC efficiency scenario
- Actually block or redact salary / PII access
- Show rewritten output

If this doesn’t work, stop adding features.

---

## Explicit non-goals (for now)
- No ML / anomaly detection
- No policy DSL sophistication
- No performance optimization
- No multi-tenant support
- No “enterprise readiness”
- No integrations beyond the chosen interception point

---

## After control works (later)
- Persist events to Postgres
- Optional: export traces to OTel for visualization only
- Approval UX (CLI or minimal web)
- More connectors

Not before.
