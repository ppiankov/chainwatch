# TODO / Next steps

This document defines the immediate next steps for Chainwatch.
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

## Completed milestones

### Control that actually works ✅

All three original goals are met:

1. **Interception points** — 5 implemented (not 1):
   - `chainwatch exec` — subprocess wrapper (CW-03)
   - `chainwatch proxy` — HTTP forward proxy (CW-02)
   - `chainwatch mcp` — MCP tool server (CW-08)
   - `chainwatch intercept` — LLM response interceptor (CW-11)
   - `chainwatch serve` — gRPC policy server (CW-15)

2. **Tracer → policy → enforcement wired end-to-end** ✅
   - All 5 interception points use the same evaluation pipeline
   - Decisions attached to events, denied actions never execute
   - Hash-chained audit log (CW-12), session replay (CW-13), alert webhooks (CW-14)

3. **Demo scenario works** ✅
   - SOC efficiency scenario blocks salary/PII access
   - `make run-demo` and `make run-realistic-demo` both enforce

### Phase 0: Core ✅
CW-01 through CW-07 — monotonic state machine, proxy, subprocess wrapper, declarative policy YAML, safety profiles, approval workflow, root access monitor.

### Phase 1: Integration Layer ✅
CW-08 through CW-11 — MCP server, Python SDK, Go SDK, LLM response interceptor.

### Phase 2: Audit & Compliance ✅
CW-12 through CW-14 — hash-chained audit log, session replay, alert webhooks.

### Phase 3: Multi-Agent & Production ✅
CW-15 through CW-17 — gRPC policy server, agent identity & sessions, budget enforcement.

---

## Immediate next milestone: Phase 4 — Simulation & Testing

### WO-CW18: Rate Limiting
Per-agent rate limits on tool call frequency. Token bucket per agent per tool category. Prevents runaway loops.

### WO-CW19: Policy Simulator
Replay recorded audit logs against new policies. "If I tighten this threshold, which past actions would have been blocked?"

### WO-CW20: CI Policy Gate
`chainwatch check --scenario tests/*.yaml` — run policy assertions in CI. If any scenario allows an action that should be blocked, CI fails.

### WO-CW21: Policy Diff
`chainwatch diff policy-v1.yaml policy-v2.yaml` — show what changed in human-readable terms.

---

## Later milestones

### Phase 5: Ecosystem (CW-22, CW-23)
- Profile marketplace (built-in profiles for coding-agent, research-agent, customer-support, data-analyst)
- Agent certification (`chainwatch certify --profile enterprise-safe`)
- Risk tier formalization (CW-23.1)
- Break-glass emergency override (CW-23.2 — already implemented)

### Phase 6: Adversarial Validation — Dogfight (CW-24 through CW-30)
- VM battlefield setup, 5 test rounds, recording guide
- Prerequisites: CW-12 (audit log) ✅, CW-23.1 (risk tiers) ✅

---

## Explicit non-goals (permanent)
- No ML / anomaly detection
- No LLM-based content analysis
- No dashboards or visualization
- No "warn mode" that allows irreversible actions through
- No model negotiation on boundary decisions

---

## Case study: Entropia + Chainwatch (corporate intraweb)

Goal: demonstrate safe scrutiny of sensitive corporate intraweb content using
Entropia for analysis and Chainwatch for runtime enforcement.

Notes:
- Enforcement is mode-agnostic: applies in both LLM and no-LLM workflows.
- PII exposure and over-collection risks exist even without LLM usage
  (e.g. report generation, exports).

Tasks:
- [ ] Publish case study doc:
      docs/case-studies/entropia-chainwatch-intraweb.md
- [ ] Document that enforcement applies regardless of LLM usage
- [ ] Define HTTP proxy insertion strategy for intraweb crawling (Chainwatch boundary)
- [ ] Provide a reproducible MVP demo using intraweb snapshot + FileGuard (v0.1.x stand-in)

Dependencies:
- Entropia must support proxy configuration (env vars or CLI flags) so that
  intraweb crawling can be routed through an enforcing boundary.

Not before.
