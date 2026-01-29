# Case study: Scrutinizing a sensitive corporate intraweb with Entropia + Chainwatch

## Summary
This case study explores a workflow for scrutinizing internal corporate documentation (wiki/intraweb)
using Entropia for analysis while using Chainwatch to enforce runtime boundaries that reduce blast radius
and prevent accidental over-collection or leakage.

Entropia identifies what is interesting or inconsistent.
Chainwatch governs what an autonomous workflow is allowed to access and output.

## Why this matters
Corporate intraweb content often mixes low-sensitivity policy text with highly sensitive details
(PII, incident artifacts, credentials, internal hostnames, compensation references). Agent-driven
analysis can unintentionally expand scope and exfiltrate material even when each individual request
is “authorized”.

This workflow assumes:
- broad access is sometimes required to be useful
- least privilege is insufficient for autonomous exploration
- enforcement must be chain-aware and runtime, not post-hoc

## Roles
### Entropia (analysis)
- Crawls or ingests intraweb pages/documents
- Flags inconsistencies, weak sourcing, suspicious phrasing, drift, and high-risk topics
- Produces a task list / evidence snippets / risk tags

### Chainwatch (runtime enforcement)
- Intercepts access at enforceable boundaries
- Evaluates chain context (trace state) and purpose
- Enforces decisions at runtime: allow / redact / block / require approval / rewrite output
- Produces audit traces aligned with `docs/mvp-event.md`

## LLM vs non-LLM execution
Chainwatch enforcement applies regardless of whether Entropia is executed in `--llm` or `--no-llm` mode.

PII exposure, over-collection, and improper aggregation can occur even when no language model is involved
(e.g., report generation, exports, or artifacts shared with humans). For this reason, enforcement is
intentionally mode-agnostic.

`--llm` mode introduces additional risks (e.g. prompt injection, unintended data synthesis), but it does
not define the security boundary.

As a result:
- Reports generated in `--no-llm` mode may be redacted
- Certain analyses may fail if they exceed allowed sensitivity for the stated purpose
- Bulk exports may be blocked even without LLM involvement

This behavior is intentional and aligns with the goal of reducing blast radius across the full execution chain.

## Integration model
### Target architecture (preferred)
1. Entropia fetches intraweb content through an HTTP proxy
2. The proxy is instrumented/enforced by Chainwatch (HTTP boundary; planned v0.2.0+)
3. Chainwatch correlates requests into a trace and enforces policy based on:
   - destination and path
   - sensitivity classification (domain/path rules; later tags)
   - volume limits and scope expansion
   - output/egress controls

### Current limitation
Entropia currently can only be routed through a proxy, but does not accept proxy configuration as a parameter.
Proxy support must be added to Entropia before this end-to-end flow is possible.

Required Entropia work:
- accept proxy configuration (CLI flags and/or env vars)
- propagate to HTTP client(s)
- document usage and add tests

## MVP approximation (what we can demonstrate today)
Chainwatch v0.1.0 enforces file operations via FileGuard. Until HTTP proxy enforcement exists, we can approximate
an intraweb audit by exporting a snapshot of pages to files and letting an “agent workflow” attempt to read them.

This demonstrates:
- real runtime interception
- deterministic enforcement decisions
- blocking sensitive access (e.g., salary/HR pages)
- redaction for PII-like content
- trace/audit output

It does not demonstrate:
- live intraweb crawling
- network boundary enforcement
- proxy routing correctness

## Example scenario: “SOC efficiency policy audit”
User request:
> “Review our SOC efficiency guidance and propose improvements.”

Data sources (intraweb snapshot):
- /policies/soc_efficiency.md (low)
- /security/siem_runbook.md (medium)
- /hr/employees.csv (high, PII)
- /hr/salary_bands.csv (high, blocked for this purpose)

Expected enforcement:
- allow policy + runbook
- allow with redaction for employees.csv (or require aggregation-only output)
- require approval or block salary_bands.csv (default: require approval)

## Policies and classification (v0)
Classification can be path-based initially:
- high: paths containing hr, employee, salary, payroll, pii, ssn
- medium: siem, incident, security
- low: default

Purpose-bound rule example:
- purpose == SOC_efficiency AND resource contains salary => REQUIRE_APPROVAL

## Outputs
Artifacts produced:
- console demo output (allowed/redacted/blocked)
- trace summary JSON
- events consistent with `docs/mvp-event.md`

## Next steps
- Add proxy parameter support to Entropia (see Entropia TODO)
- Implement Chainwatch HTTP proxy boundary (planned v0.2.0+)
- Replace path heuristics with sensitivity labels from a crawler/tagger (future)
- Add output interception to prevent bulk export/exfiltration (future)
