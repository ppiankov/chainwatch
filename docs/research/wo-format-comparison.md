# RES-05: Standard vs Custom Work Order Format

**Date:** 2026-03-10
**Status:** Complete
**Verdict:** Keep custom WO schema. Wrap in CloudEvents envelope for transport. Build sink adapters for downstream systems (JIRA, GitHub Issues, PagerDuty, Alertmanager).

## Question

Should nullbot output a standard format (STIX, SARIF, GitHub Issues, etc.) instead of the custom WO schema?

## Findings

### Formats Evaluated

| Format | Coverage | Overhead | Ecosystem | Fit |
|--------|----------|----------|-----------|-----|
| **STIX/TAXII** | Poor — threat intel, not SRE ops | Very high (50+ lines per finding) | OpenCTI, MISP — all threat-intel | 2/10 |
| **SARIF** | Partial — file-based findings only | Moderate | GitHub Code Scanning, VS Code | 4/10 |
| **GitHub Issues** | Full but unstructured | Low per finding | Universal | 5/10 as primary, 8/10 as sink |
| **JIRA** | Instance-specific, not portable | Moderate | Enterprise ticketing | 3/10 as schema, 8/10 as sink |
| **PagerDuty Events v2** | Good for observations | Low (~15 fields) | PD, Opsgenie, incident mgmt | 6/10 for findings, 2/10 for WOs |
| **Alertmanager** | Good for SRE alerts | Low (~10 fields) | Prometheus ecosystem | 5/10 for alerts, 2/10 for WOs |
| **NIST SP 800-61** | Framework, not a schema | N/A | N/A | 1/10 |
| **MITRE ATT&CK** | Taxonomy, not a format | N/A | Labels only | 1/10 |
| **OpenTelemetry** | Observability pipeline | Moderate | OTel ecosystem | 2/10 |
| **CloudEvents** | Envelope only (4 required fields) | Minimal | CNCF, Knative, Argo Events | 7/10 as envelope |

### Critical Insight

No standard format supports the concept of an **agent handoff artifact**. All formats fall into two categories:

1. **Alert formats** (PagerDuty, Alertmanager, CloudEvents): "Something happened." No remediation semantics, no constraints, no goals.
2. **Finding formats** (SARIF, STIX): "Here is what we found." Domain-specific (code analysis, threat intel), no agent handoff.

Nullbot's WO schema bridges observation and remediation in one document — it carries both "what was found" AND "what the agent is allowed to do about it" (constraints, proposed goals, remediation type, redaction mode). No standard format expresses this.

### Recommendation

1. **Keep `wo.WorkOrder` as primary format.** The constraints, proposed goals, remediation type, and redaction mode fields have no equivalent in any standard.

2. **Wrap in CloudEvents for transport.** CloudEvents is a graduated CNCF standard (4 required fields). Enables interop with event meshes and message brokers at near-zero cost:
   ```json
   {
     "specversion": "1.0",
     "type": "com.chainwatch.wo.created",
     "source": "nullbot/<host>/<scope>",
     "id": "wo-a1b2c3d4",
     "data": { /* existing WorkOrder JSON */ }
   }
   ```

3. **Build sink adapters** (already started with JIRA). Each adapter converts WO → target format:
   - JIRA: exists in `internal/jira/`
   - GitHub Issues: WO template title/description → issue body, observation types → labels
   - PagerDuty Events v2: severity maps 1:1, class = observation type, dedup_key = finding hash
   - Alertmanager: labels = type+severity+scope, annotations = detail

4. **Do not adopt STIX.** Extreme overhead, wrong ecosystem.

## Decision

The custom WO schema is not technical debt — it is a domain-specific data structure that no generic standard covers. Standardize the envelope (CloudEvents), not the payload.
