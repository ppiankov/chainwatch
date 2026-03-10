# RES-09: DAKTAKLAKPAK — Alert Entropy Governor

**Date:** 2026-03-10
**Status:** Complete
**Verdict:** Novel and buildable. 5/12 dimensions fully automatable from Prometheus/Alertmanager APIs, 4 partially automatable, 3 need human input. Standalone Go CLI + Prometheus exporter mode. Should be a separate project, not a nullbot runbook.

## Question

Can the 12 DAKTAKLAKPAK dimensions be computed from Prometheus/Alertmanager? What's the implementation form? What exists already?

## Findings

### Dimension Computability

#### Fully Automatable (5/12)

| Dim | Name | Data Source | Method |
|-----|------|------------|--------|
| **D** | Duplicate | Alertmanager `GET /api/v2/alerts` | Correlate co-firing alerts by time window. Alerts firing within same 5-min window for same labels = duplicate candidates |
| **K** | Known-noise | Alertmanager silence API | Count silences per alert name. High silence-to-firing ratio = known noise |
| **A** | Always-firing | `ALERTS_FOR_STATE` metric via PromQL | Check continuous firing >14 days: `count_over_time(ALERTS{alertname="X",alertstate="firing"}[14d:1h]) > 336` |
| **P** | Paging-abuse | Alertmanager routing config + Prometheus rules API | `severity: info` or `warning` routed to paging receiver = paging abuse |
| **T** | Threshold-misaligned | Prometheus rules API + metric history | Extract threshold from PromQL expression. Compare to actual metric distribution. Crossed >50% or <0.1% of the time = misaligned |

#### Partially Automatable (4/12)

| Dim | Name | Automated Signal | Human Input Needed |
|-----|------|-----------------|-------------------|
| **A** | Actionless | Check `runbook_url` annotation exists + HTTP reachability | Whether runbook is actually useful/maintained |
| **L** | Legacy | Check if alert PromQL references metrics returning no data (pint does this) | Confirming absence = decommissioned vs temporarily missing |
| **A** | Ambiguous | Check annotations for `summary`, `description`, `runbook_url` completeness | Whether text semantically answers "what's wrong" and "what to do" |
| **K** | KPI-misaligned | No direct API signal | Business context: does this metric matter to users/revenue? |

#### Requires Human Input (3/12)

| Dim | Name | Proxy | Actual Source |
|-----|------|-------|--------------|
| **A** | Abandoned | Git history: `git log --follow -1` for last modified date | Git blame + team directory. No owner label AND >6 months = abandoned |
| **K** | Kafkaesque | Absence of description, runbook, commit context, owner | Human judgment — nobody on the team can explain its purpose |
| **K** | Killable | Composite of all other scores | Final human decision. This IS the output dimension |

### Minimum Firing History

| Window | Coverage | Practical |
|--------|----------|-----------|
| **30 days** | Minimum viable. A(always-firing), K(noise), T(threshold) | Works with default Prometheus retention |
| **90 days** | Recommended. Full statistical confidence. Captures monthly patterns | Needs Thanos/Cortex/Mimir |
| **180 days** | Ideal for A(abandoned) and seasonal patterns | Long-term storage required |

Google SRE's removal threshold: "rarely exercised, less than once a quarter" — 90 days is the minimum meaningful window.

### Existing Tools Comparison

| Tool | What It Does | DAKTAKLAKPAK Coverage | Gap |
|------|-------------|----------------------|-----|
| **Cloudflare pint** | Prometheus rule linter (Go) | L, A(actionless), T, P | Static analysis only, no runtime behavior |
| **Robusta** | K8s alert management | D, K(noise), A(ambiguous) | K8s-only. No scoring. No pruning |
| **PagerDuty Event Intelligence** | ML alert grouping | D, K(noise), A(always-firing) | Black-box ML. Optimizes routing, not source |
| **Moogsoft** | ML event correlation | D, T, K(noise) | ML-heavy. Enterprise only |
| **BigPanda** | Cross-tool correlation | D, K(noise) | Aggregation layer, not source hygiene |
| **Datadog Monitor Quality** | Flapping/muted monitor detection | K(noise), A(abandoned), P, T | Datadog-only. No deletion recommendations |
| **Grafana Alerting Insights** | Firing frequency dashboards | K(noise), A(always-firing) | Visualization only, no scoring |

**Critical gap:** Every existing tool treats alert noise as a **routing problem**. DAKTAKLAKPAK treats it as a **source code problem**. No existing tool provides deterministic scoring, pruning recommendations, or deletion workflows.

### The "Three Questions" Survival Test

Origin: Rob Ewaschuk's "My Philosophy on Alerting" (2013, at Google), which became the foundation for Google SRE Book Chapter 6. The specific formulation "What is wrong? What should I do? What happens if I ignore it?" is folk SRE wisdom rooted in Ewaschuk but not attributable to a single source. Safe to use.

Related: CASE Method (Context, Actionable, Symptom-based, Evaluated) by Ryan Frantz formalizes similar ideas.

### Governance: Alert Budgets

No company publicly documents hard alert caps. Google SRE practices:
- On-call target: <2 pages per 12-hour shift
- Actionable ratio: >80% of pages result in human action
- Review cadence: quarterly

Proposed DAKTAKLAKPAK enforcement:
- **Report**: Per-team alert count and quality scores quarterly
- **CI gate**: Block PRs adding alerts to services already over budget (pint-style)
- **Escalation**: Auto-create review ticket if service has >N alerts scoring >6/12

## Design Recommendation

### Standalone Go CLI + Prometheus Exporter

```bash
# One-shot scoring
daktaklakpak score \
  --prometheus-url http://prometheus:9090 \
  --alertmanager-url http://alertmanager:9093 \
  --history 90d \
  --format table

# Continuous exporter
daktaklakpak serve --port 9099
# Exposes: daktaklakpak_score{alertname="X", dimension="duplicate"} 1
```

### Architecture

```
cmd/daktaklakpak/main.go
internal/
  scorer/           -- One file per dimension (12 files)
  prometheus/       -- Prometheus API client
  alertmanager/     -- Alertmanager API client
  git/              -- Git history analysis for abandoned/kafkaesque
  exporter/         -- Prometheus exporter mode
  report/           -- Output formatting (JSON, table, markdown)
```

### Why Separate Project

- Different domain (monitoring hygiene, not agent safety)
- Different users (SRE teams, not agent operators)
- Different dependencies (Prometheus client, Alertmanager client)
- nullbot can consume DAKTAKLAKPAK scores as an input source for WOs, but the scoring engine stays independent

### Scoring

Equal weights initially (1 point per dimension, max 12). Configurable overrides. Thresholds:
- 4/12: flag for review
- 7/12: strong recommendation to delete
- 10/12: auto-file deletion ticket

### What Makes This Novel

1. **Source-level, not routing-level** — goal is deletion, not grouping
2. **Deterministic scoring** — no ML, every dimension has explicit criteria
3. **Multi-dimensional** — combines static analysis (annotations, PromQL) with dynamic analysis (firing history, co-occurrence)
4. **Governance integration** — alert budgets and deletion workflows, not just dashboards
