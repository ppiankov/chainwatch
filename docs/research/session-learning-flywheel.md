# RES-07: Session Learning and Knowledge Flywheel

**Date:** 2026-03-10
**Status:** Complete
**Verdict:** Worth pursuing for v2.0+ but keep it simple. SQLite-based investigation history (already have the storage layer) with pattern matching on finding hashes. Do not build a knowledge graph — the operational domain does not have the entity density to justify it.

## Question

Should nullbot learn from past investigation sessions? What would "learning" look like for an SRE observation agent?

## Findings

### What "Learning" Means for SRE

Unlike a dev assistant that learns coding patterns, an SRE agent learns **causal chains** and **remediation outcomes**:

1. **Recurrence detection**: "This host had the same finding 3 times in 30 days — the remediation isn't working"
2. **Remediation memory**: "Last time we saw `slow_queries` on this cluster, the fix was adding an index on table X"
3. **Baseline awareness**: "CPU at 85% is normal for this host during batch processing hours"
4. **Cross-host patterns**: "This finding appeared on 4/6 hosts in the same cluster — likely a shared root cause"

Items 1 and 4 are **already partially implemented** via finding deduplication (`internal/observe/finding_hashes.go`) and multi-cluster aggregation (WO-094). The gap is items 2 and 3.

### Storage Options

| Option | Pros | Cons | Fit |
|--------|------|------|-----|
| **SQLite (extend existing)** | Already used for dedup + lifecycle. Schema migration simple. Full SQL queries. | No graph relationships | 8/10 |
| **File-based JSON** | Simplest. Human-readable. Git-friendly | No queries, no joins, bloats fast | 4/10 |
| **Knowledge graph (NetworkX)** | Rich relationships. Entity inference | Overkill for ops data. Adds Python dep or needs Go port | 3/10 |
| **Hybrid RAG (vector + graph)** | Best retrieval for unstructured data | Massive complexity. Needs embedding model. Storage overhead | 2/10 |

### Fabrik-Codek Pattern Analysis

The Fabrik-Codek project uses:
- Deterministic entity IDs (MD5 of type + normalized name)
- Edge weight reinforcement (+0.1 per occurrence, capped at 1.0)
- Single-level transitive inference
- mtime-tracked incremental indexing

**Assessment:** This pattern works for a dev assistant where entities are stable (files, functions, classes) and relationships are dense (imports, calls, inherits). For SRE operations, entities are transient (hosts come and go, findings are ephemeral) and relationships are sparse (a host has findings, a finding has a remediation). The graph adds complexity without proportional value.

### What Existing Tools Do

| Tool | Learning Mechanism |
|------|-------------------|
| **PagerDuty** | Past incident similar-incident search, ML-based grouping of related alerts |
| **Rootly** | Postmortem templates with linked incidents, auto-suggested action items from past resolutions |
| **incident.io** | Catalog of past incidents searchable by service/team, "similar incidents" feature |
| **FireHydrant** | Runbook versioning with effectiveness tracking |

All use simple search/matching on structured metadata — none use knowledge graphs or RAG for incident learning.

### Risks

- **Stale knowledge**: Remediation that worked 6 months ago may not apply to current infrastructure
- **False correlations**: "Last time CPU was high, we restarted nginx" doesn't mean nginx caused the CPU spike
- **Storage bloat**: Investigation data includes command output that can be large
- **Privacy**: Investigation output may contain sensitive data (credentials in logs, PII in DB queries)

## Recommendation

**Phase 1 (v2.0): Extend SQLite with investigation history table.**

```sql
CREATE TABLE investigation_history (
    id TEXT PRIMARY KEY,
    finding_hash TEXT NOT NULL,
    host TEXT,
    cluster TEXT,
    finding_type TEXT,
    remediation_type TEXT,
    remediation_summary TEXT,
    outcome TEXT,  -- 'resolved', 'recurred', 'ineffective'
    created_at TIMESTAMP,
    resolved_at TIMESTAMP
);
```

This enables:
- "Show me past remediations for this finding type on this cluster"
- "How many times has this finding recurred?"
- "What was the average time-to-resolution for this finding type?"

**Phase 2 (v2.1+): Pattern matching on investigation history.** Before dispatching a new WO, check if a similar finding was recently resolved and what remediation was used. Surface as context in the WO, not as an automated decision.

**Do not build:** Knowledge graph, RAG, vector embeddings, or any ML-based learning. The operational domain is structured enough that SQL queries on finding metadata provide 90% of the value at 10% of the complexity.
