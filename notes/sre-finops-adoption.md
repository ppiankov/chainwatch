# SRE & FinOps Adoption Plan (LOCAL ONLY — do not commit)

Date: 2026-03-03
For: User requesting multi-agent SRE + auto FinOps

---

## What Works TODAY (no code changes)

### SRE Monitoring — Ready Now

**Built-in runbooks:**
```bash
# Linux health (processes, ports, cron, permissions, rogue users, disk, memory)
nullbot observe --scope / --type linux --classify --output /tmp/health.json

# MySQL (slow queries, replication lag, locks, InnoDB, error logs)
nullbot observe --scope /var/lib/mysql --type mysql --classify

# Nginx (config validation, SSL certs, error logs, upstream health)
nullbot observe --scope /var/log/nginx --type nginx --classify

# Postfix (queue depth, delivery failures, bounces, relay config)
nullbot observe --scope /var/log --type postfix --classify
```

**Continuous monitoring via daemon:**
```bash
nullbot init --profile vm-cloud    # generates systemd unit + env file
sudo systemctl start nullbot       # watches inbox for jobs
# Drop job files in inbox → daemon processes → observations in outbox
# nullbot list / nullbot approve <wo-id> / nullbot reject <wo-id>
```

**Ad-hoc LLM-driven investigation:**
```bash
nullbot run "investigate high CPU, check OOM kills in dmesg, verify disk space"
```

### FinOps — Ready with Custom Runbooks

Users can create YAML runbooks in `~/.chainwatch/runbooks/` — nullbot auto-discovers them.

**`~/.chainwatch/runbooks/aws-billing.yaml`:**
```yaml
name: "AWS billing investigation"
type: aws-billing
aliases: [billing, cost]
sensitivity: local
steps:
  - command: "aws ce get-cost-and-usage --time-period Start=$(date -v-30d +%Y-%m-%d),End=$(date +%Y-%m-%d) --granularity DAILY --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE --output json 2>/dev/null | head -80 || echo 'cost explorer not available'"
    purpose: "daily cost breakdown by service for last 30 days"
  - command: "aws ce get-cost-forecast --time-period Start=$(date +%Y-%m-%d),End=$(date -v+30d +%Y-%m-%d) --metric UNBLENDED_COST --granularity MONTHLY 2>/dev/null || echo 'forecast not available'"
    purpose: "cost forecast for next 30 days"
  - command: "aws ec2 describe-volumes --filters 'Name=status,Values=available' --query 'Volumes[].[VolumeId,Size,VolumeType]' --output table 2>/dev/null || echo 'no unattached EBS'"
    purpose: "find unattached EBS volumes (wasted spend)"
  - command: "aws ec2 describe-addresses --query 'Addresses[?AssociationId==null].[PublicIp,AllocationId]' --output table 2>/dev/null || echo 'no unused EIPs'"
    purpose: "find unused Elastic IPs (charged when unattached)"
  - command: "aws ce get-reservation-utilization --time-period Start=$(date -v-30d +%Y-%m-%d),End=$(date +%Y-%m-%d) 2>/dev/null | head -30 || echo 'RI utilization not available'"
    purpose: "check reserved instance utilization"
```

**`~/.chainwatch/runbooks/k8s-cost.yaml`:**
```yaml
name: "Kubernetes resource utilization"
type: k8s-cost
aliases: [utilization, k8s-resources]
sensitivity: any
steps:
  - command: "kubectl top nodes 2>/dev/null || echo 'metrics-server not available'"
    purpose: "node CPU and memory usage"
  - command: "kubectl top pods -n {{SCOPE}} --sort-by=cpu 2>/dev/null | head -20"
    purpose: "top CPU consuming pods"
  - command: "kubectl top pods -n {{SCOPE}} --sort-by=memory 2>/dev/null | head -20"
    purpose: "top memory consuming pods"
  - command: "kubectl get pods -n {{SCOPE}} -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.spec.containers[*].resources.requests.cpu}{\"\\t\"}{.spec.containers[*].resources.requests.memory}{\"\\n\"}{end}' 2>/dev/null | head -30"
    purpose: "pod resource requests for overprovisioning analysis"
  - command: "kubectl get pods --all-namespaces --field-selector=status.phase=Succeeded -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{\"\\n\"}{end}' 2>/dev/null | head -20 || echo 'no completed pods'"
    purpose: "find completed pods still consuming resources"
```

**`~/.chainwatch/runbooks/clickhouse.yaml`:**
```yaml
name: "ClickHouse server investigation"
type: clickhouse
aliases: [ch, clickhouse-server]
sensitivity: local
steps:
  - command: "clickhouse-client --query 'SELECT version()' 2>/dev/null || echo 'clickhouse-client not available'"
    purpose: "check ClickHouse version and connectivity"
  - command: "clickhouse-client --query 'SELECT * FROM system.replicas WHERE is_leader = 0 AND active_replicas < total_replicas' 2>/dev/null | head -20 || echo 'replica status not available'"
    purpose: "check replication health and lagging replicas"
  - command: "clickhouse-client --query 'SELECT database, table, formatReadableSize(sum(bytes_on_disk)) as size, sum(rows) as rows FROM system.parts WHERE active GROUP BY database, table ORDER BY sum(bytes_on_disk) DESC LIMIT 20' 2>/dev/null || echo 'cannot query parts'"
    purpose: "top tables by disk usage"
  - command: "clickhouse-client --query 'SELECT query_id, user, elapsed, read_rows, memory_usage, query FROM system.processes ORDER BY elapsed DESC LIMIT 10' 2>/dev/null || echo 'cannot list running queries'"
    purpose: "check long-running queries"
  - command: "clickhouse-client --query 'SELECT type, event_time, message FROM system.text_log WHERE level IN (\\\"Error\\\", \\\"Fatal\\\") ORDER BY event_time DESC LIMIT 30' 2>/dev/null || echo 'text_log not available'"
    purpose: "recent error and fatal log entries"
  - command: "clickhouse-client --query 'SELECT metric, value FROM system.metrics WHERE metric LIKE \\\"%Connection%\\\" OR metric LIKE \\\"%Query%\\\" OR metric LIKE \\\"%Memory%\\\"' 2>/dev/null || echo 'metrics not available'"
    purpose: "current connection, query, and memory metrics"
  - command: "clickhouse-client --query 'SELECT database, table, formatReadableSize(sum(primary_key_bytes_in_memory)) as pk_memory FROM system.parts WHERE active GROUP BY database, table ORDER BY sum(primary_key_bytes_in_memory) DESC LIMIT 10' 2>/dev/null || echo 'cannot check PK memory'"
    purpose: "tables consuming most primary key memory"
  - command: "clickhouse-client --query 'SELECT * FROM system.merges LIMIT 10' 2>/dev/null || echo 'no active merges'"
    purpose: "check active merge operations"
```

**Usage:**
```bash
nullbot observe --type aws-billing --scope us-east-1 --classify
nullbot observe --type k8s-cost --scope default --classify
nullbot observe --type clickhouse --scope prod --classify
```

---

## What's Missing — WO Dependency Map

### For SRE Multi-Agent System (full vision)

```
TODAY (works now)
  nullbot observe --type linux/mysql/nginx
  nullbot daemon (continuous monitoring)
  Custom runbooks (user YAML)
      │
      ▼
WO-CW65: SRE Investigation Runbooks ←── built-in k8s/prometheus/cloud-infra
WO-CW69: ClickHouse Investigation Runbook ←── built-in clickhouse
      │
      ▼ (can use runbooks, but agents not yet scoped)
WO-CW63: SRE Infrastructure Safety Profile ←── IaC-only enforcement
      │
      ▼ (agents scoped, but can self-approve)
WO-CW64: Agent-Reviews-Agent Approval ←── anti-circular, trust hierarchy
      │
      ▼ (full vision: specialized agents, IaC-only, cross-review)
DONE — Multi-Agent SRE with safety guardrails
```

### For Auto FinOps (full vision)

```
TODAY (works now)
  Custom runbooks (aws-billing, k8s-cost YAML)
  nullbot observe --classify
      │
      ▼
WO-CW67: FinOps Investigation Runbooks ←── built-in aws-billing/k8s-utilization/cost-anomaly
WO-CW69: ClickHouse Investigation Runbook ←── built-in clickhouse
      │
      ▼
WO-CW66: FinOps Read-Only Profile ←── structural read-only + PII redaction
      │
      ▼
WO-CW68: Multi-Runbook Evidence Correlator ←── "super-source" multi-source analysis
      │
      ▼
DONE — Continuous FinOps with multi-source correlation
```

---

## WO Summary

| WO | Name | Blocks | Needed for |
|----|------|--------|------------|
| CW63 | SRE Infrastructure Safety Profile | CW64 | SRE |
| CW64 | Agent-Reviews-Agent Approval | — | SRE |
| CW65 | SRE Investigation Runbooks | CW68 | SRE + FinOps |
| CW66 | FinOps Read-Only Profile | — | FinOps |
| CW67 | FinOps Investigation Runbooks | CW68 | FinOps |
| CW68 | Multi-Runbook Evidence Correlator | — | FinOps + SRE |
| CW69 | ClickHouse Investigation Runbook | — | Both |

**Total: 7 WOs to full vision**
- SRE path: 4 WOs (CW65 → CW63 → CW64, plus CW69)
- FinOps path: 4 WOs (CW67 → CW66 → CW68, plus CW69)
- Shared: CW65, CW68, CW69 serve both use cases
