# MVP Event (JSON)

Each intercepted agent action produces one event. Events are correlated into a trace by `trace_id`.

## Event schema (v0)

```json
{
  "ts": "2026-01-29T12:34:56.789Z",
  "trace_id": "t-123",
  "span_id": "s-005",
  "parent_span_id": "s-004",
  "actor": {
    "user_id": "pavel",
    "user_role": "auditor",
    "agent_id": "moltbot",
    "agent_version": "0.1.0"
  },
  "purpose": "SOC_efficiency",
  "action": {
    "type": "tool_call",
    "tool": "hr_api.getEmployee",
    "resource": "hr/employees",
    "operation": "read",
    "params": {
      "query": "team=SOC",
      "fields": ["name", "title", "salary_band"]
    }
  },
  "data": {
    "classification": "high",
    "tags": ["PII", "HR"],
    "volume": {
      "rows": 120,
      "bytes": 48231
    }
  },
  "egress": {
    "direction": "internal",
    "destination": "hr-api.internal"
  },
  "decision": {
    "result": "allow_with_redaction",
    "reason": "Medium risk (risk=8), redacting sensitive fields.",
    "policy_id": "purpose.SOC_efficiency.hr_pii_redact",
    "approval_key": null
  }
}
