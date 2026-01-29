# Getting Started with Chainwatch

## Installation

Clone and install in development mode:

```bash
git clone https://github.com/ppiankov/chainwatch.git
cd chainwatch
make install
```

This installs Chainwatch with all dependencies (pytest, black, ruff).

## Your First Integration

Chainwatch works by wrapping tool operations your agent uses. Currently supports file operations.

### Example: Protect File Access

```python
from chainwatch.wrappers.file_ops import FileGuard
from chainwatch.enforcement import EnforcementError

# Configure the guard
actor = {
    "user_id": "analyst_bob",
    "agent_id": "my_agent",
}

# Wrap file operations
with FileGuard(purpose="SOC_efficiency", actor=actor) as guard:
    # All file reads inside this context are monitored
    try:
        with open("/path/to/sensitive.csv", "r") as f:
            data = f.read()
        print("Access allowed:", data[:100])
    except EnforcementError as e:
        print("Access denied:", e)

    # Get trace summary
    trace = guard.get_trace_summary()
    print("Trace:", trace)
```

## How It Works

FileGuard follows a 5-step enforcement flow:

1. **Intercept**: Monkey-patches `open()`, `Path.read_text()`, `Path.read_bytes()`
2. **Classify**: Builds `Action` with sensitivity based on path patterns
3. **Evaluate**: Calls `policy.evaluate()` with current `TraceState`
4. **Enforce**: Applies decision (allow, deny, redact, require approval)
5. **Record**: Adds event to trace for audit

```
File Read Attempt
       ↓
  FileGuard._guarded_open()
       ↓
  _build_action_from_path()  → Action with ResultMeta
       ↓
  policy.evaluate()          → PolicyResult with Decision
       ↓
  enforcement.enforce()      → Pass through / Block / Redact
       ↓
  tracer.record_action()     → Event added to trace
```

## Policy Rules (v0.1.0)

### Hard Rules (Purpose-Specific)

**SOC_efficiency purpose:**
- Block salary file access (requires approval)
- Approval key: `soc_salary_access`

### Risk-Based Rules

Risk score computed from:
- **Sensitivity weight**: low=1, medium=3, high=6
- **Volume escalation**: >1K rows = +3, >10K rows = +6
- **New source**: +2 if accessing previously unseen resource
- **External egress**: +6 if data leaves internal network

**Decisions based on risk:**
- Risk ≤ 5: **ALLOW**
- Risk 6-10: **ALLOW_WITH_REDACTION**
- Risk ≥ 11: **REQUIRE_APPROVAL**

## File Classification

Automatic sensitivity detection based on path patterns:

**High sensitivity** (triggers redaction or approval):
- Paths containing: `hr`, `employee`, `salary`, `payroll`, `pii`, `personal`, `ssn`, `passport`
- Tags: `HR`, `PII`

**Medium sensitivity** (monitored):
- Paths containing: `siem`, `incident`, `security`
- Tags: `security`

**Low sensitivity** (default):
- All other paths

**Note:** This is path-based classification for MVP. v0.2.0 will add content-based tagging.

## Trace State

Each FileGuard maintains evolving state across operations:

```python
TraceState(
    trace_id="t-abc123",           # Unique trace identifier
    seen_sources=["file1", ...],   # Resources accessed
    max_sensitivity="high",         # Highest sensitivity seen
    volume_rows=150,                # Cumulative row count
    volume_bytes=50000,             # Cumulative byte count
    egress="internal",              # Worst-case egress direction
    tags=["HR", "security"],        # Accumulated tags
)
```

State evolves with each action, influencing future policy decisions.

## Redaction Behavior

### Structured Data (JSON/CSV)
When decision is `ALLOW_WITH_REDACTION`, `redact_auto()` masks PII fields:
- Detects keys: `name`, `first_name`, `last_name`, `email`, `phone`, `address`, `ssn`, `passport`, `dob`
- Replaces values with `[REDACTED]`

```python
# Before redaction
{"name": "Alice", "email": "alice@example.com", "team": "Engineering"}

# After redaction
{"name": "[REDACTED]", "email": "[REDACTED]", "team": "Engineering"}
```

### Unstructured Text
For plain text, enforcement returns a message:
```
"Content redacted; only aggregate counts available"
```

**Important:** Don't expect perfect PII detection in unstructured text. This is best-effort for MVP.

## Run the Demo

```bash
make run-demo
```

This runs the SOC efficiency scenario:
- Agent attempts to access: org chart, SIEM data, HR employees, salary
- Demonstrates all decision types: allow, redact, block
- **Critical:** Exits 1 if salary is not blocked (proves enforcement works)

Expected output:
```
======================================================================
Chainwatch Demo: SOC Efficiency Agent
======================================================================

[Agent] Attempting to read org chart...
✓ Allowed: Org chart read successfully

[Agent] Attempting to read SIEM incidents...
✓ Allowed: SIEM data read successfully

[Agent] Attempting to read HR employee list...
⚠ Allowed: HR data (may contain redacted PII)

[Agent] Attempting to read salary data...
✓ Blocked (expected): Access requires approval: soc_salary_access

======================================================================
Trace Summary
======================================================================
{
  "trace_id": "...",
  "events": [...],
  "state": {...}
}

✓ Demo successful: Salary access was blocked as expected
```

## Next Steps

- **Explore the demo code**: `examples/soc_efficiency_demo.py`
- **Read design docs**: `docs/core-idea.md`, `docs/mvp-event.md`
- **Understand integrations**: `docs/integrations/file-ops-wrapper.md`
- **Write your own wrapper**: See `src/chainwatch/wrappers/file_ops.py` for pattern
- **Run tests**: `make test` to see comprehensive test coverage

## Troubleshooting

### Monkey-patching doesn't catch my file reads
- **Cause**: Using C extensions or subprocess calls
- **Solution**: This is a known limitation for MVP. See docs/integrations/file-ops-wrapper.md for details.

### All files are classified as low sensitivity
- **Cause**: Path patterns don't match
- **Solution**: Sensitivity is path-based for MVP. Rename files to include `hr`, `salary`, etc., or wait for v0.2.0 content-based classification.

### Demo exits 0 but salary wasn't blocked
- **Cause**: Policy bug or enforcement bypass
- **Solution**: This is a CRITICAL bug. Open an issue immediately with trace output.
