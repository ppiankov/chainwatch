# File Operations Wrapper

## Overview

The file operations wrapper (`FileGuard`) intercepts file read operations to enforce chain-aware policies before allowing access.

## What It Intercepts

### Covered Operations
- `builtins.open(file, "r")` - Standard Python file opening in read mode
- `pathlib.Path.read_text()` - Path text reading
- `pathlib.Path.read_bytes()` - Path binary reading (currently pass-through)

### Implementation
Monkey-patches built-in functions during context manager lifetime:
```python
with FileGuard(...) as guard:
    # Inside: open() is wrapped
    with open("file.txt") as f:
        data = f.read()  # Intercepted
# Outside: open() is restored
```

## What It Doesn't Intercept

### Not Covered (MVP Limitations)
- **C extension file I/O**: Libraries using native code (e.g., pandas C readers)
- **Subprocess calls**: `subprocess.run(["cat", "file.txt"])`
- **Direct syscalls**: `os.open()`, `os.read()`
- **Write operations**: Only reads are monitored (writes pass through)
- **Binary reads**: `open(file, "rb")` currently passes through
- **Network operations**: HTTP/FTP file access not covered

### Rationale
MVP focuses on proving enforcement semantics. Most agent frameworks use standard Python file I/O, which monkey-patching covers.

For production deployments requiring stronger guarantees, use:
- v0.2.0: HTTP proxy wrapper (network-level interception)
- v1.0.0: Go-based sidecar (OS-level syscall interception)

## Classification Logic

### Path-Based Sensitivity

FileGuard classifies files based on path patterns:

```python
def _build_action_from_path(filepath: str) -> Action:
    sensitivity = "low"
    tags = []

    lower_path = filepath.lower()

    # High sensitivity patterns
    if "hr" in lower_path or "employee" in lower_path:
        sensitivity = "high"
        tags.append("HR")

    if "salary" in lower_path or "payroll" in lower_path:
        sensitivity = "high"
        tags.append("HR")

    if "pii" in lower_path or "ssn" in lower_path or "passport" in lower_path:
        sensitivity = "high"
        tags.append("PII")

    # Medium sensitivity patterns
    if "siem" in lower_path or "incident" in lower_path or "security" in lower_path:
        sensitivity = "medium"
        tags.append("security")

    return Action(
        tool="file_read",
        resource=filepath,
        operation="read",
        result_meta={
            "sensitivity": sensitivity,
            "tags": tags,
            "bytes": os.path.getsize(filepath),
            "rows": 0,  # Unknown without parsing
            "egress": "internal",
            "destination": "localhost",
        },
    )
```

### Expected False Positives/Negatives

**False Positives** (classified as high when actually safe):
- `/finance/quarterly_report.csv` (contains "finance" but not HR-related)
- `/personal_blog/draft.txt` (contains "personal" but not PII)

**False Negatives** (classified as low when actually sensitive):
- `/data/compensation_bands.csv` (no "salary" keyword)
- `/exports/employee_data_20250129.csv` (obfuscated naming)

### Mitigation
For v0.1.0, accept false positives as safe (over-enforcement is better than under-enforcement).

v0.2.0 will add:
- Content-based classification (parse CSV headers, JSON keys)
- User-defined classification rules in YAML config
- Machine learning classifiers (optional, non-blocking)

## Mapping to Action + ResultMeta

FileGuard converts file paths to standardized `Action` objects:

```python
Action(
    tool="file_read",
    resource="/path/to/hr_salary.csv",
    operation="read",
    params={"path": "/path/to/hr_salary.csv"},
    result_meta={
        "sensitivity": "high",
        "tags": ["HR"],
        "bytes": 50000,
        "rows": 0,  # Unknown for files
        "egress": "internal",
        "destination": "localhost",
    },
)
```

This standardization allows policy engine to treat all operations uniformly.

## Integration Examples

### Basic Usage
```python
from chainwatch.wrappers.file_ops import FileGuard

actor = {"user_id": "alice", "agent_id": "assistant"}

with FileGuard(purpose="customer_support", actor=actor) as guard:
    # All reads inside this block are protected
    with open("customer_data.csv") as f:
        data = f.read()

    # Get audit trail
    trace = guard.get_trace_summary()
```

### Handling Denials
```python
from chainwatch.enforcement import EnforcementError

with FileGuard(purpose="SOC_efficiency", actor=actor) as guard:
    try:
        with open("hr_salary.csv") as f:
            data = f.read()
    except EnforcementError as e:
        if "approval" in str(e):
            # Request approval workflow
            approval_key = e.approval_key
            request_approval(user, approval_key)
        else:
            # Hard deny
            log_denial(user, str(e))
```

### Multiple File Access
```python
with FileGuard(purpose="data_analysis", actor=actor) as guard:
    # State accumulates across reads
    df1 = pd.read_csv("sales_2024.csv")  # Intercepted
    df2 = pd.read_csv("sales_2023.csv")  # Intercepted

    # Policy sees cumulative state
    # (2 sources, combined volume, max sensitivity)
```

## Performance Considerations

### Overhead
- Per-file overhead: ~1-5ms (path classification + policy evaluation)
- Negligible for typical agent workflows (<100 file reads)
- No network calls or disk I/O in enforcement path

### Optimization Opportunities (v0.2.0+)
- Cache policy decisions for same path
- Batch classification for directory reads
- Async policy evaluation for non-blocking operation

## Testing

See `tests/integration/test_file_wrapper.py` for comprehensive examples:
- Low-risk file allows
- High-risk file blocks
- Multiple accesses accumulate state
- Context manager properly deactivates
- Write operations pass through

Run integration tests:
```bash
make test
```

## Known Limitations

1. **No content inspection**: Classification is path-only, not content-based
2. **No C extension coverage**: Native code bypasses monkey-patch
3. **No subprocess coverage**: Shell commands not intercepted
4. **Single-threaded**: Trace state not thread-safe
5. **In-memory only**: Events not persisted

These are intentional MVP constraints. See docs/decisions/002-file-classification.md for rationale and evolution plan.
