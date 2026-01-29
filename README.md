# Chainwatch (prototype)

[![CI](https://github.com/ppiankov/chainwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/chainwatch/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Chainwatch is a runtime control plane for AI agents.

AI agents need broad, dynamic access to tools and data to be useful. Existing security controls
(IAM, PAM, NGFW, DLP) validate identity and individual actions, but cannot observe or enforce safety
across the full execution chain of an autonomous agent.

This creates a gap where an agent can:
- access more data than required,
- combine sensitive datasets (mosaic risk),
- and produce unsafe outputs,
without violating any single control.

Chainwatch explores a new control point: **chain-aware runtime enforcement**.

Designed to integrate with multiple agent execution models, including tool-driven, SaaS-hosted, and local agents.
Enforcement is mode-agnostic: it applies regardless of whether an LLM is used, because leakage and over-collection can occur in “no-LLM” report workflows too.

## What it does (goal)
- Intercepts agent tool/data actions
- Correlates actions into execution chains (traces)
- Evaluates policy using evolving chain context
- Enforces decisions mid-execution:
  - allow / deny
  - allow with redaction
  - require approval
  - rewrite outputs

## What it is not
- A prompt firewall or jailbreak detector
- An IAM/RBAC replacement
- A full agent framework
- A production security product (yet)

## Status
Experimental prototype. Expect breaking changes and blunt edges.

## Concept
Treat each agent task as a distributed trace:
request -> tool calls -> data transforms -> output.
We evaluate risk and enforce policy based on the accumulated context of the trace, not isolated events.
- docs/core-idea.md
- docs/mvp-event.md

## Development rules

- Chainwatch prioritizes runtime control over detection or observability.
- Connectors may be sloppy; the core must be deterministic.
- If an action cannot be intercepted and blocked, it is out of scope.
- Policy decisions must be explainable to a human without statistics.

## Integration strategies

Chainwatch can be inserted at different points depending on the agent runtime.
See `docs/integrations/` for an analysis of supported and rejected approaches.

Only one strategy will be implemented at a time.

## FAQ
Common questions are addressed in `docs/FAQ.md`,
including why Chainwatch intentionally does not use ML for enforcement.

## Implementation notes

The current reference implementation is written in Python to optimize
for clarity and iteration speed.

A future implementation may use Go for long-running runtime components
(e.g. proxies, sidecars, or system services) once interception boundaries
and enforcement semantics are proven.

## Quick Start

### Installation

```bash
git clone https://github.com/ppiankov/chainwatch.git
cd chainwatch
make install
```

### Run the Demo

**Option 1: Basic Demo (Quick)**
```bash
make run-demo
```

**Option 2: Realistic Agent Demo (Recommended)**
```bash
make setup-test-data      # Create corporate test data
make run-realistic-demo   # Run agent that tries to accomplish a task
```

The realistic demo shows an agent autonomously trying to analyze SOC team efficiency:
- Agent decides which files to read based on its goal
- Allows reading org charts, SIEM data, performance metrics
- May redact PII from HR employee records
- **Blocks access to salary data** when agent tries cost analysis

Expected output (realistic demo):
```
[Agent] Attempting to read org chart...
✓ Allowed: Org chart read successfully

[Agent] Attempting to read SIEM incidents...
✓ Allowed: SIEM data read successfully

[Agent] Attempting to read HR employee list...
⚠ Allowed: HR data (may contain redacted PII)

[Agent] Attempting to read salary data...
✓ Blocked (expected): Access requires approval: soc_salary_access

✓ Demo successful: Salary access was blocked as expected
```

### Use as Library

```python
from chainwatch.wrappers.file_ops import FileGuard
from chainwatch.enforcement import EnforcementError

actor = {"user_id": "analyst1", "agent_id": "my_agent"}

with FileGuard(purpose="SOC_efficiency", actor=actor) as guard:
    try:
        with open("sensitive_file.csv", "r") as f:
            data = f.read()
        # Use data...
    except EnforcementError as e:
        print(f"Access denied: {e}")

    # Get audit trail
    trace = guard.get_trace_summary()
    print(trace)
```

### Test with External Agent Tools

See [docs/testing-guide.md](docs/testing-guide.md) for instructions on:
- Testing with Aider, OpenHands, or other Python-based agents
- Creating custom test scenarios with realistic corporate data
- What works now vs. what needs HTTP proxy mode (v0.2.0)

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and guidelines.

### Run Tests
```bash
make test
make test-coverage  # Generate HTML coverage report
```

### Format and Lint
```bash
make fmt   # Format with black
make lint  # Check with ruff
make all   # Format, lint, and test
```

### Build Package
```bash
make build
```

## Roadmap

### v0.1.0 (Current - MVP)
- ✓ File operation wrapper (`FileGuard`)
- ✓ Deterministic policy engine (no ML)
- ✓ SOC efficiency demo (blocks salary access)
- ✓ Unit and integration tests (>85% coverage)
- ✓ CI/CD pipeline (Python 3.10-3.12)
- ✓ Path-based file classification

### v0.2.0 (Planned)
- HTTP proxy wrapper for network interception
- Policy DSL (YAML-based configuration)
- Event persistence (Postgres/SQLite)
- Approval workflow CLI
- Content-based file classification

### v1.0.0 (Future)
- Multi-connector support (file, HTTP, database)
- Go-based proxy/sidecar for production deployments
- OpenTelemetry export
- Multi-tenant support
- Policy-as-code with version control integration

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## Known Limitations

These are intentional MVP constraints:

### Architecture
- **In-memory only**: Events not persisted to database
- **Single-threaded**: Trace management not thread-safe
- **No approval UI**: Approval required but blocks by default (no workflow interface)

### File Wrapper
- **Path-based classification**: May miss obfuscated filenames like `data_20250129.csv`
- **Monkey-patching limitations**: Won't catch C extension file I/O or subprocess calls
- **No write monitoring**: Only read operations are intercepted

### Policy
- **Hardcoded rules**: No YAML/JSON configuration yet (v0.2.0)
- **No content inspection**: Classification based on paths, not file contents (v0.2.0)
- **Structural redaction only**: No LLM-based semantic filtering

### Integration
- **File operations only**: No HTTP/network interception yet (v0.2.0)
- **No agent runtime hooks**: Can't integrate directly with Claude Code, Codex, etc. yet

**Roadmap context:** v0.1.0 proves enforcement semantics (blocking works). v0.2.0 proves insertion into real runtimes via HTTP proxy.

See `docs/integrations/file-ops-wrapper.md` and `docs/decisions/002-file-classification.md` for detailed rationale and evolution plans.

## Case studies
- `docs/case-studies/entropia-chainwatch-intraweb.md` – Using Entropia + Chainwatch to scrutinize a sensitive corporate intraweb safely.
