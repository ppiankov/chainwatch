# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-01-29

### Added
- **Denylist enforcement** (`denylist.py`)
  - Simple, deterministic resource/action blocking
  - Pattern-based matching for URLs, files, and commands
  - Default denylist blocks common dangerous patterns:
    - Checkout/payment URLs (`/checkout`, `/payment`, `stripe.com`, etc.)
    - Credential files (`~/.ssh/id_rsa`, `~/.aws/credentials`, etc.)
    - Dangerous shell commands (`rm -rf`, `sudo su`, etc.)
  - YAML configuration format for user customization
  - Automatic loading from `~/.chainwatch/denylist.yaml`
  - CLI command: `chainwatch init-denylist` to generate default denylist

- **Policy integration**
  - Denylist checked first in `policy.evaluate()` (highest priority)
  - Hard `DENY` decision for denylisted resources (no approval workflow)
  - Explicit reason messages showing which pattern matched

- **Dependencies**
  - Added `pyyaml>=6.0` for denylist configuration parsing

### Changed
- Version bumped to 0.1.1
- `policy.evaluate()` now accepts optional `denylist` parameter
- CLI help updated to include `init-denylist` command

### Documentation
- Added `examples/denylist_demo.py` - demonstrates blocking checkout URLs and credentials
- Added `tests/test_denylist.py` - comprehensive unit tests for denylist functionality
- Added `docs/v0.1.1-denylist-usage.md` - complete usage guide for denylist feature
- Roadmap documents added:
  - `docs/roadmap-clawbot.md` - Integration strategy with Clawbot and autonomous agents
  - `docs/integrations/browser-checkout-gate.md` - v0.2.0 browser wrapper spec
  - `docs/integrations/clawbot-denylist.md` - Using denylist with Clawbot today

### Why This Matters

**v0.1.1 prevents the "$3000 course purchase" incident.**

Before v0.1.1:
- Agent could navigate to checkout and complete purchase
- No mechanism to block dangerous resources by pattern

After v0.1.1:
- Checkout URLs are denylisted by default
- Agent's navigation is blocked before payment can occur
- Users can customize denylist for their specific threats

This is immediate, usable protection for Clawbot and other browser-based agents.

## [0.1.0] - 2026-01-29

### Added
- **Core abstractions**
  - `Action`: Standardized representation of agent operations
  - `TraceState`: Evolving trace-level context for policy decisions
  - `PolicyResult`: Policy evaluation outcome with decision and rationale
  - `Decision` enum: ALLOW, DENY, ALLOW_WITH_REDACTION, REQUIRE_APPROVAL, REWRITE_OUTPUT

- **Policy engine** (`policy.py`)
  - Deterministic risk scoring based on sensitivity, volume, new sources, and egress
  - Purpose-bound hard rules (e.g., SOC_efficiency blocks salary access)
  - Explainable decisions with risk score breakdown
  - No ML or statistical models (by design)

- **Trace accumulator** (`tracer.py`)
  - `TraceAccumulator` for evolving trace state across agent operations
  - Event schema matching docs/mvp-event.md specification
  - Normalized metadata aggregation with `Action.normalize_meta()`
  - JSON-serializable trace export for audit

- **Enforcement engine** (`enforcement.py`)
  - `enforce()` function mapping decisions to actions
  - ALLOW: pass through unchanged
  - DENY / REQUIRE_APPROVAL: raise `EnforcementError` with reason
  - ALLOW_WITH_REDACTION: call `redact_auto()` on data
  - REWRITE_OUTPUT: call `rewrite_output_text()` with patterns

- **Redaction utilities** (`redaction.py`)
  - `redact_auto()`: Recursive dict/list redaction with PII key detection
  - `redact_dict()` / `redact_records()`: Structural redaction APIs
  - `rewrite_output_text()`: Regex-based pattern masking for unstructured text
  - Best-effort PII detection (name, email, phone, ssn, passport, dob, address)

- **File operations wrapper** (`wrappers/file_ops.py`)
  - `FileGuard` context manager for runtime file access enforcement
  - Monkey-patches `builtins.open()`, `pathlib.Path.read_text()`, `Path.read_bytes()`
  - Path-based sensitivity classification (hr, salary, pii patterns)
  - Action → policy → enforcement flow for every file read
  - Trace export via `get_trace_summary()`

- **CLI entrypoint** (`cli.py`)
  - `chainwatch version`: Output tool version as JSON
  - `chainwatch demo soc`: Run SOC efficiency demo
  - Minimal design (no complex reporting yet)

- **SOC efficiency demo** (`examples/soc_efficiency_demo.py`)
  - Realistic scenario: SOC analyst agent accessing org chart, SIEM, HR, salary data
  - Demonstrates all decision types: allow, redact, block
  - Creates temp files simulating corporate data
  - Exits 0 if salary blocked (expected), exits 1 if not (policy violation)
  - JSON trace summary output

- **Comprehensive test suite**
  - Unit tests for types, policy, tracer, enforcement, redaction (>85% coverage)
  - Integration test for FileGuard with real temp files
  - Tests for all decision paths (allow, deny, redact, approval, rewrite)
  - pytest with coverage reporting

- **Developer ergonomics**
  - Makefile with self-documenting targets (help, install, test, fmt, lint, run-demo)
  - pyproject.toml with setuptools build system
  - Black formatting (line length 100)
  - Ruff linting (E, F, I, N, W checks)

- **CI/CD pipeline** (`.github/workflows/ci.yml`)
  - Test matrix: Python 3.10, 3.11, 3.12 on Ubuntu and macOS
  - Lint job: black format check + ruff
  - Demo job: verifies salary blocking works (fails CI if not)
  - Parallel jobs for faster feedback

- **Documentation**
  - CHANGELOG.md (this file) following keepachangelog.com format
  - CONTRIBUTING.md with setup, structure, workflow, testing guidelines
  - docs/getting-started.md: Installation and first integration
  - docs/integrations/file-ops-wrapper.md: FileGuard capabilities and limitations
  - docs/decisions/002-file-classification.md: Path-based classification rationale
  - Updated README.md with Quick Start, Usage, Development, Roadmap

### Security
- File access enforcement prevents unauthorized reads of sensitive data
- Path-based classification for HR, salary, PII patterns
- Deterministic policy (no ML means no model poisoning risk)
- Trace audit trail for compliance

### Known Limitations
- **In-memory only**: No persistence (events not stored to database)
- **Single-threaded**: Trace management not thread-safe yet
- **File wrapper only**: No HTTP/network interception (v0.2.0)
- **No approval UI**: Approval required but no workflow interface (blocks by default)
- **No policy DSL**: Rules hardcoded in policy.py (YAML config in v0.2.0)
- **Structural redaction only**: No LLM-based semantic filtering
- **Path-based classification**: False positives/negatives expected (e.g., /finance vs /hr/salary)
- **Monkey-patching limitations**: Won't catch C extension file I/O or subprocess calls

[Unreleased]: https://github.com/ppiankov/chainwatch/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ppiankov/chainwatch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ppiankov/chainwatch/releases/tag/v0.1.0
