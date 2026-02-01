# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-02-01

### Changed

**Conceptual reframe: from "denylist" to "irreversible boundaries"**

v0.1.2 contains **no code changes** from v0.1.1. The implementation is identical.

What changed is **how we describe what it does**.

We built a denylist in v0.1.1. Then we realized what it actually is: a primitive implementation of **irreversibility-aware boundary detection**.

### What This Means

**v0.1.1 language (functional, but undersold):**
- "Block dangerous actions"
- "Denylist for bad URLs"
- "Security feature"

**v0.1.2 language (aligned with Chainwatch philosophy):**
- "Refuse execution when chains cross irreversible boundaries"
- "Structural points of no return"
- "Control plane interrupt"

### Why Language Matters

Chainwatch is not about blocking "bad things."

Chainwatch is about **structural awareness of irreversibility in execution chains**.

Some actions cannot be undone:
- Payment commitment (money leaves account)
- Credential exposure (secrets cannot be "unread")
- Data destruction (deleted files cannot be recovered)

These are not moral judgments. These are **architectural properties**.

The denylist declares these boundaries. Policy evaluation refuses to cross them.

### Documentation Changes

- **Added:** `docs/irreversible-boundaries.md` - Core concept document (650+ lines)
  - **Two classes of boundaries:** Execution boundaries AND Authority boundaries
  - Execution: actions that cannot be undone (payment, credentials, destruction)
  - Authority: instructions that cannot be un-accepted (proxied commands, injection)
  - Real incident analysis: Clawdbot attack (2026) as authority boundary violation
  - Critical warning section: how approval workflows in v0.2.0 could break philosophy if implemented incorrectly
  - Terminology: DENY (absolute) vs REQUIRE_APPROVAL (human override)
  - Out-of-band approval requirements: model must not observe or influence
  - Non-goal: Chainwatch judges recoverability, not morality
  - Unified philosophy: both boundaries ask "Is this transition irreversible?"
- **Added:** `docs/monotonic-irreversibility.md` - **Canonical evolution path** (350+ lines)
  - Single axis of evolution: local → historical → structural irreversibility awareness
  - v0.2.0 design: monotonic boundary accumulation (not graphs)
  - Correctness ladder: SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE
  - Anti-patterns: what NOT to build (no ML, no prediction, no negotiation)
  - North star: "Chainwatch should never become smarter — only more conservative"
- **Added:** `docs/design/v0.2.0-specification.md` - **Implementation blueprint** (1000+ lines)
  - **Two-stage boundary enforcement architecture** (authority BEFORE execution)
  - Authority boundaries: checked BEFORE instruction admission (prevents chain contamination)
  - Execution boundaries: checked AFTER admission (prevents irreversible actions)
  - Critical ordering: ingress → admission → execution
  - Zone taxonomy: commercial intent, credentials, egress, sensitive data
  - Authority boundary detection: proxy relay, context crossing, temporal violations
  - TraceState schema evolution: irreversibility_level, zones_entered, authority_context
  - Approval workflow design: out-of-band, single-use tokens, model-blind
  - Monotonicity guarantees and testing requirements
  - Clawbot attack prevention proof (integration test requirement)
  - All warnings from irreversible-boundaries.md baked into design
  - **Unified theory: both boundaries ask "Is this transition irreversible?"**
- **Added:** `docs/boundary-configuration.md` - Configuration guide with anti-patterns
- **Added:** `docs/design/v0.2.0-specification.md` → `docs/design/README.md` - Design specification directory
- **Added:** `docs/INDEX.md` - Complete documentation index and reading guide
- **Updated:** `docs/core-idea.md` - Added "Irreversible Boundaries" section
- **Updated:** README - Changed language from "block dangerous actions" to "irreversible boundary protection"
- **Updated:** All user-facing documentation to use boundary framing

### Breaking Changes

**None.** v0.1.2 is 100% backward compatible with v0.1.1.

The YAML file is still `~/.chainwatch/denylist.yaml` (for now).
The Python module is still `denylist.py` (implementation detail).
All APIs unchanged.

What changed: **conceptual framing**.

### Migration from v0.1.1

```bash
pip install --upgrade chainwatch  # v0.1.1 → v0.1.2
# Everything still works. No code changes required.
```

### Why We Did This

v0.1.1 was technically correct but **conceptually undersold**.

Saying "we block checkout URLs" sounds like a security checklist.

Saying "we refuse to cross payment commitment boundaries because they're structurally irreversible" is a **thesis about execution control**.

The former is a feature. The latter is a principle.

Chainwatch is principles-first.

### Evolution Path

**Single axis:** Local → Historical → Structural irreversibility awareness

- **v0.1.x:** Local irreversibility (pattern matching: is this action irreversible?)
- **v0.2.0:** Monotonic boundary accumulation (has chain entered zone where this becomes irreversible?)
- **v0.3.0:** Irreversibility graphs (not execution graphs - nodes are recoverability states)
- **v0.4.0:** Distance-to-boundary signaling (non-enforcing visibility)
- **v1.0.0:** Formal boundary calculus (provable monotonicity properties)

**Correctness ladder:** SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE (one-way only)

See `docs/monotonic-irreversibility.md` for complete evolution design.

### Key Quote from New Docs

> "Chainwatch never asks the model whether an irreversible action is safe.
> If the chain crosses a hard boundary, the system refuses."

This is the line between control plane and observability.

## [0.1.1] - 2026-01-29

### Added
- **Irreversible boundary protection** (`denylist.py`)
  - Hard execution boundaries for actions that cannot be undone
  - Pattern-based detection of structural points of no return
  - Default boundaries prevent:
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
- Added `docs/irreversible-boundaries.md` - **Core concept:** Why boundaries, not blocklists
- Added `examples/denylist_demo.py` - demonstrates boundary protection (checkout, credentials)
- Added `tests/test_denylist.py` - comprehensive unit tests for boundary detection
- Added `docs/v0.1.1-denylist-usage.md` - complete usage guide
- Roadmap documents added:
  - `docs/roadmap-clawbot.md` - Integration strategy with Clawbot and autonomous agents
  - `docs/integrations/browser-checkout-gate.md` - v0.2.0 browser wrapper spec
  - `docs/integrations/clawbot-denylist.md` - Using boundary protection with Clawbot today

### Why This Matters

**v0.1.1 prevents the "$3000 course purchase" incident by treating payment as an irreversible boundary.**

Before v0.1.1:
- Agent could cross from "browsing" to "committed purchase" without intervention
- No structural awareness of irreversibility
- Policy evaluated actions in isolation, not boundary crossings

After v0.1.1:
- Payment commitment recognized as irreversible boundary
- System refuses to cross boundary (hard stop, no negotiation)
- Users can declare their own irreversible boundaries in YAML

This is not a blocklist. This is **irreversibility-aware execution control**.

Chainwatch never asks the model whether an irreversible action is safe.
If the chain crosses a hard boundary, the system refuses.

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

[Unreleased]: https://github.com/ppiankov/chainwatch/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/ppiankov/chainwatch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ppiankov/chainwatch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ppiankov/chainwatch/releases/tag/v0.1.0
