# chainwatch

Runtime control plane for AI agent safety. Intercepts tool calls at irreversible boundaries — payments, credentials, data destruction, external communication. Enforcement, not observability.

## What This Is

Python library + CLI that wraps agent tool invocations, evaluates deterministic policy, and enforces decisions (allow, deny, redact, require-approval) at boundaries agents cannot bypass.

## What This Is NOT

- Not an ML-based anomaly detector
- Not a logging/observability layer (enforcement > detection)
- Not an LLM guardrail for prompt content
- Not a permissions system (it enforces boundaries, not roles)

## Commands

- `make test` — Run pytest with coverage (-x, --tb=short)
- `make lint` — Run ruff
- `make fmt` — Format with black (100 chars)
- `make run-demo` — SOC demo (must block salary access or fails)
- `make run-realistic-demo` — Full agent loop demo
- `make setup-test-data` — Create test data for demos

## Architecture

- Source: `src/chainwatch/`
- Core: types.py (dataclasses), tracer.py (event accumulation), policy.py (risk scoring), enforcement.py (decision application), denylist.py (hard boundaries)
- Wrappers: `wrappers/file_ops.py` (FileGuard — monkey-patches builtins.open)
- Tests: `tests/` (unit + integration)
- Docs: `docs/` (design, security classes, integration strategies)

## Key Concepts

- **Irreversible boundaries**: payment, credential, destruction, external comms — hard block, no approval
- **Monotonic irreversibility**: SAFE → SENSITIVE → COMMITMENT → IRREVERSIBLE (one-way only)
- **Deterministic policy**: explicit weights (sensitivity 1-6, volume +3/+6, egress +6), human-editable thresholds
- **Denylist**: pattern-based hard blocks (URLs, files, commands) loaded from YAML

## Code Style

- Python: Black (100 chars), Ruff, dataclasses not Pydantic, type hints, pytest
- Comments explain "why" not "what"
- No ML/probabilistic approaches — all decisions must be deterministic and explainable

## Testing

- `make test` (pytest, -x, --tb=short)
- Demo gate in CI: salary MUST be blocked or CI fails
- Coverage target: >85%

## Anti-Patterns

- NEVER use ML or statistical models for safety decisions
- NEVER allow the model to decide whether to cross irreversible boundaries
- NEVER add "warn mode" that allows irreversible actions through
- NEVER store credentials or sensitive data in traces
- NEVER add LLM-based content analysis
- NEVER bypass denylist patterns with approval workflows
