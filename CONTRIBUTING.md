# Contributing to Chainwatch

If your change does not increase runtime control, it will be rejected.

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ppiankov/chainwatch.git
   cd chainwatch
   ```

2. Install in development mode:
   ```bash
   make install
   # or: pip install -e ".[dev]"
   ```

3. Verify installation:
   ```bash
   make test
   ```

## Project Structure

```
chainwatch/
├── src/chainwatch/          # Core library
│   ├── types.py            # Data models (Action, TraceState, PolicyResult)
│   ├── policy.py           # Deterministic policy evaluation
│   ├── tracer.py           # TraceAccumulator, Event schema
│   ├── enforcement.py      # Decision enforcement (allow/deny/redact)
│   ├── redaction.py        # PII redaction utilities
│   ├── wrappers/           # Integration adapters
│   │   └── file_ops.py    # File operation interceptor
│   └── cli.py             # CLI entrypoint
├── tests/                  # Unit and integration tests
├── examples/               # Runnable demos
└── docs/                   # Design docs
```

## How to Contribute

### Development Rules

1. **Enforcement > Detection**: If it doesn't block or modify execution, it's out of scope.
2. **Deterministic > Probabilistic**: No ML in the core. Policies must be explainable.
3. **Connectors are sloppy, core is clean**: All normalization happens in `Action.normalize_meta()`.
4. **Tests are mandatory**: No PRs without tests for new code.

### Workflow

1. Create a branch:
   ```bash
   git checkout -b feature/your-feature
   ```

2. Make changes and ensure quality:
   ```bash
   make fmt        # Format code
   make lint       # Check for issues
   make test       # Run tests
   ```

3. Commit with clear messages (see Commit Messages below)

4. Push and open a PR with:
   - What changed
   - Why it changed
   - How you tested it

### Testing

Run all tests:
```bash
make test
```

Run with coverage:
```bash
make test-coverage
# View report: open htmlcov/index.html
```

Tests must:
- Cover new functionality (aim for >85% coverage)
- Pass on Python 3.10+
- Be deterministic (no random data, no time-dependent assertions)
- Use pytest fixtures for setup/teardown

### Code Style

- **Black** (line length: 100)
- **Ruff** for linting
- Type hints encouraged but not required yet
- Docstrings for public APIs

Run formatters:
```bash
make fmt
```

Check without modifying:
```bash
make check-fmt
```

### Commit Messages

Follow conventional commits format:
- `feat:` new functionality
- `fix:` bug fixes
- `docs:` documentation only
- `test:` test additions/changes
- `refactor:` code changes without behavior changes
- `chore:` build, CI, dependencies

Examples:
```
feat: add HTTP proxy wrapper for network interception
fix: handle empty resource field in Action normalization
docs: clarify connector contract in integrations/README.md
test: add integration test for FileGuard with CSV files
```

### Adding New Wrappers

If you're adding a new integration (e.g., HTTP proxy, database client):

1. Create `src/chainwatch/wrappers/your_wrapper.py`
2. Implement context manager pattern (like `FileGuard`)
3. Map operations to `Action` with proper `ResultMeta`
4. Call `action.normalize_meta()` before policy evaluation
5. Add integration test in `tests/integration/test_your_wrapper.py`
6. Document in `docs/integrations/your-wrapper.md`
7. Add decision record in `docs/decisions/NNN-your-integration.md`

### Adding Policy Rules

For v0.1.0, policies are hardcoded in `src/chainwatch/policy.py`.

If adding a new rule:
1. Add to `evaluate()` function with clear comment
2. Include risk score calculation rationale
3. Add unit tests in `tests/test_policy.py`
4. Document in CHANGELOG.md under Added > Policy engine

For v0.2.0, we'll add YAML-based policy DSL.

### Documentation

When adding features:
- Update CHANGELOG.md (add to [Unreleased])
- Add/update relevant docs in docs/
- Include code examples in docs/getting-started.md if user-facing
- Update README.md if it affects Quick Start or Usage

## Questions?

Open an issue or discussion on GitHub.
