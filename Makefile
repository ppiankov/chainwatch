.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: install
install: ## Install package in development mode
	pip install -e ".[dev]"

.PHONY: build
build: ## Build package
	python -m build

.PHONY: test
test: ## Run tests
	pytest tests/ -v

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	pytest tests/ -v --cov=src/chainwatch --cov-report=term --cov-report=html

.PHONY: fmt
fmt: ## Format code with black
	black src/ tests/ examples/

.PHONY: lint
lint: ## Run linters (ruff)
	ruff check src/ tests/ examples/

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info htmlcov/ .coverage .pytest_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

.PHONY: run-demo
run-demo: ## Run the basic SOC efficiency demo
	python examples/soc_efficiency_demo.py

.PHONY: run-realistic-demo
run-realistic-demo: ## Run realistic agent demo with test data
	python examples/realistic_agent_demo.py

.PHONY: setup-test-data
setup-test-data: ## Create corporate test data
	python examples/test_data/setup_corporate_data.py corporate_test_data

.PHONY: all
all: fmt lint test ## Run fmt, lint, and test

.PHONY: check-fmt
check-fmt: ## Check if code is formatted (CI mode)
	black --check src/ tests/ examples/

# ── Go targets ──────────────────────────────────────────

.PHONY: go-build
go-build: ## Build Go binary
	go build -o bin/chainwatch ./cmd/chainwatch

.PHONY: go-test
go-test: ## Run Go tests with race detection
	go test -race -v ./internal/...

.PHONY: go-lint
go-lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: go-fmt
go-fmt: ## Format Go code
	gofmt -w cmd/ internal/

.PHONY: go-demo
go-demo: ## Run Go SOC demo (salary must be blocked)
	go run ./cmd/chainwatch demo soc

.PHONY: go-proxy
go-proxy: ## Start chainwatch HTTP proxy on port 8888
	go run ./cmd/chainwatch proxy --port 8888

.PHONY: go-exec
go-exec: ## Run a command through chainwatch guard
	go run ./cmd/chainwatch exec -- echo "chainwatch exec works"

.PHONY: go-init-policy
go-init-policy: ## Generate default policy.yaml
	go run ./cmd/chainwatch init-policy

.PHONY: go-apply-profile
go-apply-profile: ## Show clawbot safety profile patterns
	go run ./cmd/chainwatch profile apply clawbot

.PHONY: go-pending
go-pending: ## List pending approval requests
	go run ./cmd/chainwatch pending

.PHONY: go-root-monitor
go-root-monitor: ## Start root monitor for a PID (Linux only)
	go run ./cmd/chainwatch root-monitor --pid $(PID) --profile clawbot

.PHONY: go-mcp
go-mcp: ## Start MCP tool server (stdio)
	go run ./cmd/chainwatch mcp --profile clawbot

.PHONY: go-break-glass
go-break-glass: ## Issue a break-glass emergency override token
	go run ./cmd/chainwatch break-glass --reason "$(REASON)" --duration $(or $(DURATION),10m)

.PHONY: go-break-glass-list
go-break-glass-list: ## List all break-glass tokens
	go run ./cmd/chainwatch break-glass list

.PHONY: go-replay
go-replay: ## Replay a session from the audit log
	go run ./cmd/chainwatch replay $(TRACE_ID) --log $(AUDIT_LOG) $(if $(FORMAT),--format $(FORMAT))

.PHONY: go-intercept
go-intercept: ## Start chainwatch LLM response interceptor on port 9999
	go run ./cmd/chainwatch intercept --port 9999

.PHONY: go-audit-verify
go-audit-verify: ## Verify audit log integrity
	go run ./cmd/chainwatch audit verify $(AUDIT_LOG)

.PHONY: go-all
go-all: go-fmt go-lint go-test go-build ## Run Go fmt, lint, test, build

# ── Python SDK targets ─────────────────────────────────

.PHONY: sdk-python-test
sdk-python-test: ## Run Python SDK tests
	pytest sdk/python/tests/ -v

.PHONY: sdk-python-lint
sdk-python-lint: ## Lint Python SDK
	ruff check sdk/python/

.PHONY: sdk-python-fmt
sdk-python-fmt: ## Format Python SDK
	black sdk/python/

# ── Go SDK targets ────────────────────────────────────

.PHONY: sdk-go-test
sdk-go-test: ## Run Go SDK tests with race detection
	go test -race -v ./sdk/go/chainwatch/

.PHONY: sdk-go-lint
sdk-go-lint: ## Lint Go SDK
	golangci-lint run ./sdk/go/...
