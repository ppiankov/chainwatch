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

.PHONY: go-all
go-all: go-fmt go-lint go-test go-build ## Run Go fmt, lint, test, build
