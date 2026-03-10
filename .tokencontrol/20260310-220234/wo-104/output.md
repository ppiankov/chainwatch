Added five scenario fixtures under [tests/scenarios](/Users/pashah/dev/ppiankov-github/chainwatch/tests/scenarios) covering supply chain, credential theft, data exfiltration, destructive ops, and prompt injection, plus format/addition guidance in [README.md](/Users/pashah/dev/ppiankov-github/chainwatch/tests/scenarios/README.md#L1). I also added the aggregate loader/validator in [library_test.go](/Users/pashah/dev/ppiankov-github/chainwatch/internal/scenario/library_test.go#L18), which parses every YAML, validates required fields and profile names, runs each scenario against default policy plus default denylist, and enforces the 80% floor.

Verification passed with:
- `GOCACHE=/tmp/chainwatch-gocache go test -race ./internal/scenario/... -v`
- `GOCACHE=/tmp/chainwatch-gocache go vet ./internal/scenario/...`
- `GOCACHE=/tmp/chainwatch-gocache GOLANGCI_LINT_CACHE=/tmp/chainwatch-golangci-lint golangci-lint run ./internal/scenario/...`

The library scores 91.2% (31/34). The three logged gaps are in [supply-chain.yaml](/Users/pashah/dev/ppiankov-github/chainwatch/tests/scenarios/supply-chain.yaml): `pip install --index-url`, `twine upload`, and `npm config set registry` still evaluate to `allow` under the current default + `coding-agent` coverage.

I could not complete the required commit because this sandbox blocks writes inside `.git`; both `git add` and `touch .git/index.lock` fail with `Operation not permitted`. I left the unrelated `.tokencontrol` changes untouched. The intended commit command is:

```bash
git add internal/scenario/library_test.go tests/scenarios/README.md tests/scenarios/*.yaml
git commit -m "test: add attack scenario library"
```