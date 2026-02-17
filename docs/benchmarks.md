# Benchmarks

Baselines captured on Apple M2 Max. Run `make bench` to reproduce.

## Policy Evaluation

| Benchmark | Time | Allocations |
|-----------|------|-------------|
| `Evaluate_AllowSimple` | ~5 us/op | 11 allocs |
| `Evaluate_DenylistHit` | ~0.4 us/op | 5 allocs |
| `Evaluate_RulesTraversal` (50 rules) | ~5.8 us/op | 11 allocs |
| `Evaluate_AgentScoped` | ~2.4 us/op | 7 allocs |

Denylist hits short-circuit before rule traversal (0.4us vs 5us).

## Denylist Matching

| Benchmark | Time | Allocations |
|-----------|------|-------------|
| `IsBlocked_NoMatch` | ~4.7 us/op | 0 allocs |
| `IsBlocked_Match` | ~0.2 us/op | 0 allocs |
| `IsBlocked_PipeToShell` | ~1 us/op | 0 allocs |
| `IsBlocked_LargeDenylist` (1000 patterns) | ~7.4 us/op | 0 allocs |

Zero allocation on all denylist paths. Compiled regex patterns.

## Audit Log

| Benchmark | Time | Allocations |
|-----------|------|-------------|
| `Record_Single` | ~5 ms/op | — |
| `Record_Sequential100` | ~544 ms/op | — |
| `Verify_1000` | ~3.4 ms/op | — |
| `Verify_10000` | ~30 ms/op | — |

Record latency dominated by fsync (append-only guarantee). Verification is linear in entry count.

## Running Benchmarks

```bash
make bench
```

Or individual packages:

```bash
go test -bench=. -benchmem ./internal/policy/
go test -bench=. -benchmem ./internal/denylist/
go test -bench=. -benchmem ./internal/audit/
```
