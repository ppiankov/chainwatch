package promptguard

import "context"

// NoopGuard always returns Benign. Used when guard is disabled or unavailable.
type NoopGuard struct{}

func (g *NoopGuard) Classify(_ context.Context, _ string) (Result, error) {
	return Result{Decision: Benign}, nil
}

func (g *NoopGuard) Available() bool {
	return true
}
