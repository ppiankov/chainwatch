package orchestrator

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/ppiankov/chainwatch/internal/observe"
)

// VerifyAndTransition records the applied -> verified transition when drift verification passes.
func VerifyAndTransition(
	ctx context.Context,
	store *LifecycleStore,
	woID string,
	verifyResult *observe.VerifyResult,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("lifecycle store is nil")
	}

	trimmedWOID := strings.TrimSpace(woID)
	if trimmedWOID == "" {
		return fmt.Errorf("work order ID is required")
	}
	if verifyResult == nil {
		return fmt.Errorf("verify result is required")
	}
	if !verifyResult.Passed {
		log.Printf(
			"orchestrator verify: work order %s remains in %s: %s",
			trimmedWOID,
			LifecycleStateApplied,
			verifyResult.Detail,
		)
		return nil
	}

	return store.RecordTransition(LifecycleTransition{
		WOID:    trimmedWOID,
		ToState: LifecycleStateVerified,
	})
}
