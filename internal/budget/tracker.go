package budget

import (
	"time"

	"github.com/ppiankov/chainwatch/internal/model"
)

// Usage captures the current session consumption snapshot.
type Usage struct {
	Bytes    int64
	Rows     int64
	Duration time.Duration
}

// Snapshot reads current usage from TraceState.
func Snapshot(state *model.TraceState) Usage {
	return Usage{
		Bytes:    int64(state.VolumeBytes),
		Rows:     int64(state.VolumeRows),
		Duration: time.Since(state.StartedAt),
	}
}
