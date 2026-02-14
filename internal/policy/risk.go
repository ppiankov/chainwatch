package policy

import "github.com/ppiankov/chainwatch/internal/model"

// riskScore computes a deterministic, explainable risk score.
// This is NOT anomaly detection — it is cumulative scoring based on semantics.
func riskScore(meta model.ResultMeta, state *model.TraceState, isNewSource bool, cfg *PolicyConfig) int {
	risk := 0

	// Sensitivity dominates.
	risk += cfg.SensitivityWeights.WeightFor(meta.Sensitivity)

	// Volume escalation.
	if meta.Rows > 1_000 {
		risk += 3
	}
	if meta.Rows > 10_000 {
		risk += 6
	}

	// New source in the chain increases uncertainty.
	if isNewSource {
		risk += 2
	}

	// External egress is always expensive.
	if meta.Egress == model.EgressExternal {
		risk += 6
	}

	return risk
}
