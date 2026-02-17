package policy

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
)

func BenchmarkEvaluate_AllowSimple(b *testing.B) {
	cfg := DefaultConfig()
	dl := denylist.NewDefault()
	action := &model.Action{Tool: "command", Resource: "echo hello"}
	state := model.NewTraceState("bench-trace")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Evaluate(action, state, "general", "", dl, cfg)
	}
}

func BenchmarkEvaluate_DenylistHit(b *testing.B) {
	cfg := DefaultConfig()
	dl := denylist.NewDefault()
	action := &model.Action{Tool: "command", Resource: "rm -rf /"}
	state := model.NewTraceState("bench-trace")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Evaluate(action, state, "general", "", dl, cfg)
	}
}

func BenchmarkEvaluate_RulesTraversal(b *testing.B) {
	cfg := DefaultConfig()
	// Add 50 rules to force traversal
	for i := 0; i < 50; i++ {
		cfg.Rules = append(cfg.Rules, Rule{
			Purpose:         "bench_purpose",
			ResourcePattern: "*no_match_pattern*",
			Decision:        "allow",
		})
	}
	dl := denylist.NewDefault()
	action := &model.Action{Tool: "file_read", Resource: "/data/report.csv"}
	state := model.NewTraceState("bench-trace")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Evaluate(action, state, "bench_purpose", "", dl, cfg)
	}
}

func BenchmarkEvaluate_AgentScoped(b *testing.B) {
	cfg := DefaultConfig()
	dl := denylist.NewDefault()
	action := &model.Action{Tool: "command", Resource: "echo test"}
	state := model.NewTraceState("bench-trace")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Evaluate(action, state, "SOC_efficiency", "clawbot-prod", dl, cfg)
	}
}
