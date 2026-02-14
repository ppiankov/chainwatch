package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/enforce"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

func init() {
	rootCmd.AddCommand(demoCmd)
}

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run demonstration scenarios",
}

func init() {
	demoCmd.AddCommand(socCmd)
}

var socCmd = &cobra.Command{
	Use:   "soc",
	Short: "Run SOC efficiency demo (salary must be blocked)",
	RunE:  runSOCDemo,
}

func runSOCDemo(cmd *cobra.Command, args []string) error {
	fmt.Println("=== chainwatch SOC Efficiency Demo ===")
	fmt.Println("Purpose: Prove enforcement is a control plane, not observability.")
	fmt.Println()

	// Create temp files
	tmpDir, err := os.MkdirTemp("", "chainwatch-demo-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	files := map[string]struct {
		content     string
		sensitivity model.Sensitivity
	}{
		"org_chart.txt":       {"Engineering: Alice, Bob, Carol\nManagement: Dave, Eve", model.SensLow},
		"siem_incidents.json": {`[{"id":1,"type":"phishing","status":"resolved"}]`, model.SensMedium},
		"hr_employees.csv":    {"name,department,role\nAlice,Engineering,SRE\nBob,SOC,Analyst", model.SensHigh},
		"hr_salary_bands.csv": {"name,salary,bonus\nAlice,150000,10000\nBob,120000,8000", model.SensHigh},
	}

	for name, f := range files {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte(f.content), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
		_ = f
	}

	// Set up tracer, denylist, and policy config
	acc := tracer.NewAccumulator(tracer.NewTraceID())
	dl := denylist.NewDefault()
	policyCfg, err := policy.LoadConfig("")
	if err != nil {
		return fmt.Errorf("failed to load policy config: %w", err)
	}

	actor := map[string]any{
		"user_id":  "analyst1",
		"agent_id": "soc_agent",
	}
	purpose := "SOC_efficiency"

	salaryBlocked := false
	results := []map[string]any{}

	// Attempt to read each file
	fileOrder := []string{"org_chart.txt", "siem_incidents.json", "hr_employees.csv", "hr_salary_bands.csv"}

	for _, name := range fileOrder {
		path := filepath.Join(tmpDir, name)
		action := buildFileAction(path, name)

		// Evaluate policy
		result := policy.Evaluate(action, acc.State, purpose, dl, policyCfg)

		// Record event
		acc.RecordAction(actor, purpose, action, map[string]any{
			"result":       string(result.Decision),
			"reason":       result.Reason,
			"policy_id":    result.PolicyID,
			"approval_key": result.ApprovalKey,
		}, "")

		// Try enforcement
		var status string
		content, err := os.ReadFile(path)
		if err != nil {
			status = "error"
		} else {
			_, enforceErr := enforce.Enforce(result, string(content))
			if enforceErr != nil {
				status = "BLOCKED"
				if name == "hr_salary_bands.csv" {
					salaryBlocked = true
				}
			} else {
				status = "allowed"
			}
		}

		icon := "✓"
		if status == "BLOCKED" {
			icon = "✗"
		}
		fmt.Printf("  %s %s → %s (%s)\n", icon, name, status, result.Decision)

		results = append(results, map[string]any{
			"file":     name,
			"decision": string(result.Decision),
			"reason":   result.Reason,
			"status":   status,
		})
	}

	fmt.Println()

	// Output trace summary
	trace := acc.ToJSON()
	traceJSON, _ := json.MarshalIndent(trace, "", "  ")
	fmt.Println("Trace summary:")
	fmt.Println(string(traceJSON))
	fmt.Println()

	// CI gate: salary MUST be blocked
	if !salaryBlocked {
		fmt.Println("FAIL: Salary access was NOT blocked. This is a control plane failure.")
		os.Exit(1)
	}

	fmt.Println("PASS: Salary access blocked. Enforcement verified.")
	return nil
}

func buildFileAction(filepath, name string) *model.Action {
	sensitivity := model.SensLow
	var tags []string

	lower := filepath + name
	if containsAny(lower, "hr", "employee", "salary", "payroll") {
		sensitivity = model.SensHigh
		tags = append(tags, "HR")
	} else if containsAny(lower, "siem", "incident", "security") {
		sensitivity = model.SensMedium
		tags = append(tags, "security")
	}

	return &model.Action{
		Tool:      "file_read",
		Resource:  filepath,
		Operation: "read",
		Params:    map[string]any{"path": filepath},
		RawMeta: map[string]any{
			"sensitivity": string(sensitivity),
			"tags":        toAnySlice(tags),
			"bytes":       0,
			"rows":        0,
			"egress":      "internal",
			"destination": "localhost",
		},
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func toAnySlice(ss []string) []any {
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}
