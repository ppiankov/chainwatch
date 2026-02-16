package certify

import (
	"strings"
	"testing"
)

func TestLoadSuiteMinimal(t *testing.T) {
	s, err := LoadSuite("minimal")
	if err != nil {
		t.Fatalf("LoadSuite(minimal): %v", err)
	}
	if s.Name != "minimal" {
		t.Errorf("name = %q, want minimal", s.Name)
	}
	if len(s.Categories) == 0 {
		t.Fatal("expected categories, got none")
	}

	total := 0
	for _, cat := range s.Categories {
		total += len(cat.Cases)
	}
	if total != 50 {
		t.Errorf("total cases = %d, want 50", total)
	}
}

func TestLoadSuiteEnterprise(t *testing.T) {
	s, err := LoadSuite("enterprise")
	if err != nil {
		t.Fatalf("LoadSuite(enterprise): %v", err)
	}
	if s.Name != "enterprise" {
		t.Errorf("name = %q, want enterprise", s.Name)
	}

	totalEnterprise := 0
	for _, cat := range s.Categories {
		totalEnterprise += len(cat.Cases)
	}

	// Enterprise must have more cases than minimal
	m, _ := LoadSuite("minimal")
	totalMinimal := 0
	for _, cat := range m.Categories {
		totalMinimal += len(cat.Cases)
	}

	if totalEnterprise <= totalMinimal {
		t.Errorf("enterprise cases (%d) should exceed minimal cases (%d)", totalEnterprise, totalMinimal)
	}
}

func TestListSuites(t *testing.T) {
	suites := ListSuites()
	if len(suites) != 2 {
		t.Fatalf("ListSuites() = %v, want 2 suites", suites)
	}
	// Sorted order
	if suites[0] != "enterprise" || suites[1] != "minimal" {
		t.Errorf("ListSuites() = %v, want [enterprise minimal]", suites)
	}
}

func TestLoadSuiteUnknown(t *testing.T) {
	_, err := LoadSuite("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown suite")
	}
	if !strings.Contains(err.Error(), "unknown certification suite") {
		t.Errorf("error = %q, want 'unknown certification suite'", err.Error())
	}
}

func TestRunClawbotMinimal(t *testing.T) {
	s, err := LoadSuite("minimal")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}

	result, err := Run(s, "clawbot", "", "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Failed > 0 {
		for _, cat := range result.Categories {
			for _, c := range cat.Cases {
				if !c.Passed {
					t.Errorf("[%s] case %d: %s %s — expected %s, got %s (%s)",
						cat.Name, c.Index, c.Tool, c.Resource, c.Expected, c.Actual, c.Reason)
				}
			}
		}
		t.Fatalf("clawbot failed minimal: %d/%d passed", result.Passed, result.Total)
	}
}

func TestRunClawbotEnterprise(t *testing.T) {
	s, err := LoadSuite("enterprise")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}

	result, err := Run(s, "clawbot", "", "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.Failed > 0 {
		for _, cat := range result.Categories {
			for _, c := range cat.Cases {
				if !c.Passed {
					t.Errorf("[%s] case %d: %s %s — expected %s, got %s (%s)",
						cat.Name, c.Index, c.Tool, c.Resource, c.Expected, c.Actual, c.Reason)
				}
			}
		}
		t.Fatalf("clawbot failed enterprise: %d/%d passed", result.Passed, result.Total)
	}
}

func TestRunPermissiveProfileFails(t *testing.T) {
	s, err := LoadSuite("minimal")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}

	// coding-agent has fewer restrictions — should fail some deny cases
	result, err := Run(s, "coding-agent", "", "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The credential_protection category includes password-pattern cases
	// that rely on clawbot's policy rule. coding-agent won't have that rule.
	if result.Failed == 0 {
		t.Error("expected coding-agent to fail some certification cases")
	}
}

func TestCategoryResultFields(t *testing.T) {
	s, err := LoadSuite("minimal")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}

	result, err := Run(s, "clawbot", "", "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, cat := range result.Categories {
		if cat.Name == "" {
			t.Error("category name is empty")
		}
		if cat.Total == 0 {
			t.Errorf("category %q has 0 total cases", cat.Name)
		}
		if cat.Passed+cat.Failed != cat.Total {
			t.Errorf("category %q: passed(%d) + failed(%d) != total(%d)",
				cat.Name, cat.Passed, cat.Failed, cat.Total)
		}
		if len(cat.Cases) != cat.Total {
			t.Errorf("category %q: len(Cases)=%d != total=%d", cat.Name, len(cat.Cases), cat.Total)
		}
	}
}

func TestFormatTextPassFail(t *testing.T) {
	s, err := LoadSuite("minimal")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}

	result, err := Run(s, "clawbot", "", "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	text := FormatText(result)

	if !strings.Contains(text, "PASS") {
		t.Error("FormatText output missing PASS marker")
	}
	if !strings.Contains(text, "Certification:") {
		t.Error("FormatText output missing Certification header")
	}
	if !strings.Contains(text, "clawbot") {
		t.Error("FormatText output missing profile name")
	}
	if !strings.Contains(text, "Result:") {
		t.Error("FormatText output missing Result line")
	}
}

func TestFormatJSON(t *testing.T) {
	s, err := LoadSuite("minimal")
	if err != nil {
		t.Fatalf("LoadSuite: %v", err)
	}

	result, err := Run(s, "clawbot", "", "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	jsonStr, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}

	if !strings.Contains(jsonStr, `"suite": "minimal"`) {
		t.Error("JSON output missing suite field")
	}
	if !strings.Contains(jsonStr, `"profile": "clawbot"`) {
		t.Error("JSON output missing profile field")
	}
}
