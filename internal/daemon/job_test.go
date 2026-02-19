package daemon

import (
	"testing"
	"time"
)

func validJob() *Job {
	return &Job{
		ID:   "job-abc123",
		Type: JobTypeInvestigate,
		Target: JobTarget{
			Host:  "example.com",
			Scope: "/var/www/site",
		},
		Brief:     "website redirects to casino domain",
		Source:    "manual",
		CreatedAt: time.Now().UTC(),
	}
}

func TestValidateJobValid(t *testing.T) {
	if err := ValidateJob(validJob()); err != nil {
		t.Errorf("valid job should pass: %v", err)
	}
}

func TestValidateJobObserveType(t *testing.T) {
	j := validJob()
	j.Type = JobTypeObserve
	if err := ValidateJob(j); err != nil {
		t.Errorf("observe type should be valid: %v", err)
	}
}

func TestValidateJobMissingID(t *testing.T) {
	j := validJob()
	j.ID = ""
	if err := ValidateJob(j); err == nil {
		t.Error("expected error for missing ID")
	}
}

func TestValidateJobMissingType(t *testing.T) {
	j := validJob()
	j.Type = ""
	if err := ValidateJob(j); err == nil {
		t.Error("expected error for missing type")
	}
}

func TestValidateJobInvalidType(t *testing.T) {
	j := validJob()
	j.Type = "remediate"
	if err := ValidateJob(j); err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestValidateJobPathTraversalID(t *testing.T) {
	for _, id := range []string{"../etc/passwd", "job-..foo", "job/../../bad"} {
		j := validJob()
		j.ID = id
		if err := ValidateJob(j); err == nil {
			t.Errorf("expected error for path traversal ID %q", id)
		}
	}
}

func TestValidateJobInvalidIDChars(t *testing.T) {
	for _, id := range []string{"job abc", "job@123", "job;cmd"} {
		j := validJob()
		j.ID = id
		if err := ValidateJob(j); err == nil {
			t.Errorf("expected error for invalid ID chars %q", id)
		}
	}
}

func TestValidateJobEmptyScope(t *testing.T) {
	j := validJob()
	j.Target.Scope = ""
	if err := ValidateJob(j); err == nil {
		t.Error("expected error for empty scope")
	}
}

func TestValidateJobEmptyBrief(t *testing.T) {
	j := validJob()
	j.Brief = ""
	if err := ValidateJob(j); err == nil {
		t.Error("expected error for empty brief")
	}
}

func TestValidateJobEmptyHostAllowed(t *testing.T) {
	j := validJob()
	j.Target.Host = ""
	if err := ValidateJob(j); err != nil {
		t.Errorf("empty host should be allowed (local investigation): %v", err)
	}
}
