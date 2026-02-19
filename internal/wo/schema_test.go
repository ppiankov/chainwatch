package wo

import "testing"

func TestIsValidType(t *testing.T) {
	valid := []ObservationType{
		FileHashMismatch, RedirectDetected, UnauthorizedUser,
		SuspiciousCode, ConfigModified, UnknownFile,
		PermissionAnomaly, CronAnomaly, ProcessAnomaly, NetworkAnomaly,
	}
	for _, typ := range valid {
		if !IsValidType(typ) {
			t.Errorf("expected %q to be valid", typ)
		}
	}

	invalid := []ObservationType{"", "bogus", "File_hash_mismatch", "CRON_ANOMALY"}
	for _, typ := range invalid {
		if IsValidType(typ) {
			t.Errorf("expected %q to be invalid", typ)
		}
	}
}

func TestIsValidSeverity(t *testing.T) {
	valid := []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, s := range valid {
		if !IsValidSeverity(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}

	invalid := []Severity{"", "urgent", "LOW", "info"}
	for _, s := range invalid {
		if IsValidSeverity(s) {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}
