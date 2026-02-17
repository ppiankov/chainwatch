package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzVerify(f *testing.F) {
	// Seed with a valid 3-entry chain
	tmpDir := f.TempDir()
	validLog := filepath.Join(tmpDir, "valid.jsonl")
	al, err := Open(validLog)
	if err != nil {
		f.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		al.Record(AuditEntry{
			TraceID:    "t-fuzz",
			Action:     AuditAction{Tool: "command", Resource: "echo hello"},
			Decision:   "allow",
			Tier:       0,
			PolicyHash: "sha256:test",
		})
	}
	al.Close()
	validData, _ := os.ReadFile(validLog)
	f.Add(validData)

	// Empty
	f.Add([]byte{})

	// Single garbage line
	f.Add([]byte(`{"not":"a valid entry"}` + "\n"))

	// Totally invalid
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpFile := filepath.Join(t.TempDir(), "fuzz.jsonl")
		os.WriteFile(tmpFile, data, 0644)

		// Must not panic
		Verify(tmpFile)
	})
}
