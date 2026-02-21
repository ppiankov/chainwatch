package systemd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckUnitFileIntegrityNoUnitFile(t *testing.T) {
	old := UnitFilePaths
	UnitFilePaths = []string{"/nonexistent/path.service"}
	defer func() { UnitFilePaths = old }()

	msg := CheckUnitFileIntegrity()
	if msg != "" {
		t.Errorf("expected empty message when no unit file, got %q", msg)
	}
}

func TestCheckUnitFileIntegrityNoStoredHash(t *testing.T) {
	tmpDir := t.TempDir()
	unitFile := filepath.Join(tmpDir, "test.service")
	os.WriteFile(unitFile, []byte("[Unit]\nDescription=test\n"), 0644)

	old := UnitFilePaths
	oldHash := UnitHashPath
	UnitFilePaths = []string{unitFile}
	UnitHashPath = filepath.Join(tmpDir, "unit-file.sha256")
	defer func() {
		UnitFilePaths = old
		UnitHashPath = oldHash
	}()

	msg := CheckUnitFileIntegrity()
	if msg != "" {
		t.Errorf("expected empty message when no stored hash, got %q", msg)
	}
}

func TestCheckUnitFileIntegrityMatch(t *testing.T) {
	tmpDir := t.TempDir()
	content := []byte("[Unit]\nDescription=test\n")
	unitFile := filepath.Join(tmpDir, "test.service")
	os.WriteFile(unitFile, content, 0644)

	h := sha256.Sum256(content)
	hash := hex.EncodeToString(h[:])
	hashFile := filepath.Join(tmpDir, "unit-file.sha256")
	os.WriteFile(hashFile, []byte(hash+"\n"), 0600)

	old := UnitFilePaths
	oldHash := UnitHashPath
	UnitFilePaths = []string{unitFile}
	UnitHashPath = hashFile
	defer func() {
		UnitFilePaths = old
		UnitHashPath = oldHash
	}()

	msg := CheckUnitFileIntegrity()
	if msg != "" {
		t.Errorf("expected empty message for matching hash, got %q", msg)
	}
}

func TestCheckUnitFileIntegrityMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	unitFile := filepath.Join(tmpDir, "test.service")
	os.WriteFile(unitFile, []byte("[Unit]\nDescription=modified\n"), 0644)

	hashFile := filepath.Join(tmpDir, "unit-file.sha256")
	os.WriteFile(hashFile, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0600)

	old := UnitFilePaths
	oldHash := UnitHashPath
	UnitFilePaths = []string{unitFile}
	UnitHashPath = hashFile
	defer func() {
		UnitFilePaths = old
		UnitHashPath = oldHash
	}()

	msg := CheckUnitFileIntegrity()
	if msg == "" {
		t.Fatal("expected warning for modified unit file, got empty")
	}
	if !strings.Contains(msg, "modified since installation") {
		t.Errorf("expected modification warning, got %q", msg)
	}
}

func TestRecordUnitFileHash(t *testing.T) {
	tmpDir := t.TempDir()
	content := []byte("[Unit]\nDescription=test\n")
	unitFile := filepath.Join(tmpDir, "test.service")
	os.WriteFile(unitFile, content, 0644)

	hashFile := filepath.Join(tmpDir, "unit-file.sha256")

	old := UnitFilePaths
	oldHash := UnitHashPath
	UnitFilePaths = []string{unitFile}
	UnitHashPath = hashFile
	defer func() {
		UnitFilePaths = old
		UnitHashPath = oldHash
	}()

	if err := RecordUnitFileHash(); err != nil {
		t.Fatalf("RecordUnitFileHash: %v", err)
	}

	data, err := os.ReadFile(hashFile)
	if err != nil {
		t.Fatalf("read hash file: %v", err)
	}

	h := sha256.Sum256(content)
	expected := hex.EncodeToString(h[:])
	got := strings.TrimSpace(string(data))
	if got != expected {
		t.Errorf("hash = %s, want %s", got, expected)
	}
}

func TestRecordUnitFileHashNoUnit(t *testing.T) {
	old := UnitFilePaths
	UnitFilePaths = []string{"/nonexistent/path.service"}
	defer func() { UnitFilePaths = old }()

	err := RecordUnitFileHash()
	if err == nil {
		t.Error("expected error when no unit file exists")
	}
}
