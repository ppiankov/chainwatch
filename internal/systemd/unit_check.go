package systemd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// UnitFilePaths are the paths checked for the nullbot daemon unit file.
var UnitFilePaths = []string{
	"/etc/systemd/system/nullbot-daemon.service",
	"/etc/systemd/system/nullbot.service",
}

// UnitHashPath is where the install-time hash of the unit file is stored.
var UnitHashPath = "/home/nullbot/state/unit-file.sha256"

// CheckUnitFileIntegrity compares the current unit file hash against the
// stored install-time hash. Returns a warning message if the unit file
// has been modified, or empty string if integrity is confirmed or
// checking is not applicable (no unit file or no stored hash).
func CheckUnitFileIntegrity() string {
	// Find the unit file.
	var unitPath string
	for _, p := range UnitFilePaths {
		if _, err := os.Stat(p); err == nil {
			unitPath = p
			break
		}
	}
	if unitPath == "" {
		return "" // Not running under systemd or unit file not found.
	}

	// Read stored hash.
	stored, err := os.ReadFile(UnitHashPath)
	if err != nil {
		return "" // No stored hash — first install or non-systemd environment.
	}
	expectedHash := strings.TrimSpace(string(stored))
	if len(expectedHash) != 64 {
		return "" // Invalid stored hash.
	}

	// Hash the current unit file.
	data, err := os.ReadFile(unitPath)
	if err != nil {
		return fmt.Sprintf("cannot read unit file %s: %v", unitPath, err)
	}
	h := sha256.Sum256(data)
	actualHash := hex.EncodeToString(h[:])

	if actualHash == expectedHash {
		return ""
	}

	return fmt.Sprintf("systemd unit file %s has been modified since installation (expected %s, got %s)",
		unitPath, expectedHash[:16], actualHash[:16])
}

// RecordUnitFileHash writes the SHA-256 hash of the unit file to UnitHashPath.
// Called during installation to record the baseline.
func RecordUnitFileHash() error {
	for _, p := range UnitFilePaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		h := sha256.Sum256(data)
		hash := hex.EncodeToString(h[:])
		return os.WriteFile(UnitHashPath, []byte(hash+"\n"), 0600)
	}
	return fmt.Errorf("no unit file found at expected paths")
}
