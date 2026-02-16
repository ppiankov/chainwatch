//go:build dogfight

package dogfight

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// binaryPath is the compiled chainwatch binary, built once in TestMain.
var binaryPath string

func TestMain(m *testing.M) {
	root := findRepoRoot()

	tmpDir, err := os.MkdirTemp("", "dogfight-bin-*")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "chainwatch")
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/chainwatch")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("failed to build chainwatch binary: " + err.Error())
	}

	os.Exit(m.Run())
}
