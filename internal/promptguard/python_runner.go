package promptguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// PythonRunner classifies text by calling classify.py as a subprocess.
type PythonRunner struct {
	cfg Config
}

// NewPythonRunner creates a PythonRunner from the given config.
func NewPythonRunner(cfg Config) *PythonRunner {
	return &PythonRunner{cfg: cfg}
}

type classifyRequest struct {
	Text  string `json:"text"`
	Model string `json:"model,omitempty"`
}

type classifyResponse struct {
	Decision string  `json:"decision"`
	Score    float64 `json:"score"`
	Model    string  `json:"model,omitempty"`
	Error    string  `json:"error,omitempty"`
}

func (r *PythonRunner) scriptPath() string {
	if r.cfg.ScriptPath != "" {
		return r.cfg.ScriptPath
	}
	// Default: scripts/promptguard/classify.py relative to the binary.
	// In practice, users set script_path or it lives in the repo root.
	return filepath.Join("scripts", "promptguard", "classify.py")
}

func (r *PythonRunner) pythonBin() string {
	if r.cfg.Python != "" {
		return r.cfg.Python
	}
	return "python3"
}

// Classify sends text to the Python classifier and returns the result.
func (r *PythonRunner) Classify(ctx context.Context, text string) (Result, error) {
	if !r.Available() {
		return Result{Decision: Unavailable, Error: "python or script not available"}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	req := classifyRequest{
		Text:  text,
		Model: r.cfg.Model,
	}
	input, err := json.Marshal(req)
	if err != nil {
		return Result{Decision: Unavailable, Error: err.Error()}, nil
	}

	cmd := exec.CommandContext(ctx, r.pythonBin(), r.scriptPath())
	cmd.Stdin = bytes.NewReader(input)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Context timeout or python failure — not an error, just unavailable.
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return Result{Decision: Unavailable, Error: fmt.Sprintf("classify failed: %s", errMsg)}, nil
	}

	var resp classifyResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return Result{Decision: Unavailable, Error: fmt.Sprintf("invalid response: %s", err)}, nil
	}

	if resp.Error != "" {
		return Result{Decision: Unavailable, Error: resp.Error}, nil
	}

	decision := Decision(strings.ToLower(resp.Decision))
	switch decision {
	case Benign, Malicious:
		return Result{Decision: decision, Score: resp.Score, Model: resp.Model}, nil
	default:
		return Result{Decision: Unavailable, Error: fmt.Sprintf("unknown decision: %s", resp.Decision)}, nil
	}
}

// Available checks whether the python binary exists on the system.
func (r *PythonRunner) Available() bool {
	_, err := exec.LookPath(r.pythonBin())
	if err != nil {
		return false
	}
	// On non-Windows, also check the script exists.
	if runtime.GOOS != "windows" {
		script := r.scriptPath()
		cmd := exec.Command("test", "-f", script)
		return cmd.Run() == nil
	}
	return true
}
