package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ppiankov/chainwatch/internal/observe"
	"github.com/ppiankov/chainwatch/internal/redact"
	"github.com/ppiankov/chainwatch/internal/wo"
)

// ProcessorConfig holds runtime configuration for job processing.
type ProcessorConfig struct {
	Dirs          DirConfig
	Chainwatch    string
	AuditLog      string
	APIURL        string
	APIKey        string
	Model         string
	RedactConfig  *redact.RedactConfig
	ExtraPatterns []redact.ExtraPattern
}

// Processor handles job lifecycle transitions.
type Processor struct {
	cfg ProcessorConfig
}

// NewProcessor creates a processor with the given configuration.
func NewProcessor(cfg ProcessorConfig) *Processor {
	if cfg.Chainwatch == "" {
		cfg.Chainwatch = "chainwatch"
	}
	if cfg.AuditLog == "" {
		cfg.AuditLog = "/tmp/nullbot-daemon.jsonl"
	}
	return &Processor{cfg: cfg}
}

// Process handles a single job file through its full lifecycle:
// read → validate → move to processing → execute → write result to outbox.
func (p *Processor) Process(_ context.Context, jobPath string) error {
	// Structural symlink defense: reject symlinks before reading.
	// This prevents an attacker from symlinking inbox files to arbitrary
	// paths on the filesystem. Without this, a symlink to a valid JSON
	// file would be processed as a legitimate job.
	fi, err := os.Lstat(jobPath)
	if err != nil {
		return fmt.Errorf("stat job file: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("rejected symlink: %s", filepath.Base(jobPath))
	}

	// Read and parse the job file.
	data, err := os.ReadFile(jobPath)
	if err != nil {
		return fmt.Errorf("read job file: %w", err)
	}

	var job Job
	if err := json.Unmarshal(data, &job); err != nil {
		return p.writeFailedResult(filepath.Base(jobPath), fmt.Sprintf("invalid JSON: %v", err))
	}

	if err := ValidateJob(&job); err != nil {
		return p.writeFailedResult(job.ID, fmt.Sprintf("validation failed: %v", err))
	}

	// Move to processing state. Uses moveFile to handle systemd bind mounts (EXDEV).
	processingPath := filepath.Join(p.cfg.Dirs.ProcessingDir(), job.ID+".json")
	if err := moveFile(jobPath, processingPath); err != nil {
		return fmt.Errorf("move to processing: %w", err)
	}

	// Execute the job and collect results.
	result, err := p.execute(&job)
	if err != nil {
		result = &Result{
			ID:          job.ID,
			Status:      ResultFailed,
			Error:       err.Error(),
			CompletedAt: time.Now().UTC(),
		}
	}

	// Write result to outbox.
	if err := p.writeResult(result); err != nil {
		return fmt.Errorf("write result: %w", err)
	}

	// Clean up processing file.
	_ = os.Remove(processingPath)
	return nil
}

// execute dispatches the job to the appropriate handler.
func (p *Processor) execute(job *Job) (*Result, error) {
	switch job.Type {
	case JobTypeInvestigate:
		return p.runInvestigation(job, true)
	case JobTypeObserve:
		return p.runInvestigation(job, false)
	default:
		return nil, fmt.Errorf("unsupported job type: %s", job.Type)
	}
}

// runInvestigation executes an observation runbook and optionally classifies findings.
func (p *Processor) runInvestigation(job *Job, classify bool) (*Result, error) {
	// Determine runbook type from the target.
	rbType := "linux"
	if job.Target.Scope != "" {
		// Auto-detect WordPress if the scope contains wp-content or similar markers.
		rb := observe.GetRunbook(rbType)
		_ = rb // Use the default for now; runbook selection can be enhanced later.
	}

	runnerCfg := observe.RunnerConfig{
		Scope:      job.Target.Scope,
		Type:       rbType,
		Chainwatch: p.cfg.Chainwatch,
		AuditLog:   p.cfg.AuditLog,
	}

	rb := observe.GetRunbook(rbType)
	runResult, err := observe.Run(runnerCfg, rb)
	if err != nil {
		return nil, fmt.Errorf("observe run: %w", err)
	}

	evidence := observe.CollectEvidence(runResult)

	result := &Result{
		ID:          job.ID,
		CompletedAt: time.Now().UTC(),
	}

	// Classify findings if requested and evidence exists.
	var observations []wo.Observation
	var tokenMapRef string
	mode := redact.ResolveMode(p.cfg.APIURL, os.Getenv("NULLBOT_REDACT"))
	if classify && evidence != "" {
		if p.cfg.APIURL == "" {
			// No LLM configured — cache evidence for later retry.
			p.cacheEvidence(job.ID, job.Target.Scope, rbType, evidence)
			result.Error = "no LLM available (evidence cached for retry)"
		} else {
			classifyCfg := observe.ClassifierConfig{
				APIURL: p.cfg.APIURL,
				APIKey: p.cfg.APIKey,
				Model:  p.cfg.Model,
			}

			// Redact for cloud mode.
			classifyEvidence := evidence
			var tm *redact.TokenMap
			if mode == redact.ModeCloud {
				tm = redact.NewTokenMap(fmt.Sprintf("daemon-%s", job.ID))
				classifyEvidence = redact.RedactWithConfig(evidence, tm, p.cfg.RedactConfig, p.cfg.ExtraPatterns)
				if tm.Len() > 0 {
					classifyEvidence = tm.Legend() + "\n" + classifyEvidence
					// Persist the token map for audit trail.
					tmPath := filepath.Join(p.cfg.Dirs.CacheDir(), fmt.Sprintf("tokens-%s.json", job.ID))
					tmData, _ := json.MarshalIndent(tm, "", "  ")
					if err := os.WriteFile(tmPath, tmData, 0600); err == nil {
						tokenMapRef = tmPath
					}
				}
			}

			obs, err := observe.Classify(classifyCfg, classifyEvidence)
			if err != nil {
				// Classification failed — cache evidence for retry.
				p.cacheEvidence(job.ID, job.Target.Scope, rbType, evidence)
				result.Error = fmt.Sprintf("classification failed: %v (evidence cached for retry)", err)
			} else {
				// Post-validation and de-redaction.
				if tm != nil && tm.Len() > 0 {
					var allDetails string
					for _, o := range obs {
						allDetails += " " + o.Detail
					}
					if leaks := redact.CheckLeaks(allDetails, tm); len(leaks) > 0 {
						p.cacheEvidence(job.ID, job.Target.Scope, rbType, evidence)
						result.Error = fmt.Sprintf("classification leak: LLM exposed %d sensitive values (evidence cached)", len(leaks))
						result.Status = ResultFailed
						return result, nil
					}
					for i := range obs {
						obs[i].Detail = redact.Detoken(obs[i].Detail, tm)
					}
				}
				observations = obs
			}
		}
	}

	result.Observations = observations

	// If we have observations, generate a WO and mark as pending approval.
	if len(observations) > 0 {
		host := job.Target.Host
		if host == "" {
			host = "localhost"
		}
		genCfg := wo.GeneratorConfig{
			IncidentID:    job.ID,
			Host:          host,
			Scope:         job.Target.Scope,
			RedactionMode: string(mode),
			TokenMapRef:   tokenMapRef,
		}
		goals := deriveGoals(observations)
		woResult, err := wo.Generate(genCfg, observations, goals)
		if err != nil {
			result.Error = fmt.Sprintf("WO generation failed: %v", err)
			result.Status = ResultFailed
		} else {
			result.ProposedWO = woResult
			result.Status = ResultPendingApproval
		}
	} else {
		result.Status = ResultDone
	}

	return result, nil
}

// cacheEvidence writes raw evidence to the cache directory for later retry.
func (p *Processor) cacheEvidence(jobID, scope, rbType, evidence string) {
	cacheDir := observe.CacheDir(p.cfg.Dirs.State)
	entry := &observe.CachedObservation{
		ID:       jobID,
		JobID:    jobID,
		Scope:    scope,
		Type:     rbType,
		Evidence: evidence,
		CachedAt: time.Now().UTC(),
	}
	if err := observe.WriteCache(cacheDir, entry); err != nil {
		fmt.Fprintf(os.Stderr, "daemon: cache evidence %s: %v\n", jobID, err)
	}
}

// deriveGoals generates remediation goals from observations.
func deriveGoals(observations []wo.Observation) []string {
	goals := make([]string, 0, len(observations))
	for _, obs := range observations {
		goals = append(goals, fmt.Sprintf("Investigate and remediate: %s", obs.Detail))
	}
	if len(goals) == 0 {
		goals = append(goals, "Review investigation findings")
	}
	return goals
}

// writeResult writes a result to the outbox directory atomically.
func (p *Processor) writeResult(r *Result) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	filename := r.ID + ".json"
	tmpPath := filepath.Join(p.cfg.Dirs.Outbox, filename+".tmp")
	finalPath := filepath.Join(p.cfg.Dirs.Outbox, filename)

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	return os.Rename(tmpPath, finalPath)
}

// writeFailedResult writes a minimal failed result when the job can't be parsed.
func (p *Processor) writeFailedResult(id string, errMsg string) error {
	if id == "" {
		id = fmt.Sprintf("unknown-%d", time.Now().UnixNano())
	}
	r := &Result{
		ID:          id,
		Status:      ResultFailed,
		Error:       errMsg,
		CompletedAt: time.Now().UTC(),
	}
	return p.writeResult(r)
}
