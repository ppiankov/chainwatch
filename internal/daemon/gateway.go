package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// defaultTTL is the default time-to-live for pending work orders.
const defaultTTL = 24 * time.Hour

// Gateway manages the approval workflow for work orders in the outbox.
type Gateway struct {
	outbox   string
	stateDir string
	ttl      time.Duration
	mu       sync.Mutex
}

// PendingWO wraps a result with metadata for the approval UI.
type PendingWO struct {
	ID        string    `json:"id"`
	Brief     string    `json:"brief"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Target    JobTarget `json:"target"`
}

// NewGateway creates an approval gateway for work orders.
func NewGateway(outbox, stateDir string, ttl time.Duration) *Gateway {
	if ttl == 0 {
		ttl = defaultTTL
	}
	return &Gateway{
		outbox:   outbox,
		stateDir: stateDir,
		ttl:      ttl,
	}
}

// PendingWOs returns all results in the outbox with status "pending_approval".
func (g *Gateway) PendingWOs() ([]PendingWO, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	entries, err := os.ReadDir(g.outbox)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var pending []PendingWO
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		r, err := g.readResult(filepath.Join(g.outbox, e.Name()))
		if err != nil {
			continue
		}
		if r.Status != ResultPendingApproval {
			continue
		}

		info, _ := e.Info()
		createdAt := r.CompletedAt
		if info != nil {
			createdAt = info.ModTime()
		}

		pw := PendingWO{
			ID:        r.ID,
			CreatedAt: createdAt,
			ExpiresAt: createdAt.Add(g.ttl),
		}

		// Extract target from WO if present.
		if r.ProposedWO != nil {
			pw.Target = JobTarget{
				Host:  r.ProposedWO.Target.Host,
				Scope: r.ProposedWO.Target.Scope,
			}
		}

		pending = append(pending, pw)
	}
	return pending, nil
}

// Approve moves a pending WO from outbox to state/approved/.
func (g *Gateway) Approve(woID string) error {
	if err := validateWOID(woID); err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	src := filepath.Join(g.outbox, woID+".json")
	r, err := g.readResult(src)
	if err != nil {
		return fmt.Errorf("WO %q not found in outbox: %w", woID, err)
	}

	if r.Status != ResultPendingApproval {
		return fmt.Errorf("WO %q status is %q, not pending_approval", woID, r.Status)
	}

	// Check expiration.
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if time.Since(info.ModTime()) > g.ttl {
		return fmt.Errorf("WO %q has expired", woID)
	}

	// Move to approved.
	dst := filepath.Join(g.stateDir, "approved", woID+".json")
	return os.Rename(src, dst)
}

// Reject moves a pending WO from outbox to state/rejected/ with a reason.
func (g *Gateway) Reject(woID, reason string) error {
	if err := validateWOID(woID); err != nil {
		return err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	src := filepath.Join(g.outbox, woID+".json")
	r, err := g.readResult(src)
	if err != nil {
		return fmt.Errorf("WO %q not found in outbox: %w", woID, err)
	}
	if r.Status != ResultPendingApproval {
		return fmt.Errorf("WO %q status is %q, not pending_approval", woID, r.Status)
	}

	// Update the result with rejection reason.
	r.Status = "rejected"
	r.Error = reason

	// Write to rejected dir atomically.
	dst := filepath.Join(g.stateDir, "rejected", woID+".json")
	tmpPath := dst + ".tmp"
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}

	// Remove from outbox.
	return os.Remove(src)
}

// CheckExpired scans pending WOs and moves expired ones to rejected.
// Returns the number of WOs expired.
func (g *Gateway) CheckExpired() (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	entries, err := os.ReadDir(g.outbox)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	var expired int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		src := filepath.Join(g.outbox, e.Name())
		r, err := g.readResult(src)
		if err != nil || r.Status != ResultPendingApproval {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) <= g.ttl {
			continue
		}

		// Expire this WO.
		r.Status = "rejected"
		r.Error = "expired"
		woID := strings.TrimSuffix(e.Name(), ".json")
		dst := filepath.Join(g.stateDir, "rejected", woID+".json")
		tmpPath := dst + ".tmp"
		data, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(tmpPath, data, 0600); err != nil {
			continue
		}
		if err := os.Rename(tmpPath, dst); err != nil {
			continue
		}
		_ = os.Remove(src)
		expired++
	}
	return expired, nil
}

// readResult reads and parses a result JSON file.
func (g *Gateway) readResult(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// validateWOID checks for path traversal and invalid characters.
func validateWOID(id string) error {
	if id == "" {
		return fmt.Errorf("WO ID is required")
	}
	if strings.Contains(id, "..") {
		return fmt.Errorf("WO ID must not contain '..'")
	}
	if !validID.MatchString(id) {
		return fmt.Errorf("WO ID contains invalid characters")
	}
	return nil
}
