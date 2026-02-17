package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// validKey matches alphanumeric, dash, underscore, and dot characters only.
var validKey = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validateKey rejects keys that could cause path traversal.
func validateKey(key string) error {
	if key == "" {
		return fmt.Errorf("key must not be empty")
	}
	if strings.Contains(key, "..") {
		return fmt.Errorf("key must not contain '..'")
	}
	if !validKey.MatchString(key) {
		return fmt.Errorf("key contains invalid characters: only alphanumeric, dash, underscore, and dot are allowed")
	}
	return nil
}

// Status represents the state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusConsumed Status = "consumed"
	StatusExpired  Status = "expired"
)

// Approval represents a single approval request and its state.
type Approval struct {
	Key        string     `json:"key"`
	Status     Status     `json:"status"`
	Reason     string     `json:"reason"`
	PolicyID   string     `json:"policy_id"`
	Resource   string     `json:"resource"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// Store manages approval files on disk.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore creates a Store backed by the given directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create approval directory: %w", err)
	}
	return &Store{dir: dir}, nil
}

// DefaultDir returns the default approval store directory.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "chainwatch-pending")
	}
	return filepath.Join(home, ".chainwatch", "pending")
}

// Request creates a pending approval file. No-op if file already exists.
func (s *Store) Request(key, reason, policyID, resource string) error {
	if err := validateKey(key); err != nil {
		return fmt.Errorf("invalid approval key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.path(key)
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}

	a := Approval{
		Key:       key,
		Status:    StatusPending,
		Reason:    reason,
		PolicyID:  policyID,
		Resource:  resource,
		CreatedAt: time.Now().UTC(),
	}

	return s.writeAtomic(path, a)
}

// Approve marks an approval as approved. If duration > 0, sets expiration.
// If duration == 0, the approval is one-time (consumed on first use).
func (s *Store) Approve(key string, duration time.Duration) error {
	if err := validateKey(key); err != nil {
		return fmt.Errorf("invalid approval key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.read(key)
	if err != nil {
		return fmt.Errorf("approval %q not found: %w", key, err)
	}

	a.Status = StatusApproved
	now := time.Now().UTC()
	a.ResolvedAt = &now
	if duration > 0 {
		exp := now.Add(duration)
		a.ExpiresAt = &exp
	}

	return s.writeAtomic(s.path(key), *a)
}

// Deny marks an approval as denied.
func (s *Store) Deny(key string) error {
	if err := validateKey(key); err != nil {
		return fmt.Errorf("invalid approval key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.read(key)
	if err != nil {
		return fmt.Errorf("approval %q not found: %w", key, err)
	}

	a.Status = StatusDenied
	now := time.Now().UTC()
	a.ResolvedAt = &now

	return s.writeAtomic(s.path(key), *a)
}

// Check returns the current status of an approval.
// Returns StatusExpired if the approval has passed its deadline.
func (s *Store) Check(key string) (Status, error) {
	if err := validateKey(key); err != nil {
		return "", fmt.Errorf("invalid approval key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.read(key)
	if err != nil {
		return "", fmt.Errorf("approval %q not found", key)
	}

	// Check expiration for approved entries
	if a.Status == StatusApproved && a.ExpiresAt != nil && time.Now().UTC().After(*a.ExpiresAt) {
		a.Status = StatusExpired
		s.writeAtomic(s.path(key), *a)
		return StatusExpired, nil
	}

	return a.Status, nil
}

// Consume marks a one-time approval as consumed.
func (s *Store) Consume(key string) error {
	if err := validateKey(key); err != nil {
		return fmt.Errorf("invalid approval key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.read(key)
	if err != nil {
		return fmt.Errorf("approval %q not found: %w", key, err)
	}

	if a.Status == StatusConsumed {
		return fmt.Errorf("approval %q already consumed", key)
	}

	a.Status = StatusConsumed
	now := time.Now().UTC()
	a.ResolvedAt = &now

	return s.writeAtomic(s.path(key), *a)
}

// List returns all approvals in the store.
func (s *Store) List() ([]Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var approvals []Approval
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		key := strings.TrimSuffix(e.Name(), ".json")
		a, err := s.read(key)
		if err != nil {
			continue
		}
		approvals = append(approvals, *a)
	}

	return approvals, nil
}

// Cleanup removes all approval files in the store.
func (s *Store) Cleanup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, e.Name())); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (s *Store) path(key string) string {
	return filepath.Join(s.dir, key+".json")
}

func (s *Store) read(key string) (*Approval, error) {
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		return nil, err
	}

	var a Approval
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}

	return &a, nil
}

func (s *Store) writeAtomic(path string, a Approval) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
