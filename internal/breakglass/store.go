package breakglass

import (
	"crypto/rand"
	"encoding/hex"
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

// validID matches alphanumeric, dash characters only (bg-<hex>).
var validID = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// validateID rejects IDs that could cause path traversal.
func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("id must not be empty")
	}
	if strings.Contains(id, "..") {
		return fmt.Errorf("id must not contain '..'")
	}
	if !validID.MatchString(id) {
		return fmt.Errorf("id contains invalid characters")
	}
	return nil
}

const (
	// DefaultDuration is the default break-glass token validity period.
	DefaultDuration = 10 * time.Minute
	// MaxDuration is the maximum allowed break-glass token validity period.
	MaxDuration = 1 * time.Hour
)

// Token represents a break-glass emergency override token.
type Token struct {
	ID        string     `json:"id"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsActive returns true if the token is not expired, not used, not revoked.
func (t *Token) IsActive() bool {
	if t.UsedAt != nil || t.RevokedAt != nil {
		return false
	}
	return time.Now().UTC().Before(t.ExpiresAt)
}

// Store manages break-glass token files on disk.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore creates a Store backed by the given directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("cannot create breakglass directory: %w", err)
	}
	return &Store{dir: dir}, nil
}

// DefaultDir returns the default break-glass store directory.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "chainwatch-breakglass")
	}
	return filepath.Join(home, ".chainwatch", "breakglass")
}

// Create generates a new break-glass token with a mandatory reason.
func (s *Store) Create(reason string, duration time.Duration) (*Token, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("break-glass reason is required")
	}
	if duration <= 0 {
		duration = DefaultDuration
	}
	if duration > MaxDuration {
		return nil, fmt.Errorf("break-glass duration %s exceeds maximum %s", duration, MaxDuration)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := generateID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	token := &Token{
		ID:        id,
		Reason:    reason,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}

	if err := s.writeAtomic(s.path(id), token); err != nil {
		return nil, fmt.Errorf("failed to write token: %w", err)
	}

	return token, nil
}

// FindActive returns the first active (non-expired, non-used, non-revoked) token.
func (s *Store) FindActive() *Token {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		token, err := s.read(id)
		if err != nil {
			continue
		}
		if token.IsActive() {
			return token
		}
	}

	return nil
}

// Consume marks a token as used. Returns error if not active.
func (s *Store) Consume(id string) error {
	if err := validateID(id); err != nil {
		return fmt.Errorf("invalid token id: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := s.read(id)
	if err != nil {
		return fmt.Errorf("token %q not found: %w", id, err)
	}

	if !token.IsActive() {
		return fmt.Errorf("token %q is not active", id)
	}

	now := time.Now().UTC()
	token.UsedAt = &now
	return s.writeAtomic(s.path(id), token)
}

// Revoke marks a token as revoked.
func (s *Store) Revoke(id string) error {
	if err := validateID(id); err != nil {
		return fmt.Errorf("invalid token id: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := s.read(id)
	if err != nil {
		return fmt.Errorf("token %q not found: %w", id, err)
	}

	now := time.Now().UTC()
	token.RevokedAt = &now
	return s.writeAtomic(s.path(id), token)
}

// List returns all tokens in the store.
func (s *Store) List() ([]Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var tokens []Token
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		token, err := s.read(id)
		if err != nil {
			continue
		}
		tokens = append(tokens, *token)
	}

	return tokens, nil
}

// Cleanup removes expired and consumed token files.
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

	now := time.Now().UTC()
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		token, err := s.read(id)
		if err != nil {
			continue
		}
		if token.UsedAt != nil || token.RevokedAt != nil || now.After(token.ExpiresAt) {
			if err := os.Remove(s.path(id)); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func (s *Store) path(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func (s *Store) read(id string) (*Token, error) {
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *Store) writeAtomic(path string, token *Token) error {
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func generateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random ID: %w", err)
	}
	return "bg-" + hex.EncodeToString(b), nil
}
