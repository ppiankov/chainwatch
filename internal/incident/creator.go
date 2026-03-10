package incident

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ppiankov/chainwatch/internal/observe"
)

// Creator converts findings into incidents via a Backend, with deduplication.
type Creator struct {
	backend Backend
	store   *Store
}

// NewCreator returns a Creator that uses the given backend and dedup store.
func NewCreator(backend Backend, store *Store) *Creator {
	return &Creator{backend: backend, store: store}
}

// CreateFromFinding creates an incident from a single finding.
// Returns nil incident (no error) if an open incident already exists for this finding hash.
func (c *Creator) CreateFromFinding(ctx context.Context, f observe.Finding) (*Incident, error) {
	existing, err := c.store.FindByHash(f.Hash)
	if err != nil {
		return nil, fmt.Errorf("dedup check: %w", err)
	}
	if existing != nil {
		return nil, nil
	}

	input := CreateInput{
		Title:    formatTitle(f),
		Body:     formatBody(f),
		Severity: f.Severity,
		Labels:   []string{"chainwatch", "auto-created", f.Severity},
	}

	inc, err := c.backend.Create(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("create incident: %w", err)
	}

	inc.FindingHash = f.Hash
	inc.Status = "open"
	if inc.ID == "" {
		inc.ID = generateID()
	}
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt = time.Now()
	}

	if err := c.store.Save(inc); err != nil {
		return inc, fmt.Errorf("save incident: %w", err)
	}

	return inc, nil
}

// CreateFromFindings creates incidents from multiple findings, skipping duplicates.
func (c *Creator) CreateFromFindings(ctx context.Context, findings []observe.Finding) ([]*Incident, error) {
	var created []*Incident
	for _, f := range findings {
		inc, err := c.CreateFromFinding(ctx, f)
		if err != nil {
			return created, err
		}
		if inc != nil {
			created = append(created, inc)
		}
	}
	return created, nil
}

func formatTitle(f observe.Finding) string {
	detail := f.Detail
	if len(detail) > 80 {
		detail = detail[:80] + "..."
	}
	return fmt.Sprintf("[chainwatch] %s: %s", f.Type, detail)
}

func formatBody(f observe.Finding) string {
	return fmt.Sprintf(`## Finding Details

**Type:** %s
**Severity:** %s
**Finding Hash:** %s

### Detail

%s

---
Auto-created by chainwatch incident pipeline.`, f.Type, f.Severity, f.Hash, f.Detail)
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("inc-%x", b)
}
