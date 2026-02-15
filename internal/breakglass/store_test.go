package breakglass

import (
	"testing"
	"time"
)

func TestCreateTokenGeneratesUniqueID(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	t1, err := store.Create("reason1", DefaultDuration)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := store.Create("reason2", DefaultDuration)
	if err != nil {
		t.Fatal(err)
	}

	if t1.ID == t2.ID {
		t.Error("expected unique IDs")
	}
	if t1.ID[:3] != "bg-" {
		t.Errorf("expected bg- prefix, got %s", t1.ID)
	}
}

func TestCreateTokenRequiresReason(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Create("", DefaultDuration)
	if err == nil {
		t.Error("expected error for empty reason")
	}

	_, err = store.Create("   ", DefaultDuration)
	if err == nil {
		t.Error("expected error for whitespace-only reason")
	}
}

func TestCreateTokenDefaultDuration(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	token, err := store.Create("test", 0)
	if err != nil {
		t.Fatal(err)
	}

	expected := token.CreatedAt.Add(DefaultDuration)
	diff := token.ExpiresAt.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected expiry ~%v, got %v", expected, token.ExpiresAt)
	}
}

func TestCreateTokenMaxDuration(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Create("test", 2*time.Hour)
	if err == nil {
		t.Error("expected error for duration > MaxDuration")
	}
}

func TestFindActiveReturnsActiveToken(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	created, err := store.Create("test", DefaultDuration)
	if err != nil {
		t.Fatal(err)
	}

	found := store.FindActive()
	if found == nil {
		t.Fatal("expected to find active token")
	}
	if found.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, found.ID)
	}
}

func TestFindActiveSkipsUsed(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	token, _ := store.Create("test", DefaultDuration)
	store.Consume(token.ID)

	found := store.FindActive()
	if found != nil {
		t.Error("expected nil for consumed token")
	}
}

func TestFindActiveSkipsRevoked(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	token, _ := store.Create("test", DefaultDuration)
	store.Revoke(token.ID)

	found := store.FindActive()
	if found != nil {
		t.Error("expected nil for revoked token")
	}
}

func TestFindActiveSkipsExpired(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Create with very short duration, then wait
	token, _ := store.Create("test", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	if token.IsActive() {
		t.Error("token should be expired")
	}

	found := store.FindActive()
	if found != nil {
		t.Error("expected nil for expired token")
	}
}

func TestConsumeMarksUsedAt(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	token, _ := store.Create("test", DefaultDuration)
	err = store.Consume(token.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Read back
	stored, err := store.read(token.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UsedAt == nil {
		t.Error("expected UsedAt to be set")
	}
}

func TestConsumeAlreadyUsedFails(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	token, _ := store.Create("test", DefaultDuration)
	store.Consume(token.ID)

	err = store.Consume(token.ID)
	if err == nil {
		t.Error("expected error when consuming already-used token")
	}
}

func TestRevokeMarksRevokedAt(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	token, _ := store.Create("test", DefaultDuration)
	err = store.Revoke(token.ID)
	if err != nil {
		t.Fatal(err)
	}

	stored, err := store.read(token.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
}

func TestListReturnsAllTokens(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	store.Create("reason1", DefaultDuration)
	store.Create("reason2", DefaultDuration)
	store.Create("reason3", DefaultDuration)

	tokens, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(tokens))
	}
}

func TestCleanupRemovesExpired(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Create expired token
	store.Create("expired", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	// Create active token
	store.Create("active", DefaultDuration)

	err = store.Cleanup()
	if err != nil {
		t.Fatal(err)
	}

	tokens, _ := store.List()
	if len(tokens) != 1 {
		t.Errorf("expected 1 token after cleanup, got %d", len(tokens))
	}
}

func TestTokenIsActiveFalseWhenExpired(t *testing.T) {
	token := &Token{
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	if token.IsActive() {
		t.Error("expired token should not be active")
	}
}

func TestTokenIsActiveFalseWhenUsed(t *testing.T) {
	now := time.Now().UTC()
	token := &Token{
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		UsedAt:    &now,
	}
	if token.IsActive() {
		t.Error("used token should not be active")
	}
}

func TestTokenIsActiveFalseWhenRevoked(t *testing.T) {
	now := time.Now().UTC()
	token := &Token{
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		RevokedAt: &now,
	}
	if token.IsActive() {
		t.Error("revoked token should not be active")
	}
}
