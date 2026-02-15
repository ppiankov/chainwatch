package breakglass

import (
	"testing"

	"github.com/ppiankov/chainwatch/internal/model"
)

func TestCheckAndConsumeNilStore(t *testing.T) {
	action := &model.Action{Tool: "command", Resource: "sudo restart"}
	token := CheckAndConsume(nil, 3, action)
	if token != nil {
		t.Error("expected nil for nil store")
	}
}

func TestCheckAndConsumeLowTier(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	store.Create("test", DefaultDuration)

	action := &model.Action{Tool: "command", Resource: "sudo restart"}

	// Tier 0 and 1 should not trigger break-glass
	if token := CheckAndConsume(store, 0, action); token != nil {
		t.Error("expected nil for tier 0")
	}
	if token := CheckAndConsume(store, 1, action); token != nil {
		t.Error("expected nil for tier 1")
	}
}

func TestCheckAndConsumeSelfTargeting(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	store.Create("test", DefaultDuration)

	action := &model.Action{Tool: "command", Resource: "rm /usr/local/bin/chainwatch"}

	token := CheckAndConsume(store, 3, action)
	if token != nil {
		t.Error("expected nil for self-targeting action")
	}

	// Token should still be active (not consumed)
	found := store.FindActive()
	if found == nil {
		t.Error("expected token to still be active after self-targeting check")
	}
}

func TestCheckAndConsumeNoActiveToken(t *testing.T) {
	store, _ := NewStore(t.TempDir())

	action := &model.Action{Tool: "command", Resource: "sudo restart"}
	token := CheckAndConsume(store, 3, action)
	if token != nil {
		t.Error("expected nil when no active token exists")
	}
}

func TestCheckAndConsumeSuccess(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	created, _ := store.Create("emergency", DefaultDuration)

	action := &model.Action{Tool: "command", Resource: "sudo systemctl restart nginx"}
	token := CheckAndConsume(store, 2, action)

	if token == nil {
		t.Fatal("expected token for tier 2+ action with active token")
	}
	if token.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, token.ID)
	}
}

func TestCheckAndConsumeIsOneShot(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	store.Create("emergency", DefaultDuration)

	action := &model.Action{Tool: "command", Resource: "sudo systemctl restart nginx"}

	// First call consumes the token
	token1 := CheckAndConsume(store, 3, action)
	if token1 == nil {
		t.Fatal("expected token on first call")
	}

	// Second call should return nil (token consumed)
	token2 := CheckAndConsume(store, 3, action)
	if token2 != nil {
		t.Error("expected nil on second call (token already consumed)")
	}
}
