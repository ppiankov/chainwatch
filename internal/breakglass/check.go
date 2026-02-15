package breakglass

import "github.com/ppiankov/chainwatch/internal/model"

// CheckAndConsume evaluates whether a break-glass token should override a decision.
// Returns the consumed token if override applies, nil otherwise.
//
// Returns nil if:
//   - store is nil
//   - tier < 2 (break-glass only applies to tier 2+)
//   - action is self-targeting (Law 3: chainwatch cannot disable own enforcement)
//   - no active token exists
//
// Consumes the token as a side effect (single-use).
func CheckAndConsume(store *Store, tier int, action *model.Action) *Token {
	if store == nil {
		return nil
	}
	if tier < 2 {
		return nil
	}
	if model.IsSelfTargeting(action) {
		return nil
	}

	token := store.FindActive()
	if token == nil {
		return nil
	}

	if err := store.Consume(token.ID); err != nil {
		return nil // fail closed
	}

	return token
}
