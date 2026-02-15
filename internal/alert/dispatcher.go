package alert

// Dispatcher fans out alert events to matching webhook configurations.
type Dispatcher struct {
	configs []AlertConfig
}

// NewDispatcher creates a Dispatcher from webhook configurations.
// Returns nil if configs is empty (callers should nil-check).
func NewDispatcher(configs []AlertConfig) *Dispatcher {
	if len(configs) == 0 {
		return nil
	}
	return &Dispatcher{configs: configs}
}

// Dispatch sends the event to all webhooks whose Events list matches.
// Matching is based on event.Decision or event.Type (for break_glass_used).
// Fires goroutines — does not block the caller.
func (d *Dispatcher) Dispatch(event AlertEvent) {
	for _, cfg := range d.configs {
		if matches(cfg.Events, event) {
			go Send(cfg, event)
		}
	}
}

func matches(events []string, event AlertEvent) bool {
	for _, e := range events {
		if e == event.Decision {
			return true
		}
		if event.Type != "" && e == event.Type {
			return true
		}
	}
	return false
}
