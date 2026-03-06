package alert

import "context"

// Dispatcher fans out alert events to matching webhook configurations.
type Dispatcher struct {
	routes []route
}

type route struct {
	events  []string
	alerter Alerter
}

// NewDispatcher creates a Dispatcher from alert channel configurations.
// Returns nil if configs is empty (callers should nil-check).
func NewDispatcher(configs []AlertConfig) *Dispatcher {
	if len(configs) == 0 {
		return nil
	}

	activeChannels := activeChannelsFromEnv()
	routes := make([]route, 0, len(configs))
	for _, cfg := range configs {
		channel := cfg.ChannelName()
		if !channelEnabled(channel, activeChannels) {
			continue
		}
		alerter := buildAlerter(cfg)
		if alerter == nil {
			continue
		}
		routes = append(routes, route{
			events:  cfg.Events,
			alerter: alerter,
		})
	}

	if len(routes) == 0 {
		return nil
	}
	return &Dispatcher{routes: routes}
}

// Dispatch sends the event to all channels whose Events list matches.
// Matching is based on event.Decision or event.Type (for break_glass_used).
// Fires goroutines — does not block the caller.
func (d *Dispatcher) Dispatch(event AlertEvent) {
	for _, route := range d.routes {
		if matches(route.events, event) {
			go func(alerter Alerter) {
				_ = alerter.Send(context.Background(), event)
			}(route.alerter)
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
