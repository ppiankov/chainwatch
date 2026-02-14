package tracer

import (
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/zone"
)

// TraceAccumulator maintains evolving trace state and the ordered list of events.
type TraceAccumulator struct {
	State  *model.TraceState
	Events []Event
}

// NewAccumulator creates a TraceAccumulator with initialized state.
func NewAccumulator(traceID string) *TraceAccumulator {
	return &TraceAccumulator{
		State:  model.NewTraceState(traceID),
		Events: []Event{},
	}
}

// sourceFor extracts a source identifier from an action.
func sourceFor(action *model.Action) string {
	if action.Tool != "" {
		return action.Tool
	}
	if idx := indexOf(action.Resource, "/"); idx >= 0 {
		return action.Resource[:idx]
	}
	if action.Resource != "" {
		return action.Resource
	}
	return "unknown"
}

// UpdateStateFromAction normalizes metadata and updates the evolving trace state.
// Returns the normalized ResultMeta for reuse.
func (ta *TraceAccumulator) UpdateStateFromAction(action *model.Action) model.ResultMeta {
	action.NormalizeMeta()
	meta := action.NormalizedMeta()

	source := sourceFor(action)
	if !ta.State.HasSource(source) {
		ta.State.SeenSources = append(ta.State.SeenSources, source)
	}

	// Escalate sensitivity monotonically
	if model.SensRank[meta.Sensitivity] > model.SensRank[ta.State.MaxSensitivity] {
		ta.State.MaxSensitivity = meta.Sensitivity
	}

	ta.State.VolumeRows += meta.Rows
	ta.State.VolumeBytes += meta.Bytes

	// Keep "worst" egress (external beats internal)
	if ta.State.Egress != model.EgressExternal && meta.Egress == model.EgressExternal {
		ta.State.Egress = model.EgressExternal
	}

	for _, t := range meta.Tags {
		if !containsStr(ta.State.Tags, t) {
			ta.State.Tags = append(ta.State.Tags, t)
		}
	}

	// v0.2.0: zone detection and advancement
	newZones := zone.DetectZones(action, ta.State)
	if len(newZones) > 0 {
		ta.AdvanceZone(newZones)
	}

	return meta
}

// AdvanceZone unions new zones into state and escalates the irreversibility level.
// Zones can only be added, never removed. Level can only increase, never decrease.
func (ta *TraceAccumulator) AdvanceZone(newZones map[model.Zone]bool) model.BoundaryZone {
	for z := range newZones {
		ta.State.ZonesEntered[z] = true
	}
	newLevel := zone.ComputeIrreversibilityLevel(ta.State.ZonesEntered)
	ta.State.EscalateLevel(newLevel)
	return ta.State.Zone
}

// BuildEvent creates an Event from an action and decision.
func (ta *TraceAccumulator) BuildEvent(
	spanID string,
	parentSpanID string,
	actor map[string]any,
	purpose string,
	action *model.Action,
	decision map[string]any,
	meta *model.ResultMeta,
) Event {
	if meta == nil {
		action.NormalizeMeta()
		m := action.NormalizedMeta()
		meta = &m
	}

	// Include zone information in event data
	zonesStr := make([]string, 0, len(ta.State.ZonesEntered))
	for z := range ta.State.ZonesEntered {
		zonesStr = append(zonesStr, string(z))
	}

	return Event{
		Timestamp:    UTCNowISO(),
		TraceID:      ta.State.TraceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		Actor:        actor,
		Purpose:      purpose,
		Action: map[string]any{
			"type":      "tool_call",
			"tool":      action.Tool,
			"resource":  action.Resource,
			"operation": action.Operation,
			"params":    action.Params,
		},
		Data: map[string]any{
			"classification":        string(meta.Sensitivity),
			"tags":                  meta.Tags,
			"volume":                map[string]any{"rows": meta.Rows, "bytes": meta.Bytes},
			"zones_entered":         zonesStr,
			"irreversibility_level": ta.State.Zone.String(),
		},
		Egress: map[string]any{
			"direction":   string(meta.Egress),
			"destination": meta.Destination,
		},
		Decision: decision,
	}
}

// Record appends an event to the list.
func (ta *TraceAccumulator) Record(event Event) {
	ta.Events = append(ta.Events, event)
}

// RecordAction is a convenience: updates state, builds event, and records it.
func (ta *TraceAccumulator) RecordAction(
	actor map[string]any,
	purpose string,
	action *model.Action,
	decision map[string]any,
	parentSpanID string,
) Event {
	meta := ta.UpdateStateFromAction(action)
	spanID := NewSpanID()

	ev := ta.BuildEvent(spanID, parentSpanID, actor, purpose, action, decision, &meta)
	ta.Record(ev)
	return ev
}

// ToJSON returns a snapshot for debugging / export.
func (ta *TraceAccumulator) ToJSON() map[string]any {
	zonesStr := make([]string, 0, len(ta.State.ZonesEntered))
	for z := range ta.State.ZonesEntered {
		zonesStr = append(zonesStr, string(z))
	}

	return map[string]any{
		"trace_state": map[string]any{
			"trace_id":              ta.State.TraceID,
			"seen_sources":          ta.State.SeenSources,
			"max_sensitivity":       string(ta.State.MaxSensitivity),
			"volume_rows":           ta.State.VolumeRows,
			"volume_bytes":          ta.State.VolumeBytes,
			"egress":                string(ta.State.Egress),
			"tags":                  ta.State.Tags,
			"zone":                  ta.State.Zone.String(),
			"zones_entered":         zonesStr,
			"irreversibility_level": ta.State.Zone.String(),
		},
		"events": ta.Events,
	}
}

func indexOf(s, sep string) int {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
