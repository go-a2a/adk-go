// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package event

// EventActions represents actions and metadata associated with events.
type EventActions struct {
	// SkipSummarization prevents the model from summarizing function responses if true.
	SkipSummarization bool `json:"skip_summarization,omitempty"`

	// StateDelta tracks state changes.
	StateDelta map[string]any `json:"state_delta,omitempty"`

	// ArtifactDelta tracks artifact version updates.
	ArtifactDelta map[string]any `json:"artifact_delta,omitempty"`

	// TransferToAgent specifies an agent transfer destination.
	TransferToAgent string `json:"transfer_to_agent,omitempty"`

	// Escalate indicates if the conversation should be escalated.
	Escalate bool `json:"escalate,omitempty"`

	// RequestedAuthConfigs contains authentication configurations.
	RequestedAuthConfigs map[string]any `json:"requested_auth_configs,omitempty"`
}

// NewEventActions creates a new EventActions instance with default values.
func NewEventActions() *EventActions {
	return &EventActions{
		StateDelta:           make(map[string]any),
		ArtifactDelta:        make(map[string]any),
		RequestedAuthConfigs: make(map[string]any),
	}
}

// WithSkipSummarization sets the SkipSummarization flag.
func (ea *EventActions) WithSkipSummarization(skip bool) *EventActions {
	ea.SkipSummarization = skip
	return ea
}

// WithTransferToAgent sets the TransferToAgent field.
func (ea *EventActions) WithTransferToAgent(agent string) *EventActions {
	ea.TransferToAgent = agent
	return ea
}

// WithEscalate sets the Escalate flag.
func (ea *EventActions) WithEscalate(escalate bool) *EventActions {
	ea.Escalate = escalate
	return ea
}

// AddStateDelta adds an entry to the StateDelta map.
func (ea *EventActions) AddStateDelta(key string, value any) *EventActions {
	ea.StateDelta[key] = value
	return ea
}

// AddArtifactDelta adds an entry to the ArtifactDelta map.
func (ea *EventActions) AddArtifactDelta(key string, value any) *EventActions {
	ea.ArtifactDelta[key] = value
	return ea
}

// AddRequestedAuthConfig adds an entry to the RequestedAuthConfigs map.
func (ea *EventActions) AddRequestedAuthConfig(key string, value any) *EventActions {
	ea.RequestedAuthConfigs[key] = value
	return ea
}
