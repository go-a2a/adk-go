// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package event

// EventActions represents actions and metadata associated with events.
type EventActions struct {
	// SkipSummarization prevents the model from summarizing function responses if true.
	SkipSummarization bool `json:"skip_summarization,omitempty"`
	
	// StateDelta tracks state changes.
	StateDelta map[string]interface{} `json:"state_delta,omitempty"`
	
	// ArtifactDelta tracks artifact version updates.
	ArtifactDelta map[string]interface{} `json:"artifact_delta,omitempty"`
	
	// TransferToAgent specifies an agent transfer destination.
	TransferToAgent string `json:"transfer_to_agent,omitempty"`
	
	// Escalate indicates if the conversation should be escalated.
	Escalate bool `json:"escalate,omitempty"`
	
	// RequestedAuthConfigs contains authentication configurations.
	RequestedAuthConfigs map[string]interface{} `json:"requested_auth_configs,omitempty"`
}

// NewEventActions creates a new EventActions instance with default values.
func NewEventActions() *EventActions {
	return &EventActions{
		StateDelta:          make(map[string]interface{}),
		ArtifactDelta:       make(map[string]interface{}),
		RequestedAuthConfigs: make(map[string]interface{}),
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
func (ea *EventActions) AddStateDelta(key string, value interface{}) *EventActions {
	ea.StateDelta[key] = value
	return ea
}

// AddArtifactDelta adds an entry to the ArtifactDelta map.
func (ea *EventActions) AddArtifactDelta(key string, value interface{}) *EventActions {
	ea.ArtifactDelta[key] = value
	return ea
}

// AddRequestedAuthConfig adds an entry to the RequestedAuthConfigs map.
func (ea *EventActions) AddRequestedAuthConfig(key string, value interface{}) *EventActions {
	ea.RequestedAuthConfigs[key] = value
	return ea
}