// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"github.com/go-a2a/adk-go/auth"
)

// EventActions represents actions and metadata associated with events.
type EventActions struct {
	// SkipSummarization prevents the model from summarizing function responses if true.
	//
	// Only used for function_response event.
	SkipSummarization bool

	// StateDelta indicates that the event is updating the state with the given delta.
	StateDelta map[string]any

	// ArtifactDelta indicates that the event is updating an artifact. key is the filename, value is the version.
	ArtifactDelta map[string]int

	// TransferToAgent is the event transfers to the specified agent if set.
	TransferToAgent string

	// Escalate the agent is escalating to a higher level agent.
	Escalate bool

	// RequestedAuthConfigs will only be set by a tool response indicating tool request euc.
	// dict key is the function call id since one function call response (from model)
	// could correspond to multiple function calls.
	// dict value is the required auth config.
	RequestedAuthConfigs map[string]*auth.AuthConfig
}

// NewEventActions creates a new EventActions instance with default values.
func NewEventActions() *EventActions {
	return &EventActions{
		StateDelta:           make(map[string]any),
		ArtifactDelta:        make(map[string]int),
		RequestedAuthConfigs: make(map[string]*auth.AuthConfig),
	}
}

// WithSkipSummarization sets the SkipSummarization flag.
func (ea *EventActions) WithSkipSummarization(skip bool) *EventActions {
	ea.SkipSummarization = skip
	return ea
}

// WithStateDelta adds an entry to the StateDelta map.
func (ea *EventActions) WithStateDelta(key string, value any) *EventActions {
	ea.StateDelta[key] = value
	return ea
}

// WithArtifactDelta adds an entry to the ArtifactDelta map.
func (ea *EventActions) WithArtifactDelta(key string, value int) *EventActions {
	ea.ArtifactDelta[key] = value
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

// WithRequestedAuthConfig adds an entry to the RequestedAuthConfigs map.
func (ea *EventActions) WithRequestedAuthConfig(key string, value *auth.AuthConfig) *EventActions {
	ea.RequestedAuthConfigs[key] = value
	return ea
}
