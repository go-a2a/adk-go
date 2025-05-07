// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

// EventActions represents the actions attached to an event.
type EventActions struct {
	// SkipSummarization if true, it won't call model to summarize function response.
	//
	// Only used for functionResponse event.
	SkipSummarization bool

	// StateDelta indicates that the event is updating the state with the given delta.
	StateDelta map[string]any

	// ArtifactDelta indicates that the event is updating an artifact. key is the filename, value is the version.
	ArtifactDelta map[string]int

	// TransferToAgent if set, the event transfers to the specified agent.
	TransferToAgent string

	// Escalate is the agent is escalating to a higher level agent.
	Escalate bool

	// RequestedAuthConfigs authentication configurations requested by tool responses.
	RequestedAuthConfigs map[string]*AuthConfig
}

// NewEventActions creates a new [EventActions] instance with default values.
func NewEventActions() *EventActions {
	return &EventActions{
		StateDelta:           make(map[string]any),
		ArtifactDelta:        make(map[string]int),
		RequestedAuthConfigs: make(map[string]*AuthConfig),
	}
}
