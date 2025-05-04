// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"maps"
	"sync"

	"github.com/go-a2a/adk-go/event"
)

// ReadOnlyContext provides a read-only view of an invocation context.
// It allows read-only access to the current invocation state without
// allowing modifications.
type ReadOnlyContext struct {
	// invocationContext is the underlying invocation context
	invocationContext *InvocationContext

	// mu protects access to the state map
	mu sync.RWMutex

	// immutableState is a read-only copy of the session state
	immutableState map[string]any

	eventAction *event.EventActions
}

// InvocationID returns the ID of the current invocation.
func (r *ReadOnlyContext) InvocationID() string {
	return r.invocationContext.InvocationID
}

// AgentName returns the name of the agent that is currently running.
func (r *ReadOnlyContext) AgentName() string {
	// return r.invocationContext.Agent.Name
	return ""
}

// State returns a read-only view of the session state.
// This map cannot be modified.
func (r *ReadOnlyContext) State() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to ensure immutability
	return maps.Clone(r.immutableState)
}
