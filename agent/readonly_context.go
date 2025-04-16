// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"sync"

	"github.com/go-a2a/adk-go/session"
)

// ReadOnlyContext provides a read-only view of an invocation context.
// It allows read-only access to the current invocation state without
// allowing modifications.
type ReadOnlyContext struct {
	ctx context.Context

	// invocationContext is the underlying invocation context
	invocationContext *InvocationContext

	// mu protects access to the state map
	mu sync.RWMutex

	// immutableState is a read-only copy of the session state
	immutableState map[string]any
}

// NewReadOnlyContext creates a new ReadOnlyContext instance.
func NewReadOnlyContext(ctx context.Context, invocationContext *InvocationContext) *ReadOnlyContext {
	// Create a snapshot of the state to ensure it's immutable
	stateSnapshot := make(map[string]any)
	if invocationContext.Session != nil && invocationContext.Session().State != nil {
		for k, v := range invocationContext.Session().State.ToMap() {
			stateSnapshot[k] = v
		}
	}

	return &ReadOnlyContext{
		ctx:               ctx,
		invocationContext: invocationContext,
		immutableState:    stateSnapshot,
	}
}

// InvocationID returns the ID of the current invocation.
func (r *ReadOnlyContext) InvocationID() string {
	return r.invocationContext.Session().ID
}

// AgentName returns the name of the agent that is currently running.
func (r *ReadOnlyContext) AgentName() string {
	return r.invocationContext.agent.name
}

// Context returns the underlying context.Context.
func (r *ReadOnlyContext) Context() context.Context {
	return context.Background()
}

// SessionID returns the current session ID.
func (r *ReadOnlyContext) SessionID() string {
	return r.invocationContext.Session().ID
}

// UserID returns the current user ID.
func (r *ReadOnlyContext) UserID() string {
	return r.invocationContext.UserID()
}

// AppName returns the current application name.
func (r *ReadOnlyContext) AppName() string {
	return r.invocationContext.AppName()
}

// State returns a read-only view of the session state.
// This map cannot be modified.
func (r *ReadOnlyContext) State() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to ensure immutability
	stateCopy := make(map[string]any, len(r.immutableState))
	for k, v := range r.immutableState {
		stateCopy[k] = v
	}
	return stateCopy
}

// GetState returns a specific value from the session state.
func (r *ReadOnlyContext) GetState(key string) (any, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	value, exists := r.immutableState[key]
	return value, exists
}

// Session returns the underlying session.
// Note: The returned session should be treated as read-only.
func (r *ReadOnlyContext) Session() *session.Session {
	return r.invocationContext.Session()
}
