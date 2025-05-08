// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

// ReadOnlyContext provides read-only access to agent context.
type ReadOnlyContext struct {
	invocationContext *InvocationContext
}

// NewReadOnlyContext creates a new read-only context.
func NewReadOnlyContext(invocationContext *InvocationContext) *ReadOnlyContext {
	return &ReadOnlyContext{
		invocationContext: invocationContext,
	}
}

// InvocationContextID returns the current invocation id.
func (rc *ReadOnlyContext) InvocationContextID() string {
	return rc.invocationContext.InvocationID
}

// AgentName returns the name of the agent that is currently running.
func (rc *ReadOnlyContext) AgentName() string {
	return rc.invocationContext.Agent.Name()
}

// State returns the state of the current session. READONLY field.
func (rc *ReadOnlyContext) State() map[string]any {
	return rc.invocationContext.Session.State()
}
