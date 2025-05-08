// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

// ReadOnlyContext provides read-only access to agent context.
type ReadOnlyContext struct {
	InvocationContext *InvocationContext

	// Agent is the agent being invoked.
	Agent Agent

	// Input is the input provided to the agent.
	Input map[string]any

	// Metadata contains additional information.
	Metadata map[string]any
}

// NewReadOnlyContext creates a new read-only context.
func NewReadOnlyContext(agent Agent, input map[string]any) *ReadOnlyContext {
	return &ReadOnlyContext{
		Agent:    agent,
		Input:    input,
		Metadata: make(map[string]any),
	}
}
