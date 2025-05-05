// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
)

// ReadOnlyContext provides read-only access to agent context.
type ReadOnlyContext struct {
	// Context is the Go context for the invocation.
	Context context.Context

	// Input is the input provided to the agent.
	Input any

	// Agent is the agent being invoked.
	Agent Agent

	// Memory is the agent's memory, if any.
	Memory Memory

	// Metadata contains additional information.
	Metadata map[string]any
}

// NewReadOnlyContext creates a new read-only context.
func NewReadOnlyContext(ctx context.Context, agent Agent, input any, memory Memory) *ReadOnlyContext {
	return &ReadOnlyContext{
		Context:  ctx,
		Input:    input,
		Agent:    agent,
		Memory:   memory,
		Metadata: make(map[string]any),
	}
}

// GetMetadata gets a metadata value.
func (c *ReadOnlyContext) GetMetadata(key string) any {
	return c.Metadata[key]
}

// Tools returns the agent's tools.
func (c *ReadOnlyContext) Tools() []Tool {
	return c.Agent.Tools()
}

// GetMemoryContent retrieves all messages in memory.
func (c *ReadOnlyContext) GetMemoryContent() ([]Message, error) {
	if c.Memory == nil {
		return nil, nil
	}

	return c.Memory.Get()
}
