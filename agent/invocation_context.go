// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"time"
)

// InvocationContext provides context for agent invocation.
type InvocationContext struct {
	// Context is the Go context for the invocation.
	Context context.Context

	// Input is the input provided to the agent.
	Input any

	// Agent is the agent being invoked.
	Agent Agent

	// RunConfig is the configuration for the invocation.
	RunConfig *RunConfig

	// Metadata contains additional information.
	Metadata map[string]any
}

// NewInvocationContext creates a new invocation context.
func NewInvocationContext(ctx context.Context, agent Agent, input any, runConfig *RunConfig) *InvocationContext {
	if runConfig == nil {
		runConfig = DefaultRunConfig()
	}

	return &InvocationContext{
		Context:   ctx,
		Input:     input,
		Agent:     agent,
		RunConfig: runConfig,
		Metadata:  make(map[string]any),
	}
}

// SetMetadata sets a metadata value.
func (c *InvocationContext) SetMetadata(key string, value any) {
	c.Metadata[key] = value
}

// GetMetadata gets a metadata value.
func (c *InvocationContext) GetMetadata(key string) any {
	return c.Metadata[key]
}

// WithTimeout returns a new context with the given timeout.
func (c *InvocationContext) WithTimeout(timeout time.Duration) *InvocationContext {
	ctx, _ := context.WithTimeout(c.Context, timeout)
	c.Context = ctx
	return c
}

// RegisterCallback registers a callback for an event.
func (c *InvocationContext) RegisterCallback(event string, callback CallbackFunc) {
	if baseAgent, ok := c.Agent.(*BaseAgent); ok {
		baseAgent.RegisterCallback(event, callback)
	}
}
