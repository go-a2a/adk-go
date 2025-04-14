// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/tool"
)

type ProcessFunc func(ctx context.Context, msg message.Message) (message.Message, error)

// BaseAgent represents a customizable agent that can be implemented with custom logic.
type BaseAgent struct {
	name        string
	description string
	tools       []tool.Tool
	ProcessFunc ProcessFunc
}

// NewBaseAgent creates a new BaseAgent with the provided configuration.
func NewBaseAgent(name string, description string, tools []tool.Tool, processFn ProcessFunc) *BaseAgent {
	return &BaseAgent{
		name:        name,
		description: description,
		tools:       tools,
		ProcessFunc: processFn,
	}
}

// Name returns the agent's name.
func (a *BaseAgent) Name() string {
	return a.name
}

// Description returns the agent's description.
func (a *BaseAgent) Description() string {
	return a.description
}

// Process handles a user message using the custom process function.
func (a *BaseAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	return a.ProcessFunc(ctx, msg)
}

// Tools returns the agent's tools.
func (a *BaseAgent) Tools() []tool.Tool {
	return a.tools
}
