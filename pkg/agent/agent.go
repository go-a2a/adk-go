// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// Agent represents a basic agent in the Agent Development Kit.
type Agent struct {
	name        string
	model       model.Model
	instruction string
	description string
	tools       []tool.Tool
	subAgents   []Agent
}

// NewAgent creates a new Agent with the provided configuration.
func NewAgent(name string, model model.Model, instruction, description string, tools []tool.Tool) *Agent {
	return &Agent{
		name:        name,
		model:       model,
		instruction: instruction,
		description: description,
		tools:       tools,
	}
}

// WithSubAgents adds sub-agents to this agent.
func (a *Agent) WithSubAgents(subAgents ...Agent) *Agent {
	a.subAgents = append(a.subAgents, subAgents...)
	return a
}

// Name returns the agent's name.
func (a *Agent) Name() string {
	return a.name
}

// Process handles a user message and returns a response.
func (a *Agent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	// Implementation will depend on the model integration
	// This is a placeholder for the actual implementation
	return message.Message{}, nil
}

// RunWithTools executes a request with the available tools.
func (a *Agent) RunWithTools(ctx context.Context, req message.Message) (message.Message, error) {
	// Placeholder for tool execution logic
	return message.Message{}, nil
}
