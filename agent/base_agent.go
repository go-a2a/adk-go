// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/message"
	"github.com/go-a2a/adk-go/tool"
)

// ProcessFunc represents a function that processes a message and returns a response.
type ProcessFunc func(ctx context.Context, msg message.Message) (message.Message, error)

// BeforeAgentCallback callback signature that is invoked before the agent run.
//
// Returns the content to return to the user. When set, the agent run will skipped and the provided content will be returned to user.
type BeforeAgentCallback func(cctx *CallbackContext) *genai.Content

// AfterAgentCallback callback signature that is invoked after the agent run.
//
// Returns the content to return to the user. When set, the agent run will skipped and the provided content will be appended to event history as agent response.
type AfterAgentCallback func(cctx *CallbackContext) *genai.Content

// BaseAgent represents a customizable agent that can be implemented with custom logic.
type BaseAgent struct {
	name                string
	description         string
	tools               []tool.Tool
	processFunc         ProcessFunc
	subAgents           []*BaseAgent
	beforeAgentCallback BeforeAgentCallback
	afterAgentCallback  AfterAgentCallback
}

// NewBaseAgent creates a new BaseAgent with the provided configuration.
func NewBaseAgent(name, description string, tools []tool.Tool, processFn ProcessFunc) *BaseAgent {
	return &BaseAgent{
		name:        name,
		description: description,
		tools:       tools,
		processFunc: processFn,
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
	return a.processFunc(ctx, msg)
}

// Tools returns the agent's tools.
func (a *BaseAgent) Tools() []tool.Tool {
	return a.tools
}
