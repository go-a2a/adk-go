// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"

	"github.com/go-a2a/adk-go/types"
)

// SequentialAgent runs a sequence of agents in order.
type SequentialAgent struct {
	*Config

	agents []types.Agent
}

var _ types.Agent = (*SequentialAgent)(nil)

// SequentialAgentOption configures a SequentialAgent.
type SequentialAgentOption func(*SequentialAgent)

// WithAgents sets the agents for the sequential agent.
func WithAgents(agents ...types.Agent) SequentialAgentOption {
	return func(a *SequentialAgent) {
		a.agents = agents
	}
}

// NewSequentialAgent creates a new sequential agent with the given name and options.
func NewSequentialAgent(name string, opts ...SequentialAgentOption) *SequentialAgent {
	agent := &SequentialAgent{
		Config: NewConfig(name),
		agents: []types.Agent{},
	}
	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

func (a *SequentialAgent) Name() string {
	return "sequential_agent"
}

// Execute runs the sequential agent with the given input.
func (a *SequentialAgent) Execute(ctx context.Context, input map[string]any, opts ...types.RunOption) (*types.LLMResponse, error) {
	if len(a.agents) == 0 {
		return nil, fmt.Errorf("no agents to execute")
	}

	// Create callback context
	callbackCtx := types.NewCallbackContext(a, input)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, types.CallbackBeforeExecution, callbackCtx); err != nil {
		return nil, err
	}

	result := input
	var lastResponse *types.LLMResponse
	var lastError error

	for _, agent := range a.agents {
		response, err := agent.Execute(ctx, result, opts...)
		if err != nil {
			lastError = err
			a.logger.ErrorContext(ctx, "agent execution failed",
				"agent", agent.Name(),
				"error", err,
			)
			break
		}

		// Use the response content as input to the next agent
		result = map[string]any{
			"result": response.Content,
		}
		lastResponse = response
	}

	// Update callback context with response
	callbackCtx.Response = lastResponse

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, types.CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", "error", err)
	}

	if lastError != nil {
		return &types.LLMResponse{
			ErrorCode:    "EXECUTION_FAILED",
			ErrorMessage: lastError.Error(),
		}, lastError
	}

	return lastResponse, nil
}
