// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"

	"github.com/go-a2a/adk-go/types"
)

// LoopCondition determines whether the loop should continue.
type LoopCondition func(iteration int, input map[string]any, lastOutput *types.LLMResponse) bool

// LoopAgent runs an agent repeatedly until a condition is met.
type LoopAgent struct {
	*Config

	condition     LoopCondition
	maxIterations int
}

var _ types.Agent = (*LoopAgent)(nil)

// NewLoopAgent creates a new loop agent with the given name and options.
func NewLoopAgent(name string, opts ...LoopAgentOption) *LoopAgent {
	a := &LoopAgent{
		Config: &Config{name: name},
		condition: func(iteration int, input map[string]any, lastOutput *types.LLMResponse) bool {
			return !lastOutput.Action.Escalate
		},
		maxIterations: 10, // Default
	}
	for _, opt := range opts {
		opt(a)
	}

	return a
}

// LoopAgentOption configures a LoopAgent.
type LoopAgentOption func(*LoopAgent)

// WithLoopCondition sets the condition for the loop.
func WithLoopCondition(condition LoopCondition) LoopAgentOption {
	return func(a *LoopAgent) {
		a.condition = condition
	}
}

// WithMaxIterations sets the maximum number of iterations.
func WithMaxIterations(maxIterations int) LoopAgentOption {
	return func(a *LoopAgent) {
		a.maxIterations = maxIterations
	}
}

// Name implements [types.Agent].
func (a *LoopAgent) Name() string {
	return "loop_agent"
}

// Execute runs the loop agent with the given input.
func (a *LoopAgent) Execute(ctx context.Context, input map[string]any, opts ...types.RunOption) (*types.LLMResponse, error) {
	if len(a.subAgents) == 0 {
		return nil, fmt.Errorf("sub agents not set")
	}

	if a.condition == nil {
		return nil, fmt.Errorf("condition not set")
	}

	// Create callback context
	callbackCtx := types.NewCallbackContext(a, input)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, types.CallbackBeforeExecution, callbackCtx); err != nil {
		return nil, err
	}

	lastOutput := input
	var lastResponse *types.LLMResponse

	for i := 0; i < a.maxIterations; i++ {
		for _, agent := range a.subAgents {
			response, err := agent.Execute(ctx, lastOutput, opts...)
			if err != nil {
				resp := &types.LLMResponse{
					ErrorCode:    "EXECUTION_FAILED",
					ErrorMessage: err.Error(),
				}
				return resp, err
			}

			lastOutput = map[string]any{
				"output": response.Content,
			}
			lastResponse = response

			// Check if we should continue
			if !a.condition(i, input, lastResponse) {
				a.logger.InfoContext(ctx, "loop condition satisfied, stopping loop", "iteration", i)
				break
			}
		}
	}

	// Update callback context with response
	callbackCtx.Response = lastResponse

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, types.CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", "error", err)
	}

	return lastResponse, nil
}
