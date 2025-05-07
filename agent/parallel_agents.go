// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// ParallelAgent runs multiple agents in parallel.
type ParallelAgent struct {
	*Config

	agents []types.Agent
}

var _ types.Agent = (*ParallelAgent)(nil)

// ParallelAgentOption configures a ParallelAgent.
type ParallelAgentOption func(*ParallelAgent)

// WithParallelAgents sets the agents for the parallel agent.
func WithParallelAgents(agents ...types.Agent) ParallelAgentOption {
	return func(a *ParallelAgent) {
		a.agents = agents
	}
}

// NewParallelAgent creates a new parallel agent with the given name and options.
func NewParallelAgent(name string, opts ...ParallelAgentOption) *ParallelAgent {
	agent := &ParallelAgent{
		Config: NewConfig(name),
		agents: []types.Agent{},
	}
	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

// Name implements the [types.Agent].
func (a *ParallelAgent) Name() string {
	return "parallel_agent"
}

// Execute runs the parallel agent with the given input.
func (a *ParallelAgent) Execute(ctx context.Context, input map[string]any, opts ...types.RunOption) (*types.LLMResponse, error) {
	if len(a.agents) == 0 {
		return nil, fmt.Errorf("no agents to execute")
	}

	// Create callback context
	callbackCtx := types.NewCallbackContext(a, input)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, types.CallbackBeforeExecution, callbackCtx); err != nil {
		return nil, err
	}

	responses := make([]*types.LLMResponse, len(a.agents))
	errs := make([]error, len(a.agents))

	var wg sync.WaitGroup
	wg.Add(len(a.agents))

	for i, agent := range a.agents {
		go func(i int, agent types.Agent) {
			defer wg.Done()

			response, err := agent.Execute(ctx, input, opts...)
			responses[i] = response
			errs[i] = err

			if err != nil {
				a.logger.ErrorContext(ctx, "agent execution failed",
					slog.String("agent", agent.Name()),
					slog.Any("err", err),
				)
			}
		}(i, agent)
	}

	wg.Wait()

	// Combine responses
	combinedResponse := a.combineResponses(responses)

	// Check for errors
	for _, err := range errs {
		if err != nil {
			combinedResponse.ErrorCode = "PARTIAL_FAILURE"
			combinedResponse.ErrorMessage = "Some agents failed execution"
			break
		}
	}

	// Update callback context with response
	callbackCtx.Response = combinedResponse

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, types.CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", slog.Any("err", err))
	}

	return combinedResponse, nil
}

// combineResponses combines multiple responses into one.
func (a *ParallelAgent) combineResponses(responses []*types.LLMResponse) *types.LLMResponse {
	var combinedContent strings.Builder
	var toolCalls []*types.ToolCall

	for i, response := range responses {
		if response.Content != nil {
			if combinedContent.Len() > 0 {
				combinedContent.WriteString("\n\n")
			}
			combinedContent.WriteString(fmt.Sprintf("Agent %d (%s):\n", i+1, a.agents[i].Name()))
			combinedContent.WriteString(response.Content.Parts[0].Text)
		}

		toolCalls = append(toolCalls, response.ToolCalls...)
	}

	return &types.LLMResponse{
		Content:   genai.NewContentFromText(combinedContent.String(), genai.RoleUser),
		ToolCalls: toolCalls,
	}
}
