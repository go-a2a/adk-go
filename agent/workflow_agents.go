// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// SequentialAgent runs a sequence of agents in order.
type SequentialAgent struct {
	*BaseAgent

	agents []Agent
}

// SequentialAgentOption configures a SequentialAgent.
type SequentialAgentOption func(*SequentialAgent)

// WithAgents sets the agents for the sequential agent.
func WithAgents(agents ...Agent) SequentialAgentOption {
	return func(a *SequentialAgent) {
		a.agents = agents
	}
}

// NewSequentialAgent creates a new sequential agent with the given name and options.
func NewSequentialAgent(name string, opts ...SequentialAgentOption) *SequentialAgent {
	agent := &SequentialAgent{
		BaseAgent: NewBaseAgent(name),
		agents:    make([]Agent, 0),
	}

	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

// Execute runs the sequential agent with the given input.
func (a *SequentialAgent) Execute(ctx context.Context, input any, opts ...RunOption) (Response, error) {
	if len(a.agents) == 0 {
		return Response{}, fmt.Errorf("no agents to execute")
	}

	// Create callback context
	callbackCtx := NewCallbackContext(a, input, nil)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackBeforeExecution, callbackCtx); err != nil {
		return Response{}, err
	}

	var result any = input
	var lastResponse Response
	var lastError error

	for _, agent := range a.agents {
		response, err := agent.Execute(ctx, result, opts...)
		if err != nil {
			lastError = err
			a.logger.ErrorContext(ctx, "agent execution failed",
				"agent", agent.Name(),
				"error", err)
			break
		}

		// Use the response content as input to the next agent
		result = response.Content
		lastResponse = response
	}

	// Update callback context with response
	callbackCtx.Response = &lastResponse

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", "error", err)
	}

	if lastError != nil {
		return Response{
			ErrorCode:    "EXECUTION_FAILED",
			ErrorMessage: lastError.Error(),
		}, lastError
	}

	return lastResponse, nil
}

// ParallelAgent runs multiple agents in parallel.
type ParallelAgent struct {
	*BaseAgent

	agents []Agent
}

// ParallelAgentOption configures a ParallelAgent.
type ParallelAgentOption func(*ParallelAgent)

// WithParallelAgents sets the agents for the parallel agent.
func WithParallelAgents(agents ...Agent) ParallelAgentOption {
	return func(a *ParallelAgent) {
		a.agents = agents
	}
}

// NewParallelAgent creates a new parallel agent with the given name and options.
func NewParallelAgent(name string, opts ...ParallelAgentOption) *ParallelAgent {
	agent := &ParallelAgent{
		BaseAgent: NewBaseAgent(name),
		agents:    make([]Agent, 0),
	}

	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

// Execute runs the parallel agent with the given input.
func (a *ParallelAgent) Execute(ctx context.Context, input any, opts ...RunOption) (Response, error) {
	if len(a.agents) == 0 {
		return Response{}, fmt.Errorf("no agents to execute")
	}

	// Create callback context
	callbackCtx := NewCallbackContext(a, input, nil)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackBeforeExecution, callbackCtx); err != nil {
		return Response{}, err
	}

	responses := make([]Response, len(a.agents))
	errs := make([]error, len(a.agents))

	var wg sync.WaitGroup
	wg.Add(len(a.agents))

	for i, agent := range a.agents {
		go func(i int, agent Agent) {
			defer wg.Done()

			response, err := agent.Execute(ctx, input, opts...)
			responses[i] = response
			errs[i] = err

			if err != nil {
				a.logger.ErrorContext(ctx, "agent execution failed",
					"agent", agent.Name(),
					"error", err)
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
	callbackCtx.Response = &combinedResponse

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", "error", err)
	}

	return combinedResponse, nil
}

// combineResponses combines multiple responses into one.
func (a *ParallelAgent) combineResponses(responses []Response) Response {
	var combinedContent strings.Builder
	var toolCalls []ToolCall

	for i, response := range responses {
		if response.Content != "" {
			if combinedContent.Len() > 0 {
				combinedContent.WriteString("\n\n")
			}
			combinedContent.WriteString(fmt.Sprintf("Agent %d (%s):\n", i+1, a.agents[i].Name()))
			combinedContent.WriteString(response.Content)
		}

		toolCalls = append(toolCalls, response.ToolCalls...)
	}

	return Response{
		Content:   combinedContent.String(),
		ToolCalls: toolCalls,
	}
}

// LoopAgent runs an agent repeatedly until a condition is met.
type LoopAgent struct {
	*BaseAgent

	agent         Agent
	condition     LoopCondition
	maxIterations int
}

// LoopCondition determines whether the loop should continue.
type LoopCondition func(iteration int, input any, lastOutput Response) bool

// LoopAgentOption configures a LoopAgent.
type LoopAgentOption func(*LoopAgent)

// WithLoopAgent sets the agent for the loop.
func WithLoopAgent(agent Agent) LoopAgentOption {
	return func(a *LoopAgent) {
		a.agent = agent
	}
}

// WithLoopCondition sets the condition for the loop.
func WithLoopCondition(condition LoopCondition) LoopAgentOption {
	return func(a *LoopAgent) {
		a.condition = condition
	}
}

// WithMaxIterations sets the maximum number of iterations.
func WithMaxIterations(max int) LoopAgentOption {
	return func(a *LoopAgent) {
		a.maxIterations = max
	}
}

// NewLoopAgent creates a new loop agent with the given name and options.
func NewLoopAgent(name string, opts ...LoopAgentOption) *LoopAgent {
	agent := &LoopAgent{
		BaseAgent:     NewBaseAgent(name),
		maxIterations: 10, // Default
	}

	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

// Execute runs the loop agent with the given input.
func (a *LoopAgent) Execute(ctx context.Context, input any, opts ...RunOption) (Response, error) {
	if a.agent == nil {
		return Response{}, fmt.Errorf("agent not set")
	}

	if a.condition == nil {
		return Response{}, fmt.Errorf("condition not set")
	}

	// Create callback context
	callbackCtx := NewCallbackContext(a, input, nil)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackBeforeExecution, callbackCtx); err != nil {
		return Response{}, err
	}

	var lastOutput any = input
	var lastResponse Response

	for i := 0; i < a.maxIterations; i++ {
		response, err := a.agent.Execute(ctx, lastOutput, opts...)
		if err != nil {
			return Response{
				ErrorCode:    "EXECUTION_FAILED",
				ErrorMessage: err.Error(),
			}, err
		}

		lastOutput = response.Content
		lastResponse = response

		// Check if we should continue
		if !a.condition(i, input, lastResponse) {
			a.logger.InfoContext(ctx, "loop condition satisfied, stopping loop",
				"iteration", i)
			break
		}
	}

	// Update callback context with response
	callbackCtx.Response = &lastResponse

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", "error", err)
	}

	return lastResponse, nil
}
