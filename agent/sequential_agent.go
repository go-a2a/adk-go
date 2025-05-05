// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"iter"
	"log/slog"

	"google.golang.org/genai"
)

// SequentialAgent is an agent that runs multiple agents in sequence.
type SequentialAgent struct {
	Agent
	agents []BaseAgent
	logger *slog.Logger
}

// SequentialAgentOption is a function that modifies a SequentialAgent.
type SequentialAgentOption func(*SequentialAgent)

// WithAgents sets the agents for the sequential agent.
func WithAgents(agents []BaseAgent) SequentialAgentOption {
	return func(a *SequentialAgent) {
		a.agents = agents
	}
}

// WithSequentialLogger sets the logger for the sequential agent.
func WithSequentialLogger(logger *slog.Logger) SequentialAgentOption {
	return func(a *SequentialAgent) {
		a.logger = logger
	}
}

// NewSequentialAgent creates a new sequential agent with the given options.
func NewSequentialAgent(options ...SequentialAgentOption) *SequentialAgent {
	agent := &SequentialAgent{
		Agent:  *NewAgent(),
		agents: []BaseAgent{},
		logger: slog.Default(),
	}

	for _, option := range options {
		option(agent)
	}

	return agent
}

// AddAgent adds an agent to the sequential agent.
func (a *SequentialAgent) AddAgent(agent BaseAgent) {
	a.agents = append(a.agents, agent)
}

// InvokeAsync invokes the sequential agent and returns a stream of responses.
func (a *SequentialAgent) InvokeAsync(ctx context.Context, invocationCtx InvocationContext) iter.Seq2[*genai.Content, error] {
	return func(yield func(*genai.Content, error) bool) {
		// If we don't have any agents, return an error
		if len(a.agents) == 0 {
			yield(nil, fmt.Errorf("no agents configured for sequential agent"))
			return
		}

		// Get the history and request from the invocation context
		history := invocationCtx.GetHistory()
		request := invocationCtx.GetRequest()

		// Create callback context for before callbacks
		callbackCtx := NewCallbackContextWithOptions(
			WithHistory(history),
			WithRequest(request),
		)

		// Execute before callbacks
		beforeResult := invocationCtx.ExecuteBeforeCallbacks(callbackCtx)
		if beforeResult != nil {
			// If a before callback returned a result, use it instead of calling the agents
			a.logger.Debug("Using result from before callback")
			if !yield(beforeResult, nil) {
				return
			}
		}

		// Create a working copy of the history that we'll update as we go
		workingHistory := make([]*genai.Content, len(history))
		copy(workingHistory, history)

		// Add the user request to the working history if provided
		if request != nil {
			workingHistory = append(workingHistory, request)
		}

		// Process each agent in sequence
		var finalContent *genai.Content

		for i, agent := range a.agents {
			a.logger.Debug("Invoking agent in sequence", "agent", agent.Name(), "index", i)

			// Create a new invocation context for this agent
			agentInvocationCtx := NewInvocationContextWithOptions(
				WithInvocationHistory(workingHistory),
			)

			// Invoke the agent
			response, err := agent.Invoke(ctx, *agentInvocationCtx)
			if err != nil {
				yield(nil, fmt.Errorf("error invoking agent %s: %w", agent.Name(), err))
				return
			}

			// Add the agent's response to the working history
			if response != nil {
				workingHistory = append(workingHistory, response)
				finalContent = response

				// Yield intermediate results
				if !yield(response, nil) {
					return
				}
			}
		}

		// Create callback context for after callbacks
		callbackCtx = NewCallbackContextWithOptions(
			WithHistory(history),
			WithRequest(request),
			WithContent(finalContent),
		)
		callbackCtx.MarkEnd()

		// Execute after callbacks
		afterResult := invocationCtx.ExecuteAfterCallbacks(callbackCtx)
		if afterResult != nil {
			// If an after callback returned a result, yield it
			a.logger.Debug("Using result from after callback")
			yield(afterResult, nil)
		}

	}
}

// Invoke synchronously invokes the sequential agent and returns the final response.
func (a *SequentialAgent) Invoke(ctx context.Context, invocationCtx InvocationContext) (*genai.Content, error) {
	return a.Agent.Invoke(ctx, invocationCtx)
}
