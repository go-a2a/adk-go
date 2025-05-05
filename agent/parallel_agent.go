// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"sync"

	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

// ParallelAgent is an agent that runs multiple agents in parallel.
type ParallelAgent struct {
	Agent
	agents []BaseAgent
	logger *slog.Logger
}

// ParallelAgentOption is a function that modifies a ParallelAgent.
type ParallelAgentOption func(*ParallelAgent)

// WithParallelAgents sets the agents for the parallel agent.
func WithParallelAgents(agents []BaseAgent) ParallelAgentOption {
	return func(a *ParallelAgent) {
		a.agents = agents
	}
}

// WithParallelLogger sets the logger for the parallel agent.
func WithParallelLogger(logger *slog.Logger) ParallelAgentOption {
	return func(a *ParallelAgent) {
		a.logger = logger
	}
}

// NewParallelAgent creates a new parallel agent with the given options.
func NewParallelAgent(options ...ParallelAgentOption) *ParallelAgent {
	agent := &ParallelAgent{
		Agent:  *NewAgent(),
		agents: []BaseAgent{},
		logger: slog.Default(),
	}

	for _, option := range options {
		option(agent)
	}

	return agent
}

// AddAgent adds an agent to the parallel agent.
func (a *ParallelAgent) AddAgent(agent BaseAgent) {
	a.agents = append(a.agents, agent)
}

// InvokeAsync invokes the parallel agent and returns a stream of responses.
func (a *ParallelAgent) InvokeAsync(ctx context.Context, invocationCtx InvocationContext) iter.Seq2[*genai.Content, error] {
	return func(yield func(*genai.Content, error) bool) {
		// If we don't have any agents, return an error
		if len(a.agents) == 0 {
			yield(nil, fmt.Errorf("no agents configured for parallel agent"))
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
			yield(beforeResult, nil)
			return
		}

		// Create a working copy of the history
		workingHistory := make([]*genai.Content, len(history))
		copy(workingHistory, history)

		// Add the user request to the working history if provided
		if request != nil {
			workingHistory = append(workingHistory, request)
		}

		// Create a wait group for parallelism
		var wg sync.WaitGroup

		// Create a mutex for thread-safe access to responses
		var mu sync.Mutex

		// Create a slice to hold all responses
		responses := make([]*genai.Content, 0, len(a.agents))

		// Create a channel for errors
		errCh := make(chan error, len(a.agents))

		// Process each agent in parallel
		for i, agent := range a.agents {
			wg.Add(1)

			go func(idx int, ag BaseAgent) {
				defer wg.Done()

				a.logger.Debug("Invoking agent in parallel", "agent", ag.Name(), "index", idx)

				// Create a new invocation context for this agent
				agentInvocationCtx := NewInvocationContextWithOptions(
					WithInvocationHistory(workingHistory),
				)

				// Invoke the agent
				response, err := ag.Invoke(ctx, *agentInvocationCtx)
				if err != nil {
					errCh <- fmt.Errorf("error invoking agent %s: %w", ag.Name(), err)
					return
				}

				// Add the agent's response to the responses slice
				if response != nil {
					mu.Lock()
					responses = append(responses, response)
					mu.Unlock()
				}
			}(i, agent)
		}

		// Wait for all agents to complete
		go func() {
			wg.Wait()
			close(errCh)
		}()

		// Check for errors
		for err := range errCh {
			yield(nil, err)
			return
		}

		// Combine all responses
		combinedContent := &genai.Content{
			Role:  model.RoleAssistant,
			Parts: []*genai.Part{},
		}

		// Add each response to the combined content
		for _, response := range responses {
			// Yield individual responses
			yield(response, nil)

			// Add to combined content
			for _, part := range response.Parts {
				combinedContent.Parts = append(combinedContent.Parts, part)
			}
		}

		// Create callback context for after callbacks
		callbackCtx = NewCallbackContextWithOptions(
			WithHistory(history),
			WithRequest(request),
			WithContent(combinedContent),
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

// Invoke synchronously invokes the parallel agent and returns the final response.
func (a *ParallelAgent) Invoke(ctx context.Context, invocationCtx InvocationContext) (*genai.Content, error) {
	return a.Agent.Invoke(ctx, invocationCtx)
}
