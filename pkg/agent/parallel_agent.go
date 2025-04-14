// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/observability"
)

// ParallelAgent represents an agent that processes a message through multiple sub-agents in parallel.
// This can be useful for tasks that can be processed independently and then combined.
type ParallelAgent struct {
	name             string
	description      string
	agents           []*Agent
	resultAggregator func(ctx context.Context, results []message.Message) (message.Message, error)
}

// DefaultAggregator provides a simple aggregation strategy that concatenates results.
func DefaultAggregator(ctx context.Context, results []message.Message) (message.Message, error) {
	if len(results) == 0 {
		return message.Message{}, fmt.Errorf("no results to aggregate")
	}

	// Use the first message as a base and append content from others
	aggregated := results[0]

	// For each additional result, append its content
	for i := 1; i < len(results); i++ {
		aggregated.Content += "\n\n" + results[i].Content
	}

	return aggregated, nil
}

// NewParallelAgent creates a new ParallelAgent with the provided configuration.
func NewParallelAgent(
	name,
	description string,
	resultAggregator func(ctx context.Context, results []message.Message) (message.Message, error),
	agents ...*Agent,
) *ParallelAgent {
	// Use default aggregator if none provided
	if resultAggregator == nil {
		resultAggregator = DefaultAggregator
	}

	return &ParallelAgent{
		name:             name,
		description:      description,
		agents:           agents,
		resultAggregator: resultAggregator,
	}
}

// Name returns the agent's name.
func (a *ParallelAgent) Name() string {
	return a.name
}

// AddAgent adds an agent to the parallel execution group.
func (a *ParallelAgent) AddAgent(agent *Agent) *ParallelAgent {
	a.agents = append(a.agents, agent)
	return a
}

// Process implements the Agent interface and processes a message through multiple agents in parallel.
func (a *ParallelAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "parallel_agent.Process")
	defer span.End()

	span.SetAttributes(
		attribute.String("agent.name", a.name),
		attribute.Int("agent.parallel_count", len(a.agents)),
	)

	if len(a.agents) == 0 {
		return message.Message{}, fmt.Errorf("parallel agent '%s' has no sub-agents", a.name)
	}

	// Create channels for results and errors
	resultsChan := make(chan message.ProcessResult, len(a.agents))

	// WaitGroup to track completion of all goroutines
	var wg sync.WaitGroup
	wg.Add(len(a.agents))

	// Process message with each agent in parallel
	for i, agent := range a.agents {
		go func(idx int, subAgent *Agent) {
			defer wg.Done()

			agentCtx, agentSpan := observability.StartSpan(ctx, fmt.Sprintf("parallel_agent.worker.%d", idx))
			defer agentSpan.End()

			agentSpan.SetAttributes(
				attribute.String("agent.worker.name", subAgent.Name()),
				attribute.Int("agent.worker.index", idx),
			)

			observability.Info(agentCtx, "ParallelAgent worker starting",
				slog.Int("worker", idx),
				slog.String("agent", subAgent.Name()))

			// Process with the current agent
			result, err := subAgent.Process(agentCtx, msg)

			if err != nil {
				observability.Error(agentCtx, err, "ParallelAgent worker failed",
					slog.Int("worker", idx),
					slog.String("agent", subAgent.Name()))
			} else {
				observability.Info(agentCtx, "ParallelAgent worker completed",
					slog.Int("worker", idx),
					slog.String("agent", subAgent.Name()))
			}

			// Send result or error to the channel
			resultsChan <- message.ProcessResult{
				Message: result,
				Error:   err,
			}
		}(i, agent)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultsChan)

	// Collect all successful results
	var results []message.Message
	var errors []error

	for res := range resultsChan {
		if res.Error != nil {
			errors = append(errors, res.Error)
		} else {
			results = append(results, res.Message)
		}
	}

	// Log errors but don't necessarily fail if we have at least one success
	if len(errors) > 0 {
		for i, err := range errors {
			observability.Warn(ctx, "ParallelAgent had worker failures",
				slog.Int("error_index", i),
				slog.String("error", err.Error()))
		}
	}

	// If we have no results, return an error
	if len(results) == 0 {
		return message.Message{}, fmt.Errorf("all parallel agents failed: %v", errors)
	}

	// Aggregate results using the provided strategy
	return a.resultAggregator(ctx, results)
}
