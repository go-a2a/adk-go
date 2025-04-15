// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/message"
	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/tool"
)

// LoopAgent represents an agent that loops over processing steps until a condition is met.
// This is useful for multi-step reasoning or iterative problem solving.
type LoopAgent struct {
	Agent
	maxIterations  int
	shouldContinue func(ctx context.Context, msg message.Message) (bool, error)
}

// NewLoopAgent creates a new LoopAgent with the provided configuration.
func NewLoopAgent(
	name string,
	model model.Model,
	instruction,
	description string,
	tools []tool.Tool,
	maxIterations int,
	shouldContinue func(ctx context.Context, msg message.Message) (bool, error),
) *LoopAgent {
	baseAgent := NewAgent(name, model, instruction, description, tools)

	return &LoopAgent{
		Agent:          *baseAgent,
		maxIterations:  maxIterations,
		shouldContinue: shouldContinue,
	}
}

// DefaultContinueCondition provides a simple default condition that always returns true.
func DefaultContinueCondition(ctx context.Context, msg message.Message) (bool, error) {
	// The default condition always returns true, which means the agent will continue
	// processing until maxIterations is reached
	return true, nil
}

// Process overrides the base Agent's Process method to implement looping behavior.
func (a *LoopAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "loop_agent.Process")
	defer span.End()

	span.SetAttributes(attribute.String("agent.name", a.name))
	span.SetAttributes(attribute.Int("agent.max_iterations", a.maxIterations))

	if a.model == nil {
		return message.Message{}, fmt.Errorf("agent '%s' has no model configured", a.name)
	}

	// Define a continue function if none was provided
	contFunc := a.shouldContinue
	if contFunc == nil {
		contFunc = DefaultContinueCondition
	}

	// Initial processing using the parent Process method
	currentMsg := msg
	var err error

	// Process in a loop until shouldContinue returns false or maxIterations is reached
	for i := 0; i < a.maxIterations; i++ {
		span.SetAttributes(attribute.Int("agent.current_iteration", i))
		observability.Logger(ctx).InfoContext(ctx, "LoopAgent iteration",
			slog.Int("iteration", i),
			slog.String("agent", a.name))

		// Process the message using the parent Agent's RunWithTools
		currentMsg, err = a.RunWithTools(ctx, currentMsg)
		if err != nil {
			return message.Message{}, fmt.Errorf("loop agent iteration %d failed: %w", i, err)
		}

		// Check if we should continue
		shouldCont, err := contFunc(ctx, currentMsg)
		if err != nil {
			observability.Logger(ctx).WarnContext(ctx, "Error in continuation condition",
				slog.String("error", err.Error()))
		}

		if !shouldCont {
			observability.Logger(ctx).InfoContext(ctx, "LoopAgent stopping",
				slog.Int("completed_iterations", i+1),
				slog.String("reason", "continuation condition returned false"))
			break
		}
	}

	return currentMsg, nil
}
