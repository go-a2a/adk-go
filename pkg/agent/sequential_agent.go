// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/observability"
)

// SequentialAgent represents an agent that processes a message through multiple sub-agents in sequence.
// Each sub-agent receives the output of the previous agent in the chain.
type SequentialAgent struct {
	name        string
	description string
	agents      []*Agent
}

// NewSequentialAgent creates a new SequentialAgent with the provided configuration.
func NewSequentialAgent(name, description string, agents ...*Agent) *SequentialAgent {
	return &SequentialAgent{
		name:        name,
		description: description,
		agents:      agents,
	}
}

// Name returns the agent's name.
func (a *SequentialAgent) Name() string {
	return a.name
}

// AddAgent adds an agent to the sequence.
func (a *SequentialAgent) AddAgent(agent *Agent) *SequentialAgent {
	a.agents = append(a.agents, agent)
	return a
}

// Process implements the Agent interface and processes a message through the sequence of agents.
func (a *SequentialAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "sequential_agent.Process")
	defer span.End()

	span.SetAttributes(
		attribute.String("agent.name", a.name),
		attribute.Int("agent.sequence_length", len(a.agents)),
	)

	if len(a.agents) == 0 {
		return message.Message{}, fmt.Errorf("sequential agent '%s' has no sub-agents", a.name)
	}

	// Process the message through each agent in sequence
	currentMsg := msg
	var err error

	for i, agent := range a.agents {
		span.SetAttributes(attribute.Int("agent.current_step", i))
		observability.Logger(ctx).Info("SequentialAgent processing step",
			slog.Int("step", i),
			slog.String("agent", agent.Name()))

		// Process with the current agent
		currentMsg, err = agent.Process(ctx, currentMsg)
		if err != nil {
			return message.Message{}, fmt.Errorf("sequential agent step %d (agent '%s') failed: %w",
				i, agent.Name(), err)
		}
	}

	return currentMsg, nil
}
