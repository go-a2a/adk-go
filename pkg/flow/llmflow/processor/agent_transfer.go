// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// AgentTransferProcessor processes agent transfer requests.
type AgentTransferProcessor struct{}

// NewAgentTransferProcessor creates a new AgentTransferProcessor.
func NewAgentTransferProcessor() *AgentTransferProcessor {
	return &AgentTransferProcessor{}
}

// Run processes agent transfer requests and returns a channel of events.
func (p *AgentTransferProcessor) Run(ctx *flow.LlmFlowContext, request *flow.LlmRequest) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		// Check if the most recent events include agent transfer requests
		// This is a simplified implementation
		state := ctx.Session.GetState()
		events := state.Events

		for i := len(events) - 1; i >= 0 && i >= len(events)-5; i-- {
			evt := events[i]
			// Check if this is an agent transfer event
			// This would need to be implemented based on your event structure

			slog.InfoContext(ctx.Context, "Checking for agent transfer", "event", evt.Type())
		}
	}()

	return eventCh, nil
}
