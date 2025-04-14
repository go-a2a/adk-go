// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// AgentTransferRequestProcessor handles agent transfers in requests.
type AgentTransferRequestProcessor struct {
	*RequestProcessor

	// AllowPeerTransfer determines if peer transfers are allowed.
	AllowPeerTransfer bool
}

// NewAgentTransferRequestProcessor creates a new AgentTransferRequestProcessor.
func NewAgentTransferRequestProcessor(allowPeerTransfer bool) *AgentTransferRequestProcessor {
	return &AgentTransferRequestProcessor{
		RequestProcessor:  NewRequestProcessor("AgentTransferRequestProcessor"),
		AllowPeerTransfer: allowPeerTransfer,
	}
}

// SetAllowPeerTransfer sets whether peer transfers are allowed.
func (p *AgentTransferRequestProcessor) SetAllowPeerTransfer(allowPeerTransfer bool) {
	p.AllowPeerTransfer = allowPeerTransfer
}

// Process implements RequestProcessor.Process.
func (p *AgentTransferRequestProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
) (<-chan *event.Event, error) {
	// Check for transfer request in the last event
	if len(ic.Events) > 0 {
		lastEvent := ic.Events[len(ic.Events)-1]

		// Check if this is a user event (no transfers for user events)
		if lastEvent.Author == "user" {
			ch := make(chan *event.Event)
			close(ch)
			return ch, nil
		}

		// Check if there's a transfer request in the actions
		if lastEvent.Actions != nil && lastEvent.Actions.TransferToAgent != "" {
			transferTo := lastEvent.Actions.TransferToAgent

			// In a real implementation, we would validate the target agent
			// and handle the transfer logic
			// For now, we'll store the transfer target in the invocation context properties
			ic.Properties["transfer_to_agent"] = transferTo

			// Check if this is a peer transfer
			if p.isPeerTransfer(ic, transferTo) {
				// Only allow if peer transfers are enabled
				if !p.AllowPeerTransfer {
					// In a real implementation, we might add a note to the system message
					// about why the transfer was blocked
					req.System += "\n\nNote: A transfer to peer agent was requested but is not allowed."
				}
			}
		}
	}

	// Return empty channel as this processor doesn't generate events directly
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *AgentTransferRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, req)
	return err
}

// isPeerTransfer determines if the transfer is to a peer agent.
func (p *AgentTransferRequestProcessor) isPeerTransfer(ic *flow.InvocationContext, targetAgent string) bool {
	// In a real implementation, we would check the agent hierarchy
	// For now, we'll assume it's a peer transfer if the current agent is not the target
	// and not a direct parent/child of the target
	currentAgent, ok := ic.Properties["current_agent"].(string)
	if !ok || currentAgent == "" {
		return false
	}

	// This is a very simplistic check - in a real implementation we would have proper hierarchy
	return currentAgent != targetAgent
}
