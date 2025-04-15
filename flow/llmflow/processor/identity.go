// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"log/slog"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/flow"
	"github.com/go-a2a/adk-go/message"
)

// IdentityProcessor handles the processing of agent identity in LLM requests.
type IdentityProcessor struct{}

// NewIdentityProcessor creates a new IdentityProcessor.
func NewIdentityProcessor() *IdentityProcessor {
	return &IdentityProcessor{}
}

// Run processes the LLM request and returns a channel of events.
func (p *IdentityProcessor) Run(ctx *flow.LlmFlowContext, request *flow.LlmRequest) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		slog.InfoContext(ctx.Context, "Processing LLM request identity")

		// Get agent identity from the session configuration
		state := ctx.Session.GetState()
		config := state.Config

		// Check if there is an identity to add
		if identity, ok := config["identity"].(string); ok && len(identity) > 0 {
			// Add identity information to the request
			// This could be added as a system message or as part of an existing one
			identityContent := message.NewSystemContent("You are " + identity)

			// Insert the identity at the beginning of the contents
			// Check if there's already a system message
			hasSystem := false
			for _, content := range request.Contents {
				if content.Role() == "system" {
					hasSystem = true
					break
				}
			}

			if !hasSystem {
				request.Contents = append([]message.Content{identityContent}, request.Contents...)
				slog.DebugContext(ctx.Context, "Added identity to LLM request")
			}
		}
	}()

	return eventCh, nil
}
