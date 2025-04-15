// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"log/slog"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/flow"
	"github.com/go-a2a/adk-go/message"
)

// ContentsProcessor handles the preparation of contents for LLM requests.
type ContentsProcessor struct{}

// NewContentsProcessor creates a new ContentsProcessor.
func NewContentsProcessor() *ContentsProcessor {
	return &ContentsProcessor{}
}

// Run processes the LLM request and returns a channel of events.
func (p *ContentsProcessor) Run(ctx *flow.LlmFlowContext, request *flow.LlmRequest) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		slog.InfoContext(ctx.Context, "Processing LLM request contents")

		// Get session events
		state := ctx.Session.GetState()
		events := state.Events

		// Filter and convert events to content
		contents := p.getContents(events)

		// Update the request with the preprocessed contents
		request.Contents = contents
	}()

	return eventCh, nil
}

// getContents filters and converts session events to content for the LLM request.
func (p *ContentsProcessor) getContents(events []event.Event) []message.Content {
	var contents []message.Content

	// Skip authentication events
	// Convert events to content
	// Rearrange events to handle async function responses

	// This is a simplified implementation
	for _, evt := range events {
		if evt.Type() == event.TypeMessage {
			msgEvent, ok := evt.(interface{ GetContent() message.Content })
			if ok {
				contents = append(contents, msgEvent.GetContent())
			}
		}
	}

	return contents
}
