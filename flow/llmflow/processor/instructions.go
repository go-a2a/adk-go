// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"log/slog"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/flow"
	"github.com/go-a2a/adk-go/message"
)

// InstructionsProcessor handles the insertion of instructions into LLM requests.
type InstructionsProcessor struct{}

// NewInstructionsProcessor creates a new InstructionsProcessor.
func NewInstructionsProcessor() *InstructionsProcessor {
	return &InstructionsProcessor{}
}

// Run processes the LLM request and returns a channel of events.
func (p *InstructionsProcessor) Run(ctx *flow.LlmFlowContext, request *flow.LlmRequest) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		slog.InfoContext(ctx.Context, "Processing LLM request instructions")

		// Get any instructions from the session configuration
		state := ctx.Session.GetState()
		config := state.Config

		// Check if there are any instructions to add
		if instructions, ok := config["instructions"].(string); ok && len(instructions) > 0 {
			// Insert the instructions at the beginning of the contents
			systemContent := message.NewSystemContent(instructions)
			request.Contents = append([]message.Content{systemContent}, request.Contents...)

			slog.DebugContext(ctx.Context, "Added instructions to LLM request")
		}
	}()

	return eventCh, nil
}
