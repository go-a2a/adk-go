// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"log/slog"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/flow"
)

// BasicProcessor handles basic preprocessing of LLM requests.
type BasicProcessor struct{}

// NewBasicProcessor creates a new BasicProcessor.
func NewBasicProcessor() *BasicProcessor {
	return &BasicProcessor{}
}

// Run processes the LLM request and returns a channel of events.
func (p *BasicProcessor) Run(ctx *flow.LlmFlowContext, request *flow.LlmRequest) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		slog.InfoContext(ctx.Context, "Processing LLM request with basic processor")

		// Basic request validation and preprocessing
		// This could include checking for required fields, sanitizing input, etc.
		if len(request.ModelID) == 0 {
			slog.WarnContext(ctx.Context, "No model ID specified in request")
		}

		// No events emitted for basic processing
	}()

	return eventCh, nil
}
