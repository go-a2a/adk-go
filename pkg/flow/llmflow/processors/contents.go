// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// ContentsRequestProcessor optimizes content for LLM requests.
type ContentsRequestProcessor struct {
	*RequestProcessor

	// MaxContextLength is the maximum number of messages to include in context.
	MaxContextLength int

	// SummarizeContext determines if older messages should be summarized.
	SummarizeContext bool
}

// NewContentsRequestProcessor creates a new ContentsRequestProcessor.
func NewContentsRequestProcessor() *ContentsRequestProcessor {
	return &ContentsRequestProcessor{
		RequestProcessor: NewRequestProcessor("ContentsRequestProcessor"),
		MaxContextLength: 20,    // Default max context length
		SummarizeContext: false, // Default to not summarize
	}
}

// Process implements RequestProcessor.Process.
func (p *ContentsRequestProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
) (<-chan *event.Event, error) {
	// If we have more messages than the max context length, trim the oldest ones
	if len(req.Messages) > p.MaxContextLength {
		// In a real implementation, we might summarize older messages
		// For now, we'll just keep the most recent ones
		excess := len(req.Messages) - p.MaxContextLength
		req.Messages = req.Messages[excess:]
	}

	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *ContentsRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, req)
	return err
}
