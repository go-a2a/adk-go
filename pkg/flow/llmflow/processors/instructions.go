// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package processors

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// InstructionsRequestProcessor adds system instructions to LLM requests.
type InstructionsRequestProcessor struct {
	*RequestProcessor
}

// NewInstructionsRequestProcessor creates a new InstructionsRequestProcessor.
func NewInstructionsRequestProcessor() *InstructionsRequestProcessor {
	return &InstructionsRequestProcessor{
		RequestProcessor: NewRequestProcessor("InstructionsRequestProcessor"),
	}
}

// Process implements RequestProcessor.Process.
func (p *InstructionsRequestProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
) (<-chan *event.Event, error) {
	// Check if agent instructions are in properties
	if instructions, ok := ic.Properties["instructions"].(string); ok && instructions != "" {
		// Set system instructions
		req.System = instructions
	} else {
		// Set default instructions if not provided
		req.System = "You are a helpful AI assistant. Be concise, accurate, and helpful."
	}

	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *InstructionsRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, req)
	return err
}
