// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// IdentityRequestProcessor adds agent identity information to LLM requests.
type IdentityRequestProcessor struct {
	*RequestProcessor
}

// NewIdentityRequestProcessor creates a new IdentityRequestProcessor.
func NewIdentityRequestProcessor() *IdentityRequestProcessor {
	return &IdentityRequestProcessor{
		RequestProcessor: NewRequestProcessor("IdentityRequestProcessor"),
	}
}

// Process implements RequestProcessor.Process.
func (p *IdentityRequestProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
) (<-chan *event.Event, error) {
	// Check if agent identity is in properties
	if identity, ok := ic.Properties["identity"].(string); ok && identity != "" {
		// Append identity information to system instructions
		if req.System != "" {
			req.System += "\n\n"
		}
		req.System += "Your name is " + identity + ". When referring to yourself, use this name."
	}

	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *IdentityRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, req)
	return err
}
