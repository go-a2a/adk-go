// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package processors

import (
	"context"
	
	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// BasicRequestProcessor handles basic configuration for LLM requests.
type BasicRequestProcessor struct {
	*RequestProcessor
}

// NewBasicRequestProcessor creates a new BasicRequestProcessor.
func NewBasicRequestProcessor() *BasicRequestProcessor {
	return &BasicRequestProcessor{
		RequestProcessor: NewRequestProcessor("BasicRequestProcessor"),
	}
}

// Process implements RequestProcessor.Process.
func (p *BasicRequestProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
) (<-chan *event.Event, error) {
	// Set default model if not already set
	if req.Model == "" {
		// In a real implementation, this would get the model from the agent's configuration
		req.Model = "gemini-1.5-pro"
	}
	
	// Set default generation config if not fully configured
	if req.GenerationConfig == nil {
		req.GenerationConfig = &flow.GenerationConfig{
			Temperature: 0.7,
			MaxTokens:   1024,
			TopP:        0.95,
		}
	} else {
		// Set any missing defaults
		if req.GenerationConfig.Temperature == 0 {
			req.GenerationConfig.Temperature = 0.7
		}
		if req.GenerationConfig.MaxTokens == 0 {
			req.GenerationConfig.MaxTokens = 1024
		}
		if req.GenerationConfig.TopP == 0 {
			req.GenerationConfig.TopP = 0.95
		}
	}
	
	// Initialize connection options if not set
	if req.ConnectionOptions == nil {
		req.ConnectionOptions = make(map[string]interface{})
	}
	
	// Convert events to messages if not already done
	if len(req.Messages) == 0 && len(ic.Events) > 0 {
		for _, evt := range ic.Events {
			msg := flow.Message{
				Role:    evt.Author,
				Content: evt.Content,
			}
			
			// Add function calls from the event
			for _, fc := range evt.GetFunctionCalls() {
				msg.FunctionCalls = append(msg.FunctionCalls, fc)
			}
			
			req.Messages = append(req.Messages, msg)
		}
	}
	
	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *BasicRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, req)
	return err
}