// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package flow

import (
	"context"
	
	"github.com/go-a2a/adk-go/pkg/event"
)

// RequestProcessor defines the interface for processing LLM requests.
type RequestProcessor interface {
	// Process processes an LLM request and returns a channel of events.
	Process(ctx context.Context, ic *InvocationContext, req *LLMRequest) (<-chan *event.Event, error)
	
	// ProcessLive processes an LLM request and streams events to the callback.
	ProcessLive(ctx context.Context, ic *InvocationContext, req *LLMRequest, callback func(*event.Event)) error
}

// ResponseProcessor defines the interface for processing LLM responses.
type ResponseProcessor interface {
	// Process processes an LLM response and returns a channel of events.
	Process(ctx context.Context, ic *InvocationContext, resp *LLMResponse) (<-chan *event.Event, error)
	
	// ProcessLive processes an LLM response and streams events to the callback.
	ProcessLive(ctx context.Context, ic *InvocationContext, resp *LLMResponse, callback func(*event.Event)) error
}

// BaseRequestProcessor provides a basic implementation of RequestProcessor.
type BaseRequestProcessor struct {
	Name string
}

// NewBaseRequestProcessor creates a new BaseRequestProcessor.
func NewBaseRequestProcessor(name string) *BaseRequestProcessor {
	return &BaseRequestProcessor{
		Name: name,
	}
}

// Process implements RequestProcessor.Process.
func (p *BaseRequestProcessor) Process(
	ctx context.Context,
	ic *InvocationContext,
	req *LLMRequest,
) (<-chan *event.Event, error) {
	// Default implementation that does nothing
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *BaseRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *InvocationContext,
	req *LLMRequest,
	callback func(*event.Event),
) error {
	// Default implementation that does nothing
	return nil
}

// BaseResponseProcessor provides a basic implementation of ResponseProcessor.
type BaseResponseProcessor struct {
	Name string
}

// NewBaseResponseProcessor creates a new BaseResponseProcessor.
func NewBaseResponseProcessor(name string) *BaseResponseProcessor {
	return &BaseResponseProcessor{
		Name: name,
	}
}

// Process implements ResponseProcessor.Process.
func (p *BaseResponseProcessor) Process(
	ctx context.Context,
	ic *InvocationContext,
	resp *LLMResponse,
) (<-chan *event.Event, error) {
	// Default implementation that does nothing
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements ResponseProcessor.ProcessLive.
func (p *BaseResponseProcessor) ProcessLive(
	ctx context.Context,
	ic *InvocationContext,
	resp *LLMResponse,
	callback func(*event.Event),
) error {
	// Default implementation that does nothing
	return nil
}