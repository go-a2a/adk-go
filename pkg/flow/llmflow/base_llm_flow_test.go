// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package llmflow

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/go-a2a/adk-go/pkg/event"
)

// MockLLMClient is a mock implementation of LLMClient for testing.
type MockLLMClient struct {
	// GenerateCalled indicates if Generate was called.
	GenerateCalled bool
	
	// GenerateResponse is the response to return from Generate.
	GenerateResponse *LLMResponse
	
	// GenerateError is the error to return from Generate.
	GenerateError error
	
	// GenerateStreamCalled indicates if GenerateStream was called.
	GenerateStreamCalled bool
	
	// GenerateStreamError is the error to return from GenerateStream.
	GenerateStreamError error
}

// Generate implements LLMClient.Generate.
func (c *MockLLMClient) Generate(
	ctx context.Context,
	req *LLMRequest,
) (*LLMResponse, error) {
	c.GenerateCalled = true
	
	if c.GenerateResponse == nil {
		// Return a default response if none was provided
		return &LLMResponse{
			Content: "This is a mock response",
		}, c.GenerateError
	}
	
	return c.GenerateResponse, c.GenerateError
}

// GenerateStream implements LLMClient.GenerateStream.
func (c *MockLLMClient) GenerateStream(
	ctx context.Context,
	req *LLMRequest,
	callback func(*LLMResponse),
) error {
	c.GenerateStreamCalled = true
	
	if c.GenerateResponse != nil {
		callback(c.GenerateResponse)
	} else {
		// Send a default response if none was provided
		callback(&LLMResponse{
			Content: "This is a mock streaming response",
		})
	}
	
	return c.GenerateStreamError
}

// MockRequestProcessor is a mock implementation of RequestProcessor for testing.
type MockRequestProcessor struct {
	// ProcessCalled indicates if Process was called.
	ProcessCalled bool
	
	// ProcessLiveCalled indicates if ProcessLive was called.
	ProcessLiveCalled bool
	
	// Name is the name of this processor.
	Name string
}

// Process implements RequestProcessor.Process.
func (p *MockRequestProcessor) Process(
	ctx context.Context,
	ic *InvocationContext,
	req *LLMRequest,
) (<-chan *event.Event, error) {
	p.ProcessCalled = true
	
	// Return empty channel
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *MockRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *InvocationContext,
	req *LLMRequest,
	callback func(*event.Event),
) error {
	p.ProcessLiveCalled = true
	return nil
}

// MockResponseProcessor is a mock implementation of ResponseProcessor for testing.
type MockResponseProcessor struct {
	// ProcessCalled indicates if Process was called.
	ProcessCalled bool
	
	// ProcessLiveCalled indicates if ProcessLive was called.
	ProcessLiveCalled bool
	
	// Name is the name of this processor.
	Name string
}

// Process implements ResponseProcessor.Process.
func (p *MockResponseProcessor) Process(
	ctx context.Context,
	ic *InvocationContext,
	resp *LLMResponse,
) (<-chan *event.Event, error) {
	p.ProcessCalled = true
	
	// Return empty channel
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements ResponseProcessor.ProcessLive.
func (p *MockResponseProcessor) ProcessLive(
	ctx context.Context,
	ic *InvocationContext,
	resp *LLMResponse,
	callback func(*event.Event),
) error {
	p.ProcessLiveCalled = true
	return nil
}

func TestBaseLLMFlow(t *testing.T) {
	// Create a mock client
	client := &MockLLMClient{}
	
	// Create a logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	
	// Create a flow
	flow := NewBaseLLMFlow("test-flow", client, logger)
	
	// Add a request processor
	reqProcessor := &MockRequestProcessor{Name: "test-req-processor"}
	flow.AddRequestProcessor(reqProcessor)
	
	// Add a response processor
	respProcessor := &MockResponseProcessor{Name: "test-resp-processor"}
	flow.AddResponseProcessor(respProcessor)
	
	// Create a context
	ctx := context.Background()
	
	// Create an invocation context
	ic := &InvocationContext{
		SessionID:   "test-session",
		ExecutionID: "test-execution",
		Events:      []*event.Event{},
		Properties:  make(map[string]interface{}),
	}
	
	// Run the flow
	eventCh, err := flow.Run(ctx, ic)
	if err != nil {
		t.Fatalf("Error running flow: %v", err)
	}
	
	// Consume all events
	for range eventCh {
		// Just drain the channel
	}
	
	// Verify the processors were called
	if !reqProcessor.ProcessCalled {
		t.Errorf("Expected request processor to be called")
	}
	
	if !respProcessor.ProcessCalled {
		t.Errorf("Expected response processor to be called")
	}
	
	// Verify the client was called
	if !client.GenerateCalled {
		t.Errorf("Expected client Generate to be called")
	}
	
	// Test RunLive
	eventHandler := func(evt *event.Event) {
		// Do nothing in this test
	}
	
	err = flow.RunLive(ctx, ic, eventHandler)
	if err != nil {
		t.Fatalf("Error running flow live: %v", err)
	}
	
	// Verify the processors were called in live mode
	if !reqProcessor.ProcessLiveCalled {
		t.Errorf("Expected request processor ProcessLive to be called")
	}
	
	if !respProcessor.ProcessLiveCalled {
		t.Errorf("Expected response processor ProcessLive to be called")
	}
	
	// Verify the client was called in streaming mode
	if !client.GenerateStreamCalled {
		t.Errorf("Expected client GenerateStream to be called")
	}
}