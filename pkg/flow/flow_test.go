// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package flow

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/go-a2a/adk-go/pkg/event"
)

// MockProcessor is a mock processor for testing.
type MockProcessor struct {
	BaseRequestProcessor
	ProcessCalled bool
}

// NewMockProcessor creates a new MockProcessor.
func NewMockProcessor(name string) *MockProcessor {
	return &MockProcessor{
		BaseRequestProcessor: *NewBaseRequestProcessor(name),
	}
}

// Process implements RequestProcessor.Process.
func (p *MockProcessor) Process(
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

func TestInvocationContext(t *testing.T) {
	// Create a new invocation context
	ic := NewInvocationContext("test-session")

	// Check initial values
	if ic.SessionID != "test-session" {
		t.Errorf("expected SessionID to be 'test-session', got '%s'", ic.SessionID)
	}

	if len(ic.Events) != 0 {
		t.Errorf("expected Events to be empty, got %d events", len(ic.Events))
	}

	if len(ic.Properties) != 0 {
		t.Errorf("expected Properties to be empty, got %d properties", len(ic.Properties))
	}

	// Test fluent interface
	ic.WithExecutionID("test-execution")
	if ic.ExecutionID != "test-execution" {
		t.Errorf("expected ExecutionID to be 'test-execution', got '%s'", ic.ExecutionID)
	}

	// Test adding events
	evt, _ := event.NewUserEvent("Hello")
	ic.AddEvent(evt)
	if len(ic.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(ic.Events))
	}

	// Test adding properties
	ic.WithProperty("key", "value")
	if val, ok := ic.Properties["key"]; !ok || val != "value" {
		t.Errorf("expected property 'key' to be 'value', got '%v'", val)
	}
}

func TestFlowOptions(t *testing.T) {
	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Create options
	options := &FlowOptions{}

	// Add logger
	options.WithLogger(logger)
	if options.Logger != logger {
		t.Errorf("expected Logger to be set correctly")
	}

	// Add processors
	processor1 := NewMockProcessor("processor1")
	processor2 := NewMockProcessor("processor2")

	options.WithRequestProcessor(processor1)
	options.WithRequestProcessor(processor2)

	if len(options.RequestProcessors) != 2 {
		t.Errorf("expected 2 request processors, got %d", len(options.RequestProcessors))
	}

	// Add response processors
	respProcessor := &BaseResponseProcessor{}

	options.WithResponseProcessor(respProcessor)

	if len(options.ResponseProcessors) != 1 {
		t.Errorf("expected 1 response processor, got %d", len(options.ResponseProcessors))
	}
}
