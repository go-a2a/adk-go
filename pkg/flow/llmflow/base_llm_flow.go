// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package llmflow

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	
	"github.com/go-a2a/adk-go/pkg/event"
)

// LLMClient defines the interface for communicating with a language model.
type LLMClient interface {
	// Generate generates a response from the language model.
	Generate(ctx context.Context, req *LLMRequest) (*LLMResponse, error)
	
	// GenerateStream generates a streaming response from the language model.
	GenerateStream(ctx context.Context, req *LLMRequest, callback func(*LLMResponse)) error
}

// BaseLLMFlow provides a base implementation for LLM-based flows.
type BaseLLMFlow struct {
	// Name is the name of this flow.
	Name string
	
	// Client is the client for communicating with the language model.
	Client LLMClient
	
	// RequestProcessors is the list of processors for preprocessing requests.
	RequestProcessors []RequestProcessor
	
	// ResponseProcessors is the list of processors for postprocessing responses.
	ResponseProcessors []ResponseProcessor
	
	// Logger is used for logging.
	Logger *slog.Logger
}

// NewBaseLLMFlow creates a new BaseLLMFlow with the given client.
func NewBaseLLMFlow(name string, client LLMClient, logger *slog.Logger) *BaseLLMFlow {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &BaseLLMFlow{
		Name:               name,
		Client:             client,
		RequestProcessors:  []RequestProcessor{},
		ResponseProcessors: []ResponseProcessor{},
		Logger:             logger,
	}
}

// AddRequestProcessor adds a request processor to the flow.
func (f *BaseLLMFlow) AddRequestProcessor(processor RequestProcessor) *BaseLLMFlow {
	f.RequestProcessors = append(f.RequestProcessors, processor)
	return f
}

// AddResponseProcessor adds a response processor to the flow.
func (f *BaseLLMFlow) AddResponseProcessor(processor ResponseProcessor) *BaseLLMFlow {
	f.ResponseProcessors = append(f.ResponseProcessors, processor)
	return f
}

// Run executes the flow with the given context and returns a channel of events.
func (f *BaseLLMFlow) Run(ctx context.Context, ic *InvocationContext) (<-chan *event.Event, error) {
	events := make(chan *event.Event)
	
	go func() {
		defer close(events)
		
		// Create a default request
		req := &LLMRequest{
			GenerationConfig: &GenerationConfig{
				Temperature: 0.7,
				MaxTokens:   1024,
			},
			ConnectionOptions: make(map[string]interface{}),
		}
		
		// Preprocess the request with all request processors
		for _, processor := range f.RequestProcessors {
			processorEvents, err := processor.Process(ctx, ic, req)
			if err != nil {
				f.Logger.Error("Error in request processor", 
					slog.String("processor", fmt.Sprintf("%T", processor)),
					slog.String("error", err.Error()))
				return
			}
			
			// Forward processor events to the output channel
			for evt := range processorEvents {
				events <- evt
			}
		}
		
		// Call the LLM
		resp, err := f.Client.Generate(ctx, req)
		if err != nil {
			f.Logger.Error("Error generating LLM response", slog.String("error", err.Error()))
			return
		}
		
		// Postprocess the response with all response processors
		for _, processor := range f.ResponseProcessors {
			processorEvents, err := processor.Process(ctx, ic, resp)
			if err != nil {
				f.Logger.Error("Error in response processor", 
					slog.String("processor", fmt.Sprintf("%T", processor)),
					slog.String("error", err.Error()))
				return
			}
			
			// Forward processor events to the output channel
			for evt := range processorEvents {
				events <- evt
			}
		}
	}()
	
	return events, nil
}

// RunLive executes the flow with the given context and streams events to the callback.
func (f *BaseLLMFlow) RunLive(
	ctx context.Context,
	ic *InvocationContext,
	callback func(*event.Event),
) error {
	// Create a default request
	req := &LLMRequest{
		GenerationConfig: &GenerationConfig{
			Temperature: 0.7,
			MaxTokens:   1024,
		},
		ConnectionOptions: make(map[string]interface{}),
	}
	
	// Preprocess the request with all request processors
	for _, processor := range f.RequestProcessors {
		err := processor.ProcessLive(ctx, ic, req, callback)
		if err != nil {
			return fmt.Errorf("error in request processor %T: %w", processor, err)
		}
	}
	
	// Create a mutex to ensure only one goroutine writes to resp at a time
	var respMutex sync.Mutex
	resp := &LLMResponse{}
	
	// Set up a callback for streaming responses
	streamCallback := func(chunk *LLMResponse) {
		respMutex.Lock()
		resp.Content += chunk.Content
		for _, fc := range chunk.FunctionCalls {
			resp.FunctionCalls = append(resp.FunctionCalls, fc)
		}
		respMutex.Unlock()
	}
	
	// Call the LLM with streaming
	err := f.Client.GenerateStream(ctx, req, streamCallback)
	if err != nil {
		return fmt.Errorf("error generating LLM response: %w", err)
	}
	
	// Postprocess the response with all response processors
	for _, processor := range f.ResponseProcessors {
		err := processor.ProcessLive(ctx, ic, resp, callback)
		if err != nil {
			return fmt.Errorf("error in response processor %T: %w", processor, err)
		}
	}
	
	return nil
}