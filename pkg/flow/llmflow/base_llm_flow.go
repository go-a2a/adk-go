// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
)

// LLMClient defines the interface for communicating with a language model.
type LLMClient interface {
	// Generate generates a response from the language model.
	Generate(ctx context.Context, req *LLMRequest) (*LLMResponse, error)

	// GenerateStream generates a streaming response from the language model.
	GenerateStream(ctx context.Context, req *LLMRequest, callback func(*LLMResponse)) error
}

// ModelAdapter adapts a model.Model to the LLMClient interface
type ModelAdapter struct {
	model model.Model
}

// NewModelAdapter creates a new adapter for a model.
func NewModelAdapter(model model.Model) *ModelAdapter {
	return &ModelAdapter{
		model: model,
	}
}

// Generate adapts the model.Generate method to the LLMClient interface.
func (a *ModelAdapter) Generate(ctx context.Context, req *LLMRequest) (*LLMResponse, error) {
	// Convert LLMRequest to model's messages format
	messages := make([]message.Message, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = message.Message{
			Role:    message.Role(msg.Role),
			Content: msg.Content,
		}
	}

	// Set generation options based on request
	opts := model.GenerateOptions{
		Temperature: req.GenerationConfig.Temperature,
		MaxTokens:   req.GenerationConfig.MaxTokens,
		TopP:        req.GenerationConfig.TopP,
	}

	// Generate response
	resp, err := a.model.GenerateWithOptions(ctx, messages, opts)
	if err != nil {
		return nil, fmt.Errorf("model generation failed: %w", err)
	}

	// Convert model response to LLMResponse
	llmResp := &LLMResponse{
		Content: resp.Content,
	}

	return llmResp, nil
}

// GenerateStream adapts the model.GenerateStream method to the LLMClient interface.
func (a *ModelAdapter) GenerateStream(ctx context.Context, req *LLMRequest, callback func(*LLMResponse)) error {
	// Convert LLMRequest to model's messages format
	messages := make([]message.Message, len(req.Messages))
	for i, msg := range req.Messages {
		messages[i] = message.Message{
			Role:    message.Role(msg.Role),
			Content: msg.Content,
		}
	}

	// Create a response handler that adapts to the callback
	responseHandler := func(chunk message.Message) {
		callback(&LLMResponse{
			Content: chunk.Content,
		})
	}

	// Stream the response
	err := a.model.GenerateStream(ctx, messages, responseHandler)
	if err != nil {
		return fmt.Errorf("model streaming failed: %w", err)
	}

	return nil
}

// BaseLLMFlow provides a base implementation for LLM-based flows.
// It implements the flow.Flow interface while maintaining backward compatibility.
type BaseLLMFlow struct {
	// Name is the name of this flow.
	Name string

	// Client is the client for communicating with the language model.
	Client LLMClient

	// Model is the model used for newer implementations
	Model model.Model

	// RequestProcessors is the list of processors for preprocessing requests.
	RequestProcessors []RequestProcessor

	// ResponseProcessors is the list of processors for postprocessing responses.
	ResponseProcessors []ResponseProcessor

	// NewRequestProcessors is the list of newer processors for preprocessing requests.
	NewRequestProcessors []flow.RequestProcessor

	// NewResponseProcessors is the list of newer processors for postprocessing responses.
	NewResponseProcessors []flow.ResponseProcessor

	// Logger is used for logging.
	Logger *slog.Logger

	// ProcessorChain manages the sequence of processors.
	ProcessorChain *flow.ProcessorChain
}

// NewBaseLLMFlow creates a new BaseLLMFlow with the given client.
func NewBaseLLMFlow(name string, client LLMClient, logger *slog.Logger) *BaseLLMFlow {
	if logger == nil {
		logger = slog.Default()
	}

	return &BaseLLMFlow{
		Name:                  name,
		Client:                client,
		RequestProcessors:     []RequestProcessor{},
		ResponseProcessors:    []ResponseProcessor{},
		NewRequestProcessors:  []flow.RequestProcessor{},
		NewResponseProcessors: []flow.ResponseProcessor{},
		Logger:                logger,
		ProcessorChain:        flow.NewProcessorChain(logger),
	}
}

// NewBaseLLMFlowWithModel creates a new BaseLLMFlow with a model.
func NewBaseLLMFlowWithModel(name string, model model.Model, options *flow.FlowOptions) *BaseLLMFlow {
	if options == nil {
		options = flow.DefaultFlowOptions()
	}

	return &BaseLLMFlow{
		Name:                  name,
		Model:                 model,
		Client:                NewModelAdapter(model),
		NewRequestProcessors:  options.ProcessorConfig.RequestProcessors,
		NewResponseProcessors: options.ProcessorConfig.ResponseProcessors,
		Logger:                options.Logger,
		ProcessorChain:        flow.NewProcessorChain(options.Logger),
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

// AddNewRequestProcessor adds a new-style request processor to the flow.
func (f *BaseLLMFlow) AddNewRequestProcessor(processor flow.RequestProcessor) *BaseLLMFlow {
	f.NewRequestProcessors = append(f.NewRequestProcessors, processor)
	return f
}

// AddNewResponseProcessor adds a new-style response processor to the flow.
func (f *BaseLLMFlow) AddNewResponseProcessor(processor flow.ResponseProcessor) *BaseLLMFlow {
	f.NewResponseProcessors = append(f.NewResponseProcessors, processor)
	return f
}

// Run executes the flow with the given context and returns a channel of events.
// This method supports both old-style InvocationContext and new-style flow.InvocationContext.
func (f *BaseLLMFlow) Run(ctx context.Context, ic any) (<-chan *event.Event, error) {
	// Choose execution strategy based on context type
	switch typedIC := ic.(type) {
	case *InvocationContext:
		return f.runLegacy(ctx, typedIC)
	case *flow.InvocationContext:
		return f.runNew(ctx, typedIC)
	default:
		return nil, fmt.Errorf("unsupported invocation context type: %T", ic)
	}
}

// runLegacy implements the legacy Run method for backward compatibility.
func (f *BaseLLMFlow) runLegacy(ctx context.Context, ic *InvocationContext) (<-chan *event.Event, error) {
	events := make(chan *event.Event)

	go func() {
		defer close(events)

		// Create a context with a span for the flow execution
		runCtx, span := observability.StartSpan(ctx, "llmflow.RunLegacy")
		defer span.End()

		// Set attributes for the span
		span.SetAttributes(
			attribute.String("flow.name", f.Name),
			attribute.String("session_id", ic.SessionID),
		)

		// Create a default request
		req := &LLMRequest{
			GenerationConfig: &GenerationConfig{
				Temperature: 0.7,
				MaxTokens:   1024,
			},
			ConnectionOptions: make(map[string]any),
		}

		// Preprocess the request with all request processors
		for _, processor := range f.RequestProcessors {
			processorEvents, err := processor.Process(runCtx, ic, req)
			if err != nil {
				observability.Error(runCtx, err, "Error in request processor",
					slog.String("processor", fmt.Sprintf("%T", processor)))
				return
			}

			// Forward processor events to the output channel
			for evt := range processorEvents {
				events <- evt
			}
		}

		// Call the LLM
		resp, err := f.Client.Generate(runCtx, req)
		if err != nil {
			observability.Error(runCtx, err, "Error generating LLM response")
			return
		}

		// Postprocess the response with all response processors
		for _, processor := range f.ResponseProcessors {
			processorEvents, err := processor.Process(runCtx, ic, resp)
			if err != nil {
				observability.Error(runCtx, err, "Error in response processor",
					slog.String("processor", fmt.Sprintf("%T", processor)))
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

// runNew implements the new Run method using the improved flow.InvocationContext.
func (f *BaseLLMFlow) runNew(ctx context.Context, ic *flow.InvocationContext) (<-chan *event.Event, error) {
	events := make(chan *event.Event, 10) // Buffer size of 10 to avoid blocking

	go func() {
		defer close(events)

		// Create a context with a span for the flow execution
		runCtx, span := observability.StartSpan(ctx, "llmflow.RunNew")
		defer span.End()

		// Set attributes for the span
		span.SetAttributes(
			attribute.String("flow.name", f.Name),
			attribute.String("session_id", ic.SessionID),
		)

		// If there are no messages, nothing to do
		if len(ic.Messages) == 0 {
			observability.Warn(runCtx, "No messages to process in flow")
			return
		}

		// Get the last message as the request
		requestMsg := ic.Messages[len(ic.Messages)-1]

		// Process the request through request processors
		processedReq, err := f.ProcessorChain.RunRequestProcessors(runCtx, ic, requestMsg, f.NewRequestProcessors)
		if err != nil {
			observability.Error(runCtx, err, "Error processing request through processors")
			return
		}

		// Create a MessageEvent for the processed request
		reqEvent := event.NewMessageEvent(processedReq)
		events <- reqEvent

		// Generate a response from the model
		resp, err := f.Model.Generate(runCtx, ic.Messages)
		if err != nil {
			observability.Error(runCtx, err, "Error generating response from model")
			return
		}

		// Process the response through response processors
		processedResp, err := f.ProcessorChain.RunResponseProcessors(runCtx, ic, resp, f.NewResponseProcessors)
		if err != nil {
			observability.Error(runCtx, err, "Error processing response through processors")
			return
		}

		// Create a MessageEvent for the processed response
		respEvent := event.NewMessageEvent(processedResp)
		events <- respEvent

		observability.Info(runCtx, "LLM flow execution completed")
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
		ConnectionOptions: make(map[string]any),
	}

	// Create a context with a span for the flow execution
	liveCtx, span := observability.StartSpan(ctx, "llmflow.RunLive")
	defer span.End()

	// Set attributes for the span
	span.SetAttributes(
		attribute.String("flow.name", f.Name),
		attribute.String("session_id", ic.SessionID),
	)

	// Preprocess the request with all request processors
	for _, processor := range f.RequestProcessors {
		err := processor.ProcessLive(liveCtx, ic, req, callback)
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
	err := f.Client.GenerateStream(liveCtx, req, streamCallback)
	if err != nil {
		return fmt.Errorf("error generating LLM response: %w", err)
	}

	// Postprocess the response with all response processors
	for _, processor := range f.ResponseProcessors {
		err := processor.ProcessLive(liveCtx, ic, resp, callback)
		if err != nil {
			return fmt.Errorf("error in response processor %T: %w", processor, err)
		}
	}

	return nil
}

// ProcessLive implements the Flow interface for streaming event processing.
func (f *BaseLLMFlow) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	callback func(*event.Event),
) error {
	// Create a context with a span for the flow execution
	liveCtx, span := observability.StartSpan(ctx, "llmflow.ProcessLive")
	defer span.End()

	// Execute the flow but stream events to the callback
	eventCh, err := f.runNew(liveCtx, ic)
	if err != nil {
		return fmt.Errorf("failed to execute flow: %w", err)
	}

	// Stream events to the callback
	for event := range eventCh {
		callback(event)
	}

	return nil
}
