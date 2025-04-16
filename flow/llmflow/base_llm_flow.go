// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/flow"
	"github.com/go-a2a/adk-go/model/models"
	"github.com/go-a2a/adk-go/session"
)

// BaseLlmFlow is a base implementation for LLM flows.
type BaseLlmFlow struct {
	requestProcessors  []LlmRequestProcessor
	responseProcessors []LlmResponseProcessor
	modelID            string
	modelOptions       *genai.GenerateContentConfig
	tools              []*genai.Tool
}

var _ flow.Flow = (*BaseLlmFlow)(nil)

// NewBaseLlmFlow creates a new BaseLlmFlow.
func NewBaseLlmFlow(modelID string, config *genai.GenerateContentConfig) *BaseLlmFlow {
	return &BaseLlmFlow{
		requestProcessors:  []LlmRequestProcessor{},
		responseProcessors: []LlmResponseProcessor{},
		modelID:            modelID,
		modelOptions:       config,
		tools:              []*genai.Tool{},
	}
}

// AddRequestProcessor adds a request processor to the flow.
func (f *BaseLlmFlow) AddRequestProcessor(processor LlmRequestProcessor) {
	f.requestProcessors = append(f.requestProcessors, processor)
}

// AddResponseProcessor adds a response processor to the flow.
func (f *BaseLlmFlow) AddResponseProcessor(processor LlmResponseProcessor) {
	f.responseProcessors = append(f.responseProcessors, processor)
}

// SetTools sets the tools available to the language model.
func (f *BaseLlmFlow) SetTools(tools ...*genai.Tool) {
	f.tools = tools
}

// Run executes the flow and returns a channel of events.
func (f *BaseLlmFlow) Run(ctx context.Context, sess *session.Session) (<-chan event.Event, error) {
	modelProvider, err := models.DefaultRegistry.GetModel(f.modelID)
	if err != nil {
		return nil, fmt.Errorf("failed to get model provider: %w", err)
	}

	flowCtx := flow.NewLlmFlowContext(ctx, "", sess, modelProvider)
	eventCh := make(chan event.Event, 100)

	go func() {
		defer close(eventCh)

		// Create initial LLM request
		request := &models.LlmRequest{
			Model:  f.modelID,
			Config: f.modelOptions,
			Tools:  f.tools,
		}

		// Process request
		err := f.processRequest(flowCtx, request, eventCh)
		if err != nil {
			slog.ErrorContext(ctx, "Error processing request", "error", err)
			return
		}

		// Call LLM
		llmResponse, err := f.callLLM(flowCtx, request)
		if err != nil {
			slog.ErrorContext(ctx, "Error calling LLM", "error", err)
			return
		}

		// Process response
		err = f.processResponse(flowCtx, llmResponse, eventCh)
		if err != nil {
			slog.ErrorContext(ctx, "Error processing response", "error", err)
			return
		}
	}()

	return eventCh, nil
}

// RunLive executes the flow in streaming mode and returns a channel of events.
func (f *BaseLlmFlow) RunLive(ctx context.Context, sess *session.Session) (<-chan event.Event, error) {
	modelProvider, err := models.DefaultRegistry.GetModel(f.modelID)
	if err != nil {
		return nil, fmt.Errorf("failed to get model provider: %w", err)
	}

	flowCtx := flow.NewLlmFlowContext(ctx, sess, modelProvider)
	eventCh := make(chan event.Event, 100)

	go func() {
		defer close(eventCh)

		// Create initial LLM request
		request := &models.LlmRequest{
			Model:  f.modelID,
			Config: f.modelOptions,
			Tools:  f.tools,
		}

		// Process request
		err := f.processRequest(flowCtx, request, eventCh)
		if err != nil {
			slog.ErrorContext(ctx, "Error processing request", "error", err)
			return
		}

		// Call LLM with streaming
		err = f.callLLMLive(flowCtx, request, eventCh)
		if err != nil {
			slog.ErrorContext(ctx, "Error calling LLM live", "error", err)
			return
		}
	}()

	return eventCh, nil
}

// processRequest processes the LLM request through all request processors.
func (f *BaseLlmFlow) processRequest(ctx *flow.LlmFlowContext, request *models.LlmRequest, out chan<- event.Event) error {
	for _, processor := range f.requestProcessors {
		processorEvents, err := processor.Run(ctx, request)
		if err != nil {
			return fmt.Errorf("request processor error: %w", err)
		}

		// Forward all events to the output channel
		for evt := range processorEvents {
			out <- evt
		}
	}
	return nil
}

// processResponse processes the LLM response through all response processors.
func (f *BaseLlmFlow) processResponse(ctx *flow.LlmFlowContext, response *models.LlmResponse, out chan<- event.Event) error {
	for _, processor := range f.responseProcessors {
		processorEvents, err := processor.Run(ctx, response)
		if err != nil {
			return fmt.Errorf("response processor error: %w", err)
		}

		// Forward all events to the output channel
		for evt := range processorEvents {
			out <- evt
		}
	}
	return nil
}

// callLLM calls the language model and returns the response.
func (f *BaseLlmFlow) callLLM(ctx *flow.LlmFlowContext, request *models.LlmRequest) (*models.LlmResponse, error) {
	// modelClient, err := ctx.Model.GetModelClient(ctx.Context, request.ModelID)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get model client: %w", err)
	// }

	contentObjs := make([]*genai.Content, len(request.Contents))
	copy(contentObjs, request.Contents)

	// Convert tools to model-specific format
	request.Config.Tools = make([]*genai.Tool, len(request.Tools))
	copy(request.Config.Tools, request.Tools)

	// Call the model
	resp, err := ctx.Models.GenerateContent(ctx.Context, string(ctx.Provider), contentObjs, request.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	// Extract function calls from response
	var functionCalls []*genai.FunctionCall
	// This would depend on the specific implementation of model.Response
	// For simplicity, we're assuming a method like GetFunctionCalls() exists

	contens := make([]*genai.Content, len(resp.Candidates))
	for i, candidate := range resp.Candidates {
		contens[i] = candidate.Content
	}

	return &models.LlmResponse{
		Request:       request,
		Content:       contens,
		FunctionCalls: functionCalls,
	}, nil
}

// callLLMLive calls the language model in streaming mode and sends events to the output channel.
func (f *BaseLlmFlow) callLLMLive(ctx *flow.LlmFlowContext, request *models.LlmRequest, out chan<- event.Event) error {
	// modelClient := ctx.Models
	// if err != nil {
	// 	return fmt.Errorf("failed to get model client: %w", err)
	// }

	contentObjs := make([]*genai.Content, len(request.Contents))
	copy(contentObjs, request.Contents)

	// Convert tools to model-specific format
	request.Config.Tools = make([]*genai.Tool, len(request.Tools))
	copy(request.Config.Tools, request.Tools)

	// Call the model with streaming
	respCh := ctx.Models.GenerateContentStream(ctx.Context, string(ctx.Provider), contentObjs, request.Config)

	var streamResponse models.LlmResponse
	streamResponse.Request = request

	// Process streaming response
	for resp := range respCh {
		streamResponse.Content = append(streamResponse.Content, resp.Text())

		// Convert model response to events and send to output channel
		// For now, just emit a simple message event
		for _, candidate := range resp.Candidates {
			ev, err := event.NewEvent(candidate.Content.Role, candidate.Content)
			if err != nil {
				return fmt.Errorf("failed to new event: %w", err)
			}
			out <- *ev
		}
	}

	// Process the complete response
	return f.processResponse(ctx, &streamResponse, out)
}
