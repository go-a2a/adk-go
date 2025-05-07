// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/types"
)

// LLMRequestProcessor defines an interface for processing LLM requests before they're sent to the model
type LLMRequestProcessor interface {
	// Process modifies the LLM request before it's sent to the model
	Process(ctx context.Context, ic *types.InvocationContext, req *types.LLMRequest) error
}

// LLMResponseProcessor defines an interface for processing LLM responses after they're received from the model
type LLMResponseProcessor interface {
	// Process modifies the LLM response after it's received from the model
	Process(ctx context.Context, ic *types.InvocationContext, resp *types.LLMResponse, event *types.Event) error
}

// LLMFlow provides common functionality for LLM-based flows.
type LLMFlow struct {
	model              model.Model
	logger             *slog.Logger
	requestProcessors  []LLMRequestProcessor
	responseProcessors []LLMResponseProcessor
}

// NewLLMFlow creates a new [LLMFlow] with the given model and options.
func NewLLMFlow(model model.Model, opts ...FlowOption) (*LLMFlow, error) {
	if model == nil {
		return nil, fmt.Errorf("model cannot be nil")
	}

	flow := &LLMFlow{
		model:              model,
		logger:             slog.Default().With("component", "flow"),
		requestProcessors:  make([]LLMRequestProcessor, 0),
		responseProcessors: make([]LLMResponseProcessor, 0),
	}

	// Apply options
	for _, opt := range opts {
		if err := opt.apply(flow); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return flow, nil
}

// AddRequestProcessor adds a request processor to the flow
func (f *LLMFlow) AddRequestProcessor(processor LLMRequestProcessor) {
	f.requestProcessors = append(f.requestProcessors, processor)
}

// AddResponseProcessor adds a response processor to the flow
func (f *LLMFlow) AddResponseProcessor(processor LLMResponseProcessor) {
	f.responseProcessors = append(f.responseProcessors, processor)
}

// ProcessContent processes the given contents through the LLM.
func (f *LLMFlow) ProcessContent(ctx context.Context, contents []*genai.Content) (*types.LLMResponse, error) {
	if len(contents) == 0 {
		return nil, fmt.Errorf("contents cannot be empty")
	}

	req := &types.LLMRequest{
		Contents: contents,
	}

	f.logger.DebugContext(ctx, "processing content", "num_contents", len(contents))
	return f.model.GenerateContent(ctx, req)
}

// RunLive runs the flow using a live connection to the model, streaming results back
// through the event channel
func (f *LLMFlow) RunLive(ctx context.Context, ic *types.InvocationContext) (<-chan *types.Event, error) {
	eventCh := make(chan *types.Event)

	llmRequest := &types.LLMRequest{}
	eventID := types.NewEventID()

	// Run in a goroutine to handle the async flow
	go func() {
		defer close(eventCh)

		// Preprocess before calling the LLM
		for _, processor := range f.requestProcessors {
			if err := processor.Process(ctx, ic, llmRequest); err != nil {
				f.logger.ErrorContext(ctx, "error in request processor", "error", err)
				// Send error event
				eventCh <- &types.Event{
					InvocationID: ic.InvocationID,
					Author:       model.RoleSystem,
					LLMResponse: &types.LLMResponse{
						ErrorCode:    "REQUEST_PROCESSOR_ERROR",
						ErrorMessage: err.Error(),
					},
				}
				return
			}
		}

		if ic.EndInvocation {
			return
		}

		// Get the LLM model
		llm, ok := getLLM(ic)
		if !ok {
			f.logger.ErrorContext(ctx, "failed to get LLM model from invocation context")
			eventCh <- &types.Event{
				InvocationID: ic.InvocationID,
				Author:       model.RoleSystem,
				LLMResponse: &types.LLMResponse{
					ErrorCode:    "MODEL_ERROR",
					ErrorMessage: "failed to get LLM model from invocation context",
				},
			}
			return
		}

		// Establish live connection
		f.logger.DebugContext(ctx, "establishing live connection",
			"agent", ic.Agent.Name(),
			"request", fmt.Sprintf("%+v", llmRequest))

		connection, err := llm.Connect()
		if err != nil {
			f.logger.ErrorContext(ctx, "failed to establish live connection", "error", err)
			eventCh <- &types.Event{
				InvocationID: ic.InvocationID,
				Author:       model.RoleSystem,
				LLMResponse: &types.LLMResponse{
					ErrorCode:    "CONNECTION_ERROR",
					ErrorMessage: err.Error(),
				},
			}
			return
		}
		defer connection.Close()

		// Handle transcription cache if present
		if llmRequest.Contents != nil && len(llmRequest.Contents) > 0 {
			if ic.TranscriptionCache != nil {
				// TODO: Implement transcription handling
				// For now, just log that we would handle transcription
				f.logger.DebugContext(ctx, "would handle transcription here")
			} else {
				// Send history to model
				f.logger.DebugContext(ctx, "sending history to model",
					"content_count", len(llmRequest.Contents))

				err := connection.SendHistory(ctx, llmRequest.Contents)
				if err != nil {
					f.logger.ErrorContext(ctx, "failed to send history", "error", err)
					eventCh <- &types.Event{
						InvocationID: ic.InvocationID,
						Author:       model.RoleSystem,
						LLMResponse: &types.LLMResponse{
							ErrorCode:    "SEND_HISTORY_ERROR",
							ErrorMessage: err.Error(),
						},
					}
					return
				}
			}
		}

		// Start goroutine to send user inputs
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.sendToModel(ctx, connection, ic, eventCh)
		}()

		// Receive from model
		f.receiveFromModel(ctx, connection, eventID, ic, llmRequest, eventCh)

		// Wait for send goroutine to complete
		wg.Wait()
	}()

	return eventCh, nil
}

// sendToModel handles sending user inputs to the model
func (f *LLMFlow) sendToModel(ctx context.Context, connection model.BaseConnection, ic *types.InvocationContext, eventCh chan<- *types.Event) {
	// Check if we have a live request queue
	liveQueue, ok := ic.Agent.(*types.LiveRequestQueue)
	if !ok {
		f.logger.DebugContext(ctx, "agent doesn't have a live request queue, nothing to send")
		return
	}

	for {
		select {
		case <-ctx.Done():
			f.logger.DebugContext(ctx, "context canceled, stopping send loop")
			return

		default:
			// Poll for new user input
			request := liveQueue.Poll()
			if request == nil {
				// No request available, wait a bit
				time.Sleep(100 * time.Millisecond)
				continue
			}

			f.logger.DebugContext(ctx, "sending content to model", "content", request.Content)

			// Create genai Content
			content := &genai.Content{
				Parts: []*genai.Part{
					{Text: request.Content},
				},
				Role: "user",
			}

			// Send to model
			if err := connection.SendContent(ctx, content); err != nil {
				f.logger.ErrorContext(ctx, "failed to send content", "error", err)
				eventCh <- &types.Event{
					InvocationID: ic.InvocationID,
					Author:       model.RoleSystem,
					LLMResponse: &types.LLMResponse{
						ErrorCode:    "SEND_CONTENT_ERROR",
						ErrorMessage: err.Error(),
					},
				}
				return
			}
		}
	}
}

// receiveFromModel handles receiving responses from the model
func (f *LLMFlow) receiveFromModel(ctx context.Context, connection model.BaseConnection, eventID string, ic *types.InvocationContext, llmRequest *types.LLMRequest, eventCh chan<- *types.Event) {
	// This would normally require a receiver loop to handle streaming responses
	// For now, we'll implement a basic version that receives a complete response

	respCh, err := connection.Receive(ctx)
	if err != nil {
		f.logger.ErrorContext(ctx, "failed to start receiving content", "error", err)
		eventCh <- &types.Event{
			InvocationID: ic.InvocationID,
			Author:       model.RoleSystem,
			LLMResponse: &types.LLMResponse{
				ErrorCode:    "RECEIVE_CONTENT_ERROR",
				ErrorMessage: err.Error(),
			},
		}
		return
	}

	for resp := range respCh {
		// Create event from response
		event := &types.Event{
			InvocationID: ic.InvocationID,
			Author:       model.RoleAssistant,
			LLMResponse:  resp,
		}

		// Process response with processors
		for _, processor := range f.responseProcessors {
			if err := processor.Process(ctx, ic, resp, event); err != nil {
				f.logger.ErrorContext(ctx, "error in response processor", "error", err)
				// Continue with other processors
			}
		}

		// Finalize event
		event = f.finalizeModelResponseEvent(llmRequest, resp, event)

		// Send event to channel
		eventCh <- event

		// Handle function calls/responses if needed
		if len(event.GetFunctionCalls()) > 0 {
			f.logger.DebugContext(ctx, "event contains function calls",
				"function_count", len(event.GetFunctionCalls()))
			// TODO: Handle function calls
		}

		// Handle function responses if needed
		if len(event.GetFunctionResponses()) > 0 {
			f.logger.DebugContext(ctx, "event contains function responses",
				"response_count", len(event.GetFunctionResponses()))
			// TODO: Handle function responses and before-model callbacks
		}

		// Handle after-model callbacks
		if err := f.handleAfterModelCallback(ctx, ic, resp, event); err != nil {
			f.logger.ErrorContext(ctx, "error in after-model callback", "error", err)
		}
	}
}

// finalizeModelResponseEvent prepares the final event based on the LLM response
func (f *LLMFlow) finalizeModelResponseEvent(llmRequest *types.LLMRequest, llmResponse *types.LLMResponse, event *types.Event) *types.Event {
	// Deep copy the event to avoid modifying the original
	result := &types.Event{
		InvocationID: event.InvocationID,
		Author:       event.Author,
		LLMResponse:  llmResponse,
	}

	if result.Content != nil {
		functionCalls := result.GetFunctionCalls()
		if len(functionCalls) > 0 {
			// TODO: Populate client function call IDs

			// Identify long-running function calls
			if llmRequest.ToolMap != nil && len(llmRequest.ToolMap) > 0 {
				longRunningToolIDs := make([]string, 0)
				for _, call := range functionCalls {
					if tool, ok := llmRequest.ToolMap[call.Name]; ok {
						_ = tool
						// if tool.IsLongRunning() {
						// 	// We would add the function call ID here
						// 	// longRunningToolIDs = append(longRunningToolIDs, call.FunctionCallID)
						// }
					}
				}
				if len(longRunningToolIDs) > 0 {
					// Set long running tool IDs in event
					// event.LongRunningToolIDs = longRunningToolIDs
				}
			}
		}
	}

	return result
}

// handleAfterModelCallback processes callbacks that should run after the model has generated a response
func (f *LLMFlow) handleAfterModelCallback(ctx context.Context, ic *types.InvocationContext, llmResponse *types.LLMResponse, event *types.Event) error {
	// Check if agent supports callbacks
	agent, ok := ic.Agent.(types.CallbackAgent)
	if !ok {
		return nil
	}

	callbacks := agent.GetAfterModelCallbacks()
	if len(callbacks) == 0 {
		return nil
	}

	// Create callback context
	callbackCtx := &types.CallbackContext{
		Agent:    ic.Agent,
		Input:    ic.Input,
		Response: llmResponse,
	}

	// If event has actions, set them in the callback context
	if event.Actions != nil {
		callbackCtx.EventActions = event.Actions
	}

	// Run each callback in sequence
	for _, callback := range callbacks {
		if err := callback(callbackCtx); err != nil {
			return fmt.Errorf("after-model callback error: %w", err)
		}
	}

	return nil
}

// SetLogger sets the logger for this flow.
func (f *LLMFlow) SetLogger(logger *slog.Logger) {
	f.logger = logger
}

// GetModel returns the model used by this flow.
func (f *LLMFlow) GetModel() model.Model {
	return f.model
}

// getLLM extracts the LLM model from the invocation context
func getLLM(ic *types.InvocationContext) (model.Model, bool) {
	if ic == nil || ic.Agent == nil {
		return nil, false
	}

	// Check if the agent has a GetModel method
	if modelProvider, ok := ic.Agent.(interface{ GetModel() model.Model }); ok {
		return modelProvider.GetModel(), true
	}

	return nil, false
}
