// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package llmflow

import (
	"context"
	
	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
	"github.com/go-a2a/adk-go/pkg/flow/llmflow/processors"
)

// ProcessorAdapter adapts flow.RequestProcessor to llmflow.RequestProcessor.
type ProcessorAdapter struct {
	Processor interface{}
}

// AdaptFlowProcessor adapts a flow processor to a llmflow processor.
func AdaptFlowProcessor(processor interface{}) interface{} {
	switch p := processor.(type) {
	case *processors.BasicRequestProcessor:
		return &FlowRequestProcessorAdapter{p}
	case *processors.InstructionsRequestProcessor:
		return &FlowRequestProcessorAdapter{p}
	case *processors.IdentityRequestProcessor:
		return &FlowRequestProcessorAdapter{p}
	case *processors.ContentsRequestProcessor:
		return &FlowRequestProcessorAdapter{p}
	case *processors.NLPlanningRequestProcessor:
		return &FlowRequestProcessorAdapter{p}
	case *processors.CodeExecutionRequestProcessor:
		return &FlowRequestProcessorAdapter{p}
	case *processors.AgentTransferRequestProcessor:
		return &FlowRequestProcessorAdapter{p}
	case *processors.NLPlanningResponseProcessor:
		return &FlowResponseProcessorAdapter{p}
	case *processors.CodeExecutionResponseProcessor:
		return &FlowResponseProcessorAdapter{p}
	default:
		return nil
	}
}

// FlowRequestProcessorAdapter adapts flow.RequestProcessor to llmflow.RequestProcessor.
type FlowRequestProcessorAdapter struct {
	Processor interface{}
}

// Process implements RequestProcessor.Process.
func (a *FlowRequestProcessorAdapter) Process(
	ctx context.Context,
	ic *InvocationContext,
	req *LLMRequest,
) (<-chan *event.Event, error) {
	// Convert InvocationContext to flow.InvocationContext
	flowContext := &flow.InvocationContext{
		SessionID:   ic.SessionID,
		ExecutionID: ic.ExecutionID,
		Events:      ic.Events,
		Properties:  ic.Properties,
	}
	
	// Convert LLMRequest to flow.LLMRequest
	flowRequest := &flow.LLMRequest{
		Model:             req.Model,
		System:            req.System,
		ConnectionOptions: req.ConnectionOptions,
	}
	
	// Convert Messages
	for _, msg := range req.Messages {
		flowMessage := flow.Message{
			Role:         msg.Role,
			Content:      msg.Content,
			Name:         msg.Name,
			FunctionCalls: msg.FunctionCalls,
		}
		flowRequest.Messages = append(flowRequest.Messages, flowMessage)
	}
	
	// Convert Tools
	for _, tool := range req.Tools {
		flowTool := flow.Tool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
		}
		flowRequest.Tools = append(flowRequest.Tools, flowTool)
	}
	
	// Convert GenerationConfig
	if req.GenerationConfig != nil {
		flowRequest.GenerationConfig = &flow.GenerationConfig{
			Temperature:   req.GenerationConfig.Temperature,
			MaxTokens:     req.GenerationConfig.MaxTokens,
			TopP:          req.GenerationConfig.TopP,
			TopK:          req.GenerationConfig.TopK,
			StopSequences: req.GenerationConfig.StopSequences,
		}
	}
	
	// Call the underlying processor's Process method
	var eventsCh <-chan *event.Event
	var err error
	
	switch p := a.Processor.(type) {
	case *processors.BasicRequestProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowRequest)
	case *processors.InstructionsRequestProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowRequest)
	case *processors.IdentityRequestProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowRequest)
	case *processors.ContentsRequestProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowRequest)
	case *processors.NLPlanningRequestProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowRequest)
	case *processors.CodeExecutionRequestProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowRequest)
	case *processors.AgentTransferRequestProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowRequest)
	}
	
	// Copy back any changes from flow.LLMRequest to LLMRequest
	req.Model = flowRequest.Model
	req.System = flowRequest.System
	
	return eventsCh, err
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (a *FlowRequestProcessorAdapter) ProcessLive(
	ctx context.Context,
	ic *InvocationContext,
	req *LLMRequest,
	callback func(*event.Event),
) error {
	// Convert InvocationContext to flow.InvocationContext
	flowContext := &flow.InvocationContext{
		SessionID:   ic.SessionID,
		ExecutionID: ic.ExecutionID,
		Events:      ic.Events,
		Properties:  ic.Properties,
	}
	
	// Convert LLMRequest to flow.LLMRequest
	flowRequest := &flow.LLMRequest{
		Model:             req.Model,
		System:            req.System,
		ConnectionOptions: req.ConnectionOptions,
	}
	
	// Call the underlying processor's ProcessLive method
	var err error
	
	switch p := a.Processor.(type) {
	case *processors.BasicRequestProcessor:
		err = p.ProcessLive(ctx, flowContext, flowRequest, callback)
	case *processors.InstructionsRequestProcessor:
		err = p.ProcessLive(ctx, flowContext, flowRequest, callback)
	case *processors.IdentityRequestProcessor:
		err = p.ProcessLive(ctx, flowContext, flowRequest, callback)
	case *processors.ContentsRequestProcessor:
		err = p.ProcessLive(ctx, flowContext, flowRequest, callback)
	case *processors.NLPlanningRequestProcessor:
		err = p.ProcessLive(ctx, flowContext, flowRequest, callback)
	case *processors.CodeExecutionRequestProcessor:
		err = p.ProcessLive(ctx, flowContext, flowRequest, callback)
	case *processors.AgentTransferRequestProcessor:
		err = p.ProcessLive(ctx, flowContext, flowRequest, callback)
	}
	
	// Copy back any changes from flow.LLMRequest to LLMRequest
	req.Model = flowRequest.Model
	req.System = flowRequest.System
	
	return err
}

// FlowResponseProcessorAdapter adapts flow.ResponseProcessor to llmflow.ResponseProcessor.
type FlowResponseProcessorAdapter struct {
	Processor interface{}
}

// Process implements ResponseProcessor.Process.
func (a *FlowResponseProcessorAdapter) Process(
	ctx context.Context,
	ic *InvocationContext,
	resp *LLMResponse,
) (<-chan *event.Event, error) {
	// Convert InvocationContext to flow.InvocationContext
	flowContext := &flow.InvocationContext{
		SessionID:   ic.SessionID,
		ExecutionID: ic.ExecutionID,
		Events:      ic.Events,
		Properties:  ic.Properties,
	}
	
	// Convert LLMResponse to flow.LLMResponse
	flowResponse := &flow.LLMResponse{
		Content:       resp.Content,
		FunctionCalls: resp.FunctionCalls,
	}
	
	// Call the underlying processor's Process method
	var eventsCh <-chan *event.Event
	var err error
	
	switch p := a.Processor.(type) {
	case *processors.NLPlanningResponseProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowResponse)
	case *processors.CodeExecutionResponseProcessor:
		eventsCh, err = p.Process(ctx, flowContext, flowResponse)
	}
	
	// Copy back any changes from flow.LLMResponse to LLMResponse
	resp.Content = flowResponse.Content
	
	return eventsCh, err
}

// ProcessLive implements ResponseProcessor.ProcessLive.
func (a *FlowResponseProcessorAdapter) ProcessLive(
	ctx context.Context,
	ic *InvocationContext,
	resp *LLMResponse,
	callback func(*event.Event),
) error {
	// Convert InvocationContext to flow.InvocationContext
	flowContext := &flow.InvocationContext{
		SessionID:   ic.SessionID,
		ExecutionID: ic.ExecutionID,
		Events:      ic.Events,
		Properties:  ic.Properties,
	}
	
	// Convert LLMResponse to flow.LLMResponse
	flowResponse := &flow.LLMResponse{
		Content:       resp.Content,
		FunctionCalls: resp.FunctionCalls,
	}
	
	// Call the underlying processor's ProcessLive method
	var err error
	
	switch p := a.Processor.(type) {
	case *processors.NLPlanningResponseProcessor:
		err = p.ProcessLive(ctx, flowContext, flowResponse, callback)
	case *processors.CodeExecutionResponseProcessor:
		err = p.ProcessLive(ctx, flowContext, flowResponse, callback)
	}
	
	// Copy back any changes from flow.LLMResponse to LLMResponse
	resp.Content = flowResponse.Content
	
	return err
}