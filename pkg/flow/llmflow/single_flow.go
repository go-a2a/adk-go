// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package llmflow

import (
	"log/slog"
	
	"github.com/go-a2a/adk-go/pkg/flow/llmflow/processors"
)

// SingleFlow represents a simple flow with a single agent and no sub-agents.
type SingleFlow struct {
	*BaseLLMFlow
}

// NewSingleFlow creates a new SingleFlow with standard processors.
func NewSingleFlow(client LLMClient, logger *slog.Logger) *SingleFlow {
	baseFlow := NewBaseLLMFlow("SingleFlow", client, logger)
	
	flow := &SingleFlow{
		BaseLLMFlow: baseFlow,
	}
	
	// Add standard request processors
	reqProcessors := []interface{}{
		processors.NewBasicRequestProcessor(),
		processors.NewInstructionsRequestProcessor(),
		processors.NewIdentityRequestProcessor(),
		processors.NewContentsRequestProcessor(),
		processors.NewNLPlanningRequestProcessor(),
		processors.NewCodeExecutionRequestProcessor(),
	}
	
	for _, p := range reqProcessors {
		if adapter, ok := AdaptFlowProcessor(p).(RequestProcessor); ok {
			flow.AddRequestProcessor(adapter)
		}
	}
	
	// Add standard response processors
	respProcessors := []interface{}{
		processors.NewNLPlanningResponseProcessor(),
		processors.NewCodeExecutionResponseProcessor(),
	}
	
	for _, p := range respProcessors {
		if adapter, ok := AdaptFlowProcessor(p).(ResponseProcessor); ok {
			flow.AddResponseProcessor(adapter)
		}
	}
	
	return flow
}