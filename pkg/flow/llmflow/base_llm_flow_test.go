// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
	"github.com/go-a2a/adk-go/pkg/model/models"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// MockRequestProcessor is a mock LlmRequestProcessor for testing.
type MockRequestProcessor struct {
	processFunc func(ctx *flow.LlmFlowContext, request *models.LlmRequest) (<-chan event.Event, error)
}

func (m *MockRequestProcessor) Run(ctx *flow.LlmFlowContext, request *models.LlmRequest) (<-chan event.Event, error) {
	return m.processFunc(ctx, request)
}

// MockResponseProcessor is a mock LlmResponseProcessor for testing.
type MockResponseProcessor struct {
	processFunc func(ctx *flow.LlmFlowContext, response *models.LlmResponse) (<-chan event.Event, error)
}

func (m *MockResponseProcessor) Run(ctx *flow.LlmFlowContext, response *models.LlmResponse) (<-chan event.Event, error) {
	return m.processFunc(ctx, response)
}

func TestNewBaseLlmFlow(t *testing.T) {
	modelID := "test-model"
	modelOptions := models.Option{}

	flow := NewBaseLlmFlow(modelID, modelOptions)

	if flow.modelID != modelID {
		t.Errorf("Expected modelID %s, got %s", modelID, flow.modelID)
	}

	if diff := cmp.Diff(modelOptions, flow.modelOptions); diff != "" {
		t.Errorf("ModelOptions mismatch (-want +got):\n%s", diff)
	}

	if len(flow.requestProcessors) != 0 {
		t.Errorf("Expected 0 request processors, got %d", len(flow.requestProcessors))
	}

	if len(flow.responseProcessors) != 0 {
		t.Errorf("Expected 0 response processors, got %d", len(flow.responseProcessors))
	}
}

func TestAddRequestProcessor(t *testing.T) {
	flow := NewBaseLlmFlow("test-model", models.Option{})

	processor := &MockRequestProcessor{
		processFunc: func(ctx *flow.LlmFlowContext, request *models.LlmRequest) (<-chan event.Event, error) {
			ch := make(chan event.Event)
			close(ch)
			return ch, nil
		},
	}

	flow.AddRequestProcessor(processor)

	if len(flow.requestProcessors) != 1 {
		t.Errorf("Expected 1 request processor, got %d", len(flow.requestProcessors))
	}
}

func TestAddResponseProcessor(t *testing.T) {
	flow := NewBaseLlmFlow("test-model", models.Option{})

	processor := &MockResponseProcessor{
		processFunc: func(ctx *flow.LlmFlowContext, response *models.LlmResponse) (<-chan event.Event, error) {
			ch := make(chan event.Event)
			close(ch)
			return ch, nil
		},
	}

	flow.AddResponseProcessor(processor)

	if len(flow.responseProcessors) != 1 {
		t.Errorf("Expected 1 response processor, got %d", len(flow.responseProcessors))
	}
}

func TestSetTools(t *testing.T) {
	flow := NewBaseLlmFlow("test-model", models.Option{})

	tools := []tool.Tool{
		{
			Name:        "test-tool",
			Description: "Test tool",
			Parameters:  map[string]any{},
		},
	}

	flow.SetTools(tools)

	if len(flow.tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(flow.tools))
	}

	if flow.tools[0].Name != "test-tool" {
		t.Errorf("Expected tool name 'test-tool', got '%s'", flow.tools[0].Name)
	}
}
