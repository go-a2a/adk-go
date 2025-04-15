// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package models

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-a2a/adk-go/message"
	"github.com/go-a2a/adk-go/model"
)

// MockModel is a mock implementation of the Model interface for testing.
type MockModel struct {
	*Model
	Responses      map[string]string
	ToolResponses  map[string][]message.ToolCall
	StreamResponse []string
	ErrorToReturn  error
}

// NewMockModel creates a new mock model.
func NewMockModel(modelID string) *MockModel {
	capabilities := []model.ModelCapability{
		model.ModelCapabilityToolCalling,
		model.ModelCapabilityJSON,
		model.ModelCapabilityStreaming,
		model.ModelCapabilityFunctionCalling,
	}

	m := &MockModel{
		Responses:      make(map[string]string),
		ToolResponses:  make(map[string][]message.ToolCall),
		StreamResponse: []string{},
	}

	m.Model = NewBaseModel(modelID, model.ModelProviderMock, capabilities, m.generateContent)

	return m
}

// generateContent is the generator function for the mock model.
func (m *MockModel) generateContent(ctx context.Context, modelID string, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	if m.ErrorToReturn != nil {
		return message.Message{}, m.ErrorToReturn
	}

	// Check if there's a specific response for the last message
	if len(messages) > 0 {
		lastMsg := messages[len(messages)-1]
		if response, ok := m.Responses[lastMsg.Content]; ok {
			return message.NewAssistantMessage(response), nil
		}
	}

	// Generate a simple response echoing the last message
	if len(messages) > 0 {
		lastMsg := messages[len(messages)-1]
		return message.NewAssistantMessage(fmt.Sprintf("Mock response to: %s", lastMsg.Content)), nil
	}

	return message.NewAssistantMessage("Mock response."), nil
}

// GenerateWithTools overrides the base implementation.
func (m *MockModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	if m.ErrorToReturn != nil {
		return message.Message{}, m.ErrorToReturn
	}

	// Check if there's a specific tool response for the last message
	if len(messages) > 0 {
		lastMsg := messages[len(messages)-1]
		if toolCalls, ok := m.ToolResponses[lastMsg.Content]; ok {
			return message.NewAssistantToolCallMessage(toolCalls), nil
		}
	}

	// Generate a default tool call
	toolCalls := []message.ToolCall{
		{
			ID:   "mock_tool_call_1",
			Name: "search",
			Args: []byte(`{"query": "mock search query"}`),
		},
	}

	return message.NewAssistantToolCallMessage(toolCalls), nil
}

// GenerateStream overrides the base implementation.
func (m *MockModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	if m.ErrorToReturn != nil {
		return m.ErrorToReturn
	}

	// If stream response is configured, use it
	if len(m.StreamResponse) > 0 {
		for _, chunk := range m.StreamResponse {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Continue processing
			}

			handler(message.NewAssistantMessage(chunk))
		}
		return nil
	}

	// Generate a simple stream response based on the last message
	var content string
	if len(messages) > 0 {
		lastMsg := messages[len(messages)-1]
		content = fmt.Sprintf("Mock streaming response to: %s", lastMsg.Content)
	} else {
		content = "Mock streaming response."
	}

	// Split the content into words for streaming
	words := strings.SplitSeq(content, " ")
	for word := range words {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Continue processing
		}

		handler(message.NewAssistantMessage(word + " "))
	}

	return nil
}

// SetResponse sets a predefined response for a specific input.
func (m *MockModel) SetResponse(input, response string) {
	m.Responses[input] = response
}

// SetToolResponse sets a predefined tool call response for a specific input.
func (m *MockModel) SetToolResponse(input string, toolCalls []message.ToolCall) {
	m.ToolResponses[input] = toolCalls
}

// SetStreamResponse sets a predefined streaming response.
func (m *MockModel) SetStreamResponse(chunks []string) {
	m.StreamResponse = chunks
}

// SetError sets an error to be returned by the model.
func (m *MockModel) SetError(err error) {
	m.ErrorToReturn = err
}

func init() {
	// Register the mock model with the registry
	Register("mock.*", func(modelID string) (model.Model, error) {
		return NewMockModel(modelID), nil
	})
}
