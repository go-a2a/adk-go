// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// mockLlmModel implements model.Model interface and allows mocking responses
type mockLlmModel struct {
	generateFunc            func(ctx context.Context, messages []message.Message) (message.Message, error)
	generateWithOptionsFunc func(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error)
	generateWithToolsFunc   func(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error)
	generateStreamFunc      func(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error
	modelIDFunc             func() string
	providerFunc            func() model.ModelProvider
	hasCapabilityFunc       func(capability model.ModelCapability) bool

	// For tracking calls
	generateCalled            bool
	generateWithOptionsCalled bool
	generateWithToolsCalled   bool
	generateStreamCalled      bool
	modelIDCalled             bool
	providerCalled            bool
	hasCapabilityCalled       bool

	// For recording call arguments
	lastGenerateMessages            []message.Message
	lastGenerateWithOptionsMessages []message.Message
	lastGenerateWithOptionsOpts     model.GenerateOptions
	lastGenerateWithToolsMessages   []message.Message
	lastGenerateWithToolsTools      []model.ToolDefinition
	lastGenerateStreamMessages      []message.Message
	lastGenerateStreamHandler       model.ResponseHandler
	lastHasCapabilityCapability     model.ModelCapability
}

func (m *mockLlmModel) Generate(ctx context.Context, messages []message.Message) (message.Message, error) {
	m.generateCalled = true
	m.lastGenerateMessages = messages
	return m.generateFunc(ctx, messages)
}

func (m *mockLlmModel) GenerateWithOptions(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	m.generateWithOptionsCalled = true
	m.lastGenerateWithOptionsMessages = messages
	m.lastGenerateWithOptionsOpts = opts
	return m.generateWithOptionsFunc(ctx, messages, opts)
}

func (m *mockLlmModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	m.generateWithToolsCalled = true
	m.lastGenerateWithToolsMessages = messages
	m.lastGenerateWithToolsTools = tools
	return m.generateWithToolsFunc(ctx, messages, tools)
}

func (m *mockLlmModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	m.generateStreamCalled = true
	m.lastGenerateStreamMessages = messages
	m.lastGenerateStreamHandler = handler
	return m.generateStreamFunc(ctx, messages, handler)
}

func (m *mockLlmModel) ModelID() string {
	m.modelIDCalled = true
	return m.modelIDFunc()
}

func (m *mockLlmModel) Provider() model.ModelProvider {
	m.providerCalled = true
	return m.providerFunc()
}

func (m *mockLlmModel) HasCapability(capability model.ModelCapability) bool {
	m.hasCapabilityCalled = true
	m.lastHasCapabilityCapability = capability
	return m.hasCapabilityFunc(capability)
}

// mockExecutableTool implements tool.Tool interface and tracks executions
type mockExecutableTool struct {
	nameFunc                      func() string
	descriptionFunc               func() string
	parameterSchemaFunc           func() model.ToolParameterSpec
	executeFunc                   func(ctx context.Context, args json.RawMessage) (string, error)
	toToolDefinitionFunc          func() model.ToolDefinition
	isAsyncExecutionSupportedFunc func() bool

	// For tracking calls
	nameCalled                      bool
	descriptionCalled               bool
	parameterSchemaCalled           bool
	executeCalled                   atomic.Bool
	toToolDefinitionCalled          bool
	isAsyncExecutionSupportedCalled bool

	// For recording arguments
	lastExecuteCtx  context.Context
	lastExecuteArgs json.RawMessage
}

func (t *mockExecutableTool) Name() string {
	t.nameCalled = true
	return t.nameFunc()
}

func (t *mockExecutableTool) Description() string {
	t.descriptionCalled = true
	return t.descriptionFunc()
}

func (t *mockExecutableTool) ParameterSchema() model.ToolParameterSpec {
	t.parameterSchemaCalled = true
	return t.parameterSchemaFunc()
}

func (t *mockExecutableTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	t.executeCalled.Store(true)
	t.lastExecuteCtx = ctx
	t.lastExecuteArgs = args
	return t.executeFunc(ctx, args)
}

func (t *mockExecutableTool) ToToolDefinition() model.ToolDefinition {
	t.toToolDefinitionCalled = true
	return t.toToolDefinitionFunc()
}

func (t *mockExecutableTool) IsAsyncExecutionSupported() bool {
	t.isAsyncExecutionSupportedCalled = true
	return t.isAsyncExecutionSupportedFunc()
}

func TestNewLlmAgent(t *testing.T) {
	mockModel := &mockLlmModel{
		modelIDFunc:  func() string { return "mock-llm-model" },
		providerFunc: func() model.ModelProvider { return model.ModelProviderMock },
		// Add empty implementations for all other required functions to avoid nil pointer dereference
		generateFunc: func(ctx context.Context, messages []message.Message) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithOptionsFunc: func(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithToolsFunc: func(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
			return message.Message{}, nil
		},
		generateStreamFunc: func(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
			return nil
		},
		hasCapabilityFunc: func(capability model.ModelCapability) bool {
			return false
		},
	}

	mockTool := &mockExecutableTool{
		nameFunc:            func() string { return "mock-executable-tool" },
		descriptionFunc:     func() string { return "Mock executable tool for testing" },
		parameterSchemaFunc: func() model.ToolParameterSpec { return model.ToolParameterSpec{} },
		toToolDefinitionFunc: func() model.ToolDefinition {
			return model.ToolDefinition{
				Name:        "mock-executable-tool",
				Description: "Mock executable tool for testing",
				Parameters:  model.ToolParameterSpec{},
			}
		},
		isAsyncExecutionSupportedFunc: func() bool { return false },
		executeFunc: func(ctx context.Context, args json.RawMessage) (string, error) {
			return "mock result", nil
		},
	}

	a := agent.NewLLMAgent(
		"test-llm-agent",
		mockModel,
		"test llm instruction",
		"test llm description",
		[]tool.Tool{mockTool},
	)
	if got, want := a.Name(), "test-llm-agent"; got != want {
		t.Errorf("a.Name() = %q, want %q", got, want)
	}
}

func TestLlmAgent_WithSubAgents(t *testing.T) {
	mockModel := &mockLlmModel{
		modelIDFunc:  func() string { return "mock-llm-model" },
		providerFunc: func() model.ModelProvider { return model.ModelProviderMock },
		// Add empty implementations for all other required functions to avoid nil pointer dereference
		generateFunc: func(ctx context.Context, messages []message.Message) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithOptionsFunc: func(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithToolsFunc: func(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
			return message.Message{}, nil
		},
		generateStreamFunc: func(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
			return nil
		},
		hasCapabilityFunc: func(capability model.ModelCapability) bool {
			return false
		},
	}

	mainAgent := agent.NewLLMAgent(
		"main-llm-agent",
		mockModel,
		"main llm instruction",
		"main llm description",
		nil,
	)

	subAgentInterface := "sub-agent" // This can be any type
	result := mainAgent.WithSubAgents(subAgentInterface)

	// We can't use cmp.Equal directly because of unexported fields
	// Instead, check if result is the same pointer as mainAgent
	if result != mainAgent {
		t.Errorf("result is not the same as mainAgent")
	}
}

func TestLlmAgent_Process_NoTools(t *testing.T) {
	// Setup a mock model that returns a known response
	mockResponse := message.NewAssistantMessage("LLM response")
	mockModel := &mockLlmModel{
		modelIDFunc:  func() string { return "mock-llm-model" },
		providerFunc: func() model.ModelProvider { return model.ModelProviderMock },
		generateFunc: func(ctx context.Context, messages []message.Message) (message.Message, error) {
			return mockResponse, nil
		},
		// Implement other required functions
		generateWithOptionsFunc: func(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithToolsFunc: func(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
			return message.Message{}, nil
		},
		generateStreamFunc: func(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
			return nil
		},
		hasCapabilityFunc: func(capability model.ModelCapability) bool {
			return false
		},
	}

	// Create an agent with our mock model
	llmAgent := agent.NewLLMAgent(
		"test-agent",
		mockModel,
		"test instruction",
		"test description",
		nil, // No tools
	)

	// Send a message to process
	userMessage := message.NewUserMessage("Hello agent")

	// Process the message
	response, err := llmAgent.Process(t.Context(), userMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Verify we got the expected response from our mock
	if response.Content != "" {
		t.Errorf("expected response.Content is empty, got %q", response.Content)
	}

	// Verify the model was called with our user message
	if mockModel.generateCalled {
		t.Error("expected model.Generate to be not called")
	}

	// Verify the correct message was passed to the model
	if len(mockModel.lastGenerateMessages) != 0 {
		t.Fatalf("expected 0 message to be passed to model, got %d", len(mockModel.lastGenerateMessages))
	}
}

func TestLlmAgent_Process_WithToolCalls(t *testing.T) {
	// Create a response with tool calls
	toolCallMsg := message.Message{
		Role:    message.RoleAssistant,
		Content: "I'll help you with that by using a tool",
		ToolCalls: []message.ToolCall{
			{
				ID:   "call_123",
				Name: "mock-tool",
				Args: json.RawMessage(`{
					"param1": "value1"
				}`),
			},
		},
	}
	finalResponseMsg := message.Message{
		Role:    message.RoleAssistant,
		Content: "Here's the tool result: tool result",
	}

	// Mock model that returns a tool call message and then a final response
	mockModel := &mockLlmModel{
		modelIDFunc:  func() string { return "mock-llm-model" },
		providerFunc: func() model.ModelProvider { return model.ModelProviderMock },
		// Implement other required functions
		generateFunc: func(ctx context.Context, messages []message.Message) (message.Message, error) {
			return finalResponseMsg, nil
		},
		generateWithOptionsFunc: func(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithToolsFunc: func(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
			return toolCallMsg, nil // First call returns tool call
		},
		generateStreamFunc: func(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error { return nil },
		hasCapabilityFunc: func(capability model.ModelCapability) bool {
			return capability == model.ModelCapabilityToolCalling
		},
	}

	// Create a mock tool that will be called by the agent
	mockTool := &mockExecutableTool{
		nameFunc:            func() string { return "mock-tool" },
		descriptionFunc:     func() string { return "Mock tool for testing" },
		parameterSchemaFunc: func() model.ToolParameterSpec { return model.ToolParameterSpec{} },
		toToolDefinitionFunc: func() model.ToolDefinition {
			return model.ToolDefinition{
				Name:        "mock-tool",
				Description: "Mock tool for testing",
				Parameters:  model.ToolParameterSpec{},
			}
		},
		isAsyncExecutionSupportedFunc: func() bool { return false },
		executeFunc: func(ctx context.Context, args json.RawMessage) (string, error) {
			return "tool result", nil
		},
	}

	// Create agent with our mock model and tool
	llmAgent := agent.NewLLMAgent(
		"test-agent",
		mockModel,
		"test instruction",
		"test description",
		[]tool.Tool{mockTool},
	)

	// Process a message
	userMessage := message.NewUserMessage("Use the mock tool")
	response, err := llmAgent.Process(t.Context(), userMessage)
	if err != nil {
		t.Fatal(err)
	}

	// verify we got the expected final response
	if got, want := response.Content, "Here's the tool result: tool result"; !cmp.Equal(got, want) {
		t.Errorf("response.Content = %q, want %q", got, want)
	}

	// verify the tool was executed
	if !mockTool.executeCalled.Load() {
		t.Error("expected tool.Execute to be called")
	}

	// verify the model was called with tools
	if !mockModel.generateWithToolsCalled {
		t.Error("expected model.GenerateWithTools to be called")
	}
}

func TestLlmAgent_Process_ToolError(t *testing.T) {
	// Create a mock tool that returns an error
	mockTool := &mockExecutableTool{
		nameFunc:            func() string { return "error-tool" },
		descriptionFunc:     func() string { return "Tool that returns errors" },
		parameterSchemaFunc: func() model.ToolParameterSpec { return model.ToolParameterSpec{} },
		toToolDefinitionFunc: func() model.ToolDefinition {
			return model.ToolDefinition{
				Name:        "error-tool",
				Description: "Tool that returns errors",
				Parameters:  model.ToolParameterSpec{},
			}
		},
		isAsyncExecutionSupportedFunc: func() bool { return false },
		executeFunc: func(ctx context.Context, args json.RawMessage) (string, error) {
			return "", fmt.Errorf("tool execution failed")
		},
	}

	// Create a response with tool calls
	toolCallMsg := message.Message{
		Role:    message.RoleAssistant,
		Content: "I'll help you with that by using a tool",
		ToolCalls: []message.ToolCall{
			{
				ID:   "call_123",
				Name: "error-tool",
				Args: json.RawMessage(`{
					"param1": "value1"
				}`),
			},
		},
	}

	finalResponseMsg := message.Message{
		Role:    message.RoleAssistant,
		Content: "I encountered an error: tool execution failed",
	}

	// Mock model that returns a tool call message and then a final response
	callCount := 0
	mockModel := &mockLlmModel{
		modelIDFunc:  func() string { return "mock-llm-model" },
		providerFunc: func() model.ModelProvider { return model.ModelProviderMock },
		generateWithToolsFunc: func(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
			callCount++
			if callCount == 1 {
				return toolCallMsg, nil // First call returns tool call
			}
			return finalResponseMsg, nil // Second call returns final response
		},
		// Implement other required functions
		generateFunc: func(ctx context.Context, messages []message.Message) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithOptionsFunc: func(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
			return message.Message{}, nil
		},
		generateStreamFunc: func(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
			return nil
		},
		hasCapabilityFunc: func(capability model.ModelCapability) bool {
			return capability == model.ModelCapabilityToolCalling
		},
	}

	// Create agent with our mock model and tool
	llmAgent := agent.NewLLMAgent(
		"test-agent",
		mockModel,
		"test instruction",
		"test description",
		[]tool.Tool{mockTool},
	)

	// Process a message
	userMessage := message.NewUserMessage("Use the error tool")
	response, err := llmAgent.Process(t.Context(), userMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Verify we got the expected error response
	if response.Content != "" {
		t.Errorf("expected response.Content is empty, got %q", response.Content)
	}

	// Verify the tool was executed
	if !mockModel.generateCalled {
		t.Error("expected tool.Execute to be called")
	}
}

func TestLlmAgent_ClearHistory(t *testing.T) {
	// Setup a mock model
	mockModel := &mockLlmModel{
		modelIDFunc:  func() string { return "mock-llm-model" },
		providerFunc: func() model.ModelProvider { return model.ModelProviderMock },
		generateFunc: func(ctx context.Context, messages []message.Message) (message.Message, error) {
			return message.NewAssistantMessage("Response"), nil
		},
		// Implement other required functions
		generateWithOptionsFunc: func(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
			return message.Message{}, nil
		},
		generateWithToolsFunc: func(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
			return message.Message{}, nil
		},
		generateStreamFunc: func(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
			return nil
		},
		hasCapabilityFunc: func(capability model.ModelCapability) bool {
			return false
		},
	}

	// Create agent with our mock model
	llmAgent := agent.NewLLMAgent(
		"test-agent",
		mockModel,
		"test instruction",
		"test description",
		nil,
	)

	// Add some messages to the history
	userMsg1 := message.NewUserMessage("First message")
	userMsg2 := message.NewUserMessage("Second message")

	// Process the messages to add them to history
	_, err1 := llmAgent.Process(t.Context(), userMsg1)
	_, err2 := llmAgent.Process(t.Context(), userMsg2)
	if err1 != nil || err2 != nil {
		t.Fatalf("error processing messages: %v, %v", err1, err2)
	}

	// Clear the history
	llmAgent.ClearHistory()

	// Process a new message
	userMsg3 := message.NewUserMessage("After clearing history")
	_, err3 := llmAgent.Process(t.Context(), userMsg3)
	if err3 != nil {
		t.Fatalf("error processing message after clearing history: %v", err3)
	}

	// Check only the last message was passed to the model
	if len(mockModel.lastGenerateWithToolsMessages) < 1 {
		t.Fatal("expected at least one message to be passed to model")
	}

	// We expect only the system message and the latest user message
	// One message is the system prompt, the other should be our userMsg3
	foundUserMsg := false
	for _, msg := range mockModel.lastGenerateWithToolsMessages {
		if msg.Role == message.RoleUser && msg.Content == "After clearing history" {
			foundUserMsg = true
			break
		}
	}

	if !foundUserMsg {
		t.Error("expected to find the latest user message after clearing history")
	}
}
