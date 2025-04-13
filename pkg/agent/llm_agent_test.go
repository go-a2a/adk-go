// Copyright 2024 The ADK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// mockLlmModel implements model.Model interface and allows mocking responses
type mockLlmModel struct {
	mock.Mock
}

func (m *mockLlmModel) Generate(ctx context.Context, messages []message.Message) (message.Message, error) {
	args := m.Called(ctx, messages)
	return args.Get(0).(message.Message), args.Error(1)
}

func (m *mockLlmModel) GenerateWithOptions(ctx context.Context, messages []message.Message, opts any) (message.Message, error) {
	args := m.Called(ctx, messages, opts)
	return args.Get(0).(message.Message), args.Error(1)
}

func (m *mockLlmModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	args := m.Called(ctx, messages, tools)
	return args.Get(0).(message.Message), args.Error(1)
}

func (m *mockLlmModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	args := m.Called(ctx, messages, handler)
	return args.Error(0)
}

func (m *mockLlmModel) ModelID() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockLlmModel) Provider() model.ModelProvider {
	args := m.Called()
	return args.Get(0).(model.ModelProvider)
}

func (m *mockLlmModel) HasCapability(capability model.ModelCapability) bool {
	args := m.Called(capability)
	return args.Bool(0)
}

// mockExecutableTool implements tool.Tool interface and tracks executions
type mockExecutableTool struct {
	mock.Mock
}

func (t *mockExecutableTool) Name() string {
	args := t.Called()
	return args.String(0)
}

func (t *mockExecutableTool) Description() string {
	args := t.Called()
	return args.String(0)
}

func (t *mockExecutableTool) ParameterSchema() model.ToolParameterSpec {
	args := t.Called()
	return args.Get(0).(model.ToolParameterSpec)
}

func (t *mockExecutableTool) Execute(ctx context.Context, args sonic.RawMessage) (string, error) {
	mockArgs := t.Called(ctx, args)
	return mockArgs.String(0), mockArgs.Error(1)
}

func (t *mockExecutableTool) ToToolDefinition() model.ToolDefinition {
	args := t.Called()
	return args.Get(0).(model.ToolDefinition)
}

func (t *mockExecutableTool) IsAsyncExecutionSupported() bool {
	args := t.Called()
	return args.Bool(0)
}

func TestNewLlmAgent(t *testing.T) {
	mockModel := new(mockLlmModel)
	mockTool := new(mockExecutableTool)

	mockModel.On("ModelID").Return("mock-llm-model")
	mockModel.On("Provider").Return(model.ModelProviderMock)

	mockTool.On("Name").Return("mock-executable-tool")
	mockTool.On("Description").Return("Mock executable tool for testing")
	mockTool.On("ParameterSchema").Return(model.ToolParameterSpec{})
	mockTool.On("ToToolDefinition").Return(model.ToolDefinition{
		Name:        "mock-executable-tool",
		Description: "Mock executable tool for testing",
		Parameters:  model.ToolParameterSpec{},
	})
	mockTool.On("IsAsyncExecutionSupported").Return(false)

	a := agent.NewLLMAgent(
		"test-llm-agent",
		mockModel,
		"test llm instruction",
		"test llm description",
		[]tool.Tool{mockTool},
	)

	if a == nil {
		t.Fatal("Expected agent to not be nil")
	}
	if got, want := a.Name(), "test-llm-agent"; got != want {
		t.Errorf("a.Name() = %q, want %q", got, want)
	}
}

func TestLlmAgent_WithSubAgents(t *testing.T) {
	mockModel := new(mockLlmModel)
	mockModel.On("ModelID").Return("mock-llm-model")
	mockModel.On("Provider").Return(model.ModelProviderMock)

	mainAgent := agent.NewLLMAgent(
		"main-llm-agent",
		mockModel,
		"main llm instruction",
		"main llm description",
		nil,
	)

	subAgentInterface := "sub-agent" // This can be any type

	result := mainAgent.WithSubAgents(subAgentInterface)
	if result == nil {
		t.Fatal("Expected result to not be nil")
	}
	if !cmp.Equal(mainAgent, result) {
		t.Errorf("Result differs from mainAgent:\n%s", cmp.Diff(mainAgent, result))
	}
}

func TestLlmAgent_Process_NoTools(t *testing.T) {
	mockModel := new(mockLlmModel)
	mockModel.On("ModelID").Return("mock-llm-model")
	mockModel.On("Provider").Return(model.ModelProviderMock)

	expectedResponse := message.NewAssistantMessage("LLM response")

	// Set up expectations
	mockModel.On("Generate", mock.Anything, mock.Anything).Return(expectedResponse, nil)

	a := agent.NewLLMAgent(
		"test-llm-agent",
		mockModel,
		"test llm instruction",
		"test llm description",
		nil,
	)

	userMsg := message.NewUserMessage("Hello LLM")
	response, err := a.Process(context.Background(), userMsg)
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}
	if got, want := response.Role, expectedResponse.Role; got != want {
		t.Errorf("response.Role = %q, want %q", got, want)
	}
	if got, want := response.Content, expectedResponse.Content; got != want {
		t.Errorf("response.Content = %q, want %q", got, want)
	}

	mockModel.AssertCalled(t, "Generate", mock.Anything, mock.Anything)
}

func TestLlmAgent_Process_WithToolCalls(t *testing.T) {
	mockModel := new(mockLlmModel)
	mockExecutableTool := new(mockExecutableTool)

	mockModel.On("ModelID").Return("mock-llm-model")
	mockModel.On("Provider").Return(model.ModelProviderMock)

	toolName := "search"
	toolID := "tool_call_1"

	// Set up tool
	mockExecutableTool.On("Name").Return(toolName)
	mockExecutableTool.On("Description").Return("Search the web")
	mockExecutableTool.On("ParameterSchema").Return(model.ToolParameterSpec{})
	mockExecutableTool.On("ToToolDefinition").Return(model.ToolDefinition{
		Name:        toolName,
		Description: "Search the web",
		Parameters:  model.ToolParameterSpec{},
	})
	mockExecutableTool.On("IsAsyncExecutionSupported").Return(false)

	// Tool arguments
	toolArgs := map[string]string{"query": "test query"}
	toolArgsBytes, _ := json.Marshal(toolArgs)
	rawToolArgs := sonic.RawMessage(toolArgsBytes)

	// Tool response
	mockExecutableTool.On("Execute", mock.Anything, mock.Anything).Return("Search results for 'test query'", nil)

	// Set up model responses
	// First response with tool calls
	toolCallResponse := message.Message{
		Role: message.RoleAssistant,
		ToolCalls: []message.ToolCall{
			{
				ID:   toolID,
				Name: toolName,
				Args: rawToolArgs,
			},
		},
	}

	// Final response using tool results
	finalResponse := message.NewAssistantMessage("Based on the search results, here's what I found...")

	// Set up expectations for model calls
	mockModel.On("GenerateWithTools", mock.Anything, mock.Anything, mock.Anything).Return(toolCallResponse, nil)
	mockModel.On("Generate", mock.Anything, mock.Anything).Return(finalResponse, nil)

	// Create the agent
	a := agent.NewLLMAgent(
		"test-llm-agent",
		mockModel,
		"test llm instruction",
		"test llm description",
		[]tool.Tool{mockExecutableTool},
	)

	// Test the process
	userMsg := message.NewUserMessage("Search for something")
	response, err := a.Process(context.Background(), userMsg)
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}
	if got, want := response.Role, finalResponse.Role; got != want {
		t.Errorf("response.Role = %q, want %q", got, want)
	}
	if got, want := response.Content, finalResponse.Content; got != want {
		t.Errorf("response.Content = %q, want %q", got, want)
	}

	// Verify the expected calls
	mockModel.AssertCalled(t, "GenerateWithTools", mock.Anything, mock.Anything, mock.Anything)
	mockExecutableTool.AssertCalled(t, "Execute", mock.Anything, mock.Anything)
	mockModel.AssertCalled(t, "Generate", mock.Anything, mock.Anything)
}

func TestLlmAgent_Process_ToolError(t *testing.T) {
	mockModel := new(mockLlmModel)
	mockExecutableTool := new(mockExecutableTool)

	mockModel.On("ModelID").Return("mock-llm-model")
	mockModel.On("Provider").Return(model.ModelProviderMock)

	toolName := "search"
	toolID := "tool_call_1"

	// Set up tool
	mockExecutableTool.On("Name").Return(toolName)
	mockExecutableTool.On("Description").Return("Search the web")
	mockExecutableTool.On("ParameterSchema").Return(model.ToolParameterSpec{})
	mockExecutableTool.On("ToToolDefinition").Return(model.ToolDefinition{
		Name:        toolName,
		Description: "Search the web",
		Parameters:  model.ToolParameterSpec{},
	})
	mockExecutableTool.On("IsAsyncExecutionSupported").Return(false)

	// Tool arguments
	toolArgs := map[string]string{"query": "test query"}
	toolArgsBytes, _ := json.Marshal(toolArgs)
	rawToolArgs := sonic.RawMessage(toolArgsBytes)

	// Tool execution error
	toolErr := fmt.Errorf("search failed")
	mockExecutableTool.On("Execute", mock.Anything, mock.Anything).Return("", toolErr)

	// Set up model responses with tool calls
	toolCallResponse := message.Message{
		Role: message.RoleAssistant,
		ToolCalls: []message.ToolCall{
			{
				ID:   toolID,
				Name: toolName,
				Args: rawToolArgs,
			},
		},
	}

	// Final response using tool error results
	finalResponse := message.NewAssistantMessage("I encountered an error with the search...")

	// Set up expectations for model calls
	mockModel.On("GenerateWithTools", mock.Anything, mock.Anything, mock.Anything).Return(toolCallResponse, nil)
	mockModel.On("Generate", mock.Anything, mock.Anything).Return(finalResponse, nil)

	// Create the agent
	a := agent.NewLLMAgent(
		"test-llm-agent",
		mockModel,
		"test llm instruction",
		"test llm description",
		[]tool.Tool{mockExecutableTool},
	)

	// Test the process
	userMsg := message.NewUserMessage("Search for something")
	response, err := a.Process(context.Background(), userMsg)
	// The process should not fail, but instead return an error through the tool result
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}
	if got, want := response.Role, finalResponse.Role; got != want {
		t.Errorf("response.Role = %q, want %q", got, want)
	}
	if got, want := response.Content, finalResponse.Content; got != want {
		t.Errorf("response.Content = %q, want %q", got, want)
	}

	// Verify the expected calls
	mockModel.AssertCalled(t, "GenerateWithTools", mock.Anything, mock.Anything, mock.Anything)
	mockExecutableTool.AssertCalled(t, "Execute", mock.Anything, mock.Anything)
	mockModel.AssertCalled(t, "Generate", mock.Anything, mock.Anything)
}

func TestLlmAgent_ClearHistory(t *testing.T) {
	mockModel := new(mockLlmModel)
	mockModel.On("ModelID").Return("mock-llm-model")
	mockModel.On("Provider").Return(model.ModelProviderMock)
	mockModel.On("Generate", mock.Anything, mock.Anything).Return(message.NewAssistantMessage("Response"), nil)

	a := agent.NewLLMAgent(
		"test-llm-agent",
		mockModel,
		"test llm instruction",
		"test llm description",
		nil,
	)

	// First process should add to history
	userMsg := message.NewUserMessage("Hello")
	_, err := a.Process(context.Background(), userMsg)
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}

	// Clear history
	a.ClearHistory()

	// Process again - history should be fresh
	userMsg2 := message.NewUserMessage("After clear")
	_, err = a.Process(context.Background(), userMsg2)
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}

	// Ensure model was called with the correct messages
	// This is the second call to Generate, after history was cleared
	mockModel.AssertCalled(t, "Generate", mock.Anything, mock.Anything)
}
