// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"encoding/json"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// mockModel implements model.Model interface for testing
type mockModel struct{}

var _ model.Model = (*mockModel)(nil)

// Generate generates a completion based on the provided messages.
func (m *mockModel) Generate(ctx context.Context, messages []message.Message) (message.Message, error) {
	return message.NewAssistantMessage("Mock response"), nil
}

// GenerateWithOptions generates a completion with the specified options.
func (m *mockModel) GenerateWithOptions(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	return message.NewAssistantMessage("Mock response with options"), nil
}

// GenerateWithTools generates a response that can include tool calls.
func (m *mockModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	return message.NewAssistantMessage("Mock response with tools"), nil
}

// GenerateStream generates a streaming response and invokes the handler for each chunk.
func (m *mockModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	return nil
}

// ModelID returns the identifier for this model.
func (m *mockModel) ModelID() string {
	return "mock-model"
}

// Provider returns the provider of this model.
func (m *mockModel) Provider() model.ModelProvider {
	return "mock"
}

// HasCapability returns whether the model has the specified capability.
func (m *mockModel) HasCapability(capability model.ModelCapability) bool {
	return true
}

// mockTool implements tool.Tool interface for testing
type mockTool struct{}

var _ tool.Tool = (*mockTool)(nil)

// Name returns the name of the tool.
func (t *mockTool) Name() string {
	return "mock-tool"
}

// Description returns a description of what the tool does.
func (t *mockTool) Description() string {
	return "Mock tool for testing"
}

// ParameterSchema returns the JSON schema for the tool's parameters.
func (t *mockTool) ParameterSchema() model.ToolParameterSpec {
	return make(model.ToolParameterSpec)
}

// Execute runs the tool with the given arguments.
func (t *mockTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	return "Mock tool result", nil
}

// ToToolDefinition converts the tool to a ToolDefinition that can be passed to a model.
func (t *mockTool) ToToolDefinition() model.ToolDefinition {
	return model.ToolDefinition{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters:  t.ParameterSchema(),
	}
}

// IsAsyncExecutionSupported returns true if the tool supports asynchronous execution.
func (t *mockTool) IsAsyncExecutionSupported() bool {
	return false
}

func TestNewAgent(t *testing.T) {
	model := &mockModel{}
	mocktool := &mockTool{}
	a := agent.NewAgent(
		"test-agent",
		model,
		"test instruction",
		"test description",
		[]tool.Tool{mocktool},
	)

	if a == nil {
		t.Fatal("Expected agent to not be nil")
	}
	if got, want := a.Name(), "test-agent"; got != want {
		t.Errorf("a.Name() = %q, want %q", got, want)
	}
}

func TestWithSubAgents(t *testing.T) {
	model := &mockModel{}
	mocktool := &mockTool{}
	mainAgent := agent.NewAgent(
		"main-agent",
		model,
		"main instruction",
		"main description",
		[]tool.Tool{mocktool},
	)

	subAgent := agent.NewAgent(
		"sub-agent",
		model,
		"sub instruction",
		"sub description",
		[]tool.Tool{mocktool},
	)

	result := mainAgent.WithSubAgents(*subAgent)
	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// We can't use gocmp.Diff directly because of unexported fields
	// Instead, verify the result is the same pointer as mainAgent
	if result != mainAgent {
		t.Errorf("result is not the same as mainAgent")
	}
}

func TestAgent_Process(t *testing.T) {
	model := &mockModel{}
	mocktool := &mockTool{}
	a := agent.NewAgent(
		"test-agent",
		model,
		"test instruction",
		"test description",
		[]tool.Tool{mocktool},
	)

	msg := message.NewUserMessage("Hello")
	response, err := a.Process(context.Background(), msg)
	// Process is currently a placeholder in the implementation
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}
	if diff := gocmp.Diff(message.Message{}, response); diff != "" {
		t.Errorf("Process() response differs from expected: (-want +got):\n%s", diff)
	}
}

func TestAgent_RunWithTools(t *testing.T) {
	model := &mockModel{}
	mocktool := &mockTool{}
	a := agent.NewAgent(
		"test-agent",
		model,
		"test instruction",
		"test description",
		[]tool.Tool{mocktool},
	)

	msg := message.NewUserMessage("Use a tool")
	response, err := a.RunWithTools(context.Background(), msg)
	// RunWithTools is currently a placeholder in the implementation
	if err != nil {
		t.Errorf("RunWithTools() error = %v, want nil", err)
	}
	if diff := gocmp.Diff(message.Message{}, response); diff != "" {
		t.Errorf("RunWithTools() response differs from expected: (-want +got):\n%s", diff)
	}
}
