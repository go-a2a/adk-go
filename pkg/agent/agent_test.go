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
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
)

// mockModel implements model.Model interface for testing
type mockModel struct{}

func (m *mockModel) Generate(ctx context.Context, messages []message.Message) (message.Message, error) {
	return message.NewAssistantMessage("Mock response"), nil
}

func (m *mockModel) GenerateWithOptions(ctx context.Context, messages []message.Message, opts any) (message.Message, error) {
	return message.NewAssistantMessage("Mock response with options"), nil
}

func (m *mockModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools any) (message.Message, error) {
	return message.NewAssistantMessage("Mock response with tools"), nil
}

func (m *mockModel) GenerateStream(ctx context.Context, messages []message.Message, handler any) error {
	return nil
}

func (m *mockModel) ModelID() string {
	return "mock-model"
}

func (m *mockModel) Provider() any {
	return "mock"
}

func (m *mockModel) HasCapability(capability any) bool {
	return true
}

// mockTool implements tool.Tool interface for testing
type mockTool struct{}

func (t *mockTool) Name() string {
	return "mock-tool"
}

func (t *mockTool) Description() string {
	return "Mock tool for testing"
}

func (t *mockTool) ParameterSchema() any {
	return map[string]any{}
}

func (t *mockTool) Execute(ctx context.Context, args any) (string, error) {
	return "Mock tool result", nil
}

func (t *mockTool) ToToolDefinition() any {
	return map[string]any{
		"name":        t.Name(),
		"description": t.Description(),
		"parameters":  t.ParameterSchema(),
	}
}

func (t *mockTool) IsAsyncExecutionSupported() bool {
	return false
}

func TestNewAgent(t *testing.T) {
	model := &mockModel{}
	tool := &mockTool{}
	a := agent.NewAgent(
		"test-agent",
		model,
		"test instruction",
		"test description",
		[]tool.Tool{tool},
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
	tool := &mockTool{}
	mainAgent := agent.NewAgent(
		"main-agent",
		model,
		"main instruction",
		"main description",
		[]tool.Tool{tool},
	)

	subAgent := agent.NewAgent(
		"sub-agent",
		model,
		"sub instruction",
		"sub description",
		[]tool.Tool{tool},
	)

	result := mainAgent.WithSubAgents(*subAgent)
	if result == nil {
		t.Fatal("Expected result to not be nil")
	}
	if !cmp.Equal(mainAgent, result) {
		t.Errorf("Result differs from mainAgent:\n%s", cmp.Diff(mainAgent, result))
	}
}

func TestAgent_Process(t *testing.T) {
	model := &mockModel{}
	tool := &mockTool{}
	a := agent.NewAgent(
		"test-agent",
		model,
		"test instruction",
		"test description",
		[]tool.Tool{tool},
	)

	msg := message.NewUserMessage("Hello")
	response, err := a.Process(context.Background(), msg)
	// Process is currently a placeholder in the implementation
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}
	if !cmp.Equal(message.Message{}, response) {
		t.Errorf("Process() response differs from expected:\n%s", cmp.Diff(message.Message{}, response))
	}
}

func TestAgent_RunWithTools(t *testing.T) {
	model := &mockModel{}
	tool := &mockTool{}
	a := agent.NewAgent(
		"test-agent",
		model,
		"test instruction",
		"test description",
		[]tool.Tool{tool},
	)

	msg := message.NewUserMessage("Use a tool")
	response, err := a.RunWithTools(context.Background(), msg)
	// RunWithTools is currently a placeholder in the implementation
	if err != nil {
		t.Errorf("RunWithTools() error = %v, want nil", err)
	}
	if !cmp.Equal(message.Message{}, response) {
		t.Errorf("RunWithTools() response differs from expected:\n%s", cmp.Diff(message.Message{}, response))
	}
}
