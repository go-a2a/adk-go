// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"iter"
	"testing"

	"github.com/go-a2a/adk-go/agent/events"
	"github.com/go-a2a/adk-go/agent/tools"
	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

// MockModel is a mock implementation of the Model interface for testing.
type MockModel struct {
	GenerateContentFunc func(ctx context.Context, request *model.LLMRequest) (*model.LLMResponse, error)
}

func (m *MockModel) Name() string {
	return "mock-model"
}

func (m *MockModel) Connect() (model.BaseConnection, error) {
	return nil, nil
}

func (m *MockModel) GenerateContent(ctx context.Context, request *model.LLMRequest) (*model.LLMResponse, error) {
	return m.GenerateContentFunc(ctx, request)
}

func (m *MockModel) StreamGenerateContent(ctx context.Context, request *model.LLMRequest) iter.Seq2[*model.LLMResponse, error] {
	return nil
}

// TestAgentCreation tests the creation of an agent with various options.
func TestAgentCreation(t *testing.T) {
	agent := NewAgent(
		WithID("test-agent"),
		WithName("Test Agent"),
		WithDescription("A test agent"),
		WithSessionID("test-session"),
	)

	if agent.ID() != "test-agent" {
		t.Errorf("Expected agent ID to be 'test-agent', got %s", agent.ID())
	}

	if agent.Name() != "Test Agent" {
		t.Errorf("Expected agent name to be 'Test Agent', got %s", agent.Name())
	}

	if agent.Description() != "A test agent" {
		t.Errorf("Expected agent description to be 'A test agent', got %s", agent.Description())
	}
}

// TestAgentToolRegistration tests the registration of tools with an agent.
func TestAgentToolRegistration(t *testing.T) {
	agent := NewAgent(
		WithID("test-agent"),
		WithSessionID("test-session"),
	)

	// Create a simple tool
	tool := tools.NewBaseTool(
		tools.WithName("test-tool"),
		tools.WithDescription("A test tool"),
		tools.WithExecuteFunc(func(ctx context.Context, params map[string]any) (any, error) {
			return "tool-result", nil
		}),
	)

	// Register the tool
	err := agent.AddTool(tool)
	if err != nil {
		t.Fatalf("Failed to add tool: %v", err)
	}

	// Verify the tool was registered by checking if the agent has tool handling capability
	if len(agent.toolRegistry.ListTools()) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(agent.toolRegistry.ListTools()))
	}

	// Verify the registered tool is the one we added
	registeredTool, exists := agent.toolRegistry.GetTool("test-tool")
	if !exists {
		t.Fatalf("Tool 'test-tool' not found in registry")
	}

	if registeredTool.Name() != "test-tool" {
		t.Errorf("Expected tool name to be 'test-tool', got %s", registeredTool.Name())
	}

	if registeredTool.Description() != "A test tool" {
		t.Errorf("Expected tool description to be 'A test tool', got %s", registeredTool.Description())
	}
}

// TestAgentProcessEvent tests the processing of events by an agent.
func TestAgentProcessEvent(t *testing.T) {
	// Track emitted events
	var emittedEvents []*events.Event

	// Create an agent with a custom event emitter
	agent := NewAgent(
		WithID("test-agent"),
		WithSessionID("test-session"),
		WithEventEmitter(func(event *events.Event) error {
			emittedEvents = append(emittedEvents, event)
			return nil
		}),
	)

	// Create a mock model that returns a predefined response
	mockModel := &MockModel{
		GenerateContentFunc: func(ctx context.Context, request *model.LLMRequest) (*model.LLMResponse, error) {
			return &model.LLMResponse{
				Candidates: []*model.Candidate{
					{
						Content: &genai.Content{
							Role: model.RoleAssistant,
							Parts: []*genai.Part{
								{Text: "This is a test response"},
							},
						},
					},
				},
			}, nil
		},
	}

	// Set the mock model
	agent.model = mockModel

	// Create a user message event
	content := &genai.Content{
		Role: model.RoleUser,
		Parts: []*genai.Part{
			{Text: "Hello, agent!"},
		},
	}

	event, err := events.NewUserMessageEvent("test-session", content)
	if err != nil {
		t.Fatalf("Failed to create user message event: %v", err)
	}

	// Process the event
	response, err := agent.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("Failed to process event: %v", err)
	}

	// Verify the response
	if response == nil {
		t.Fatal("Expected a response, got nil")
	}

	// Extract the response content
	responseContent, err := response.GetAgentResponseContent()
	if err != nil {
		t.Fatalf("Failed to get agent response content: %v", err)
	}

	expectedText := "This is a test response"
	actualText := ""
	if len(responseContent.Response.Parts) > 0 {
		actualText = responseContent.Response.Parts[0].Text
	}

	if actualText != expectedText {
		t.Errorf("Expected response text to be '%s', got '%s'", expectedText, actualText)
	}
}

// TestAgentToolExecution tests the execution of tools by an agent.
func TestAgentToolExecution(t *testing.T) {
	// Track events for verification
	var emittedEvents []*events.Event

	// Create an agent with custom event emitter
	agent := NewAgent(
		WithID("test-agent"),
		WithSessionID("test-session"),
		WithEventEmitter(func(event *events.Event) error {
			emittedEvents = append(emittedEvents, event)
			return nil
		}),
	)

	// Create a simple tool
	tool := tools.NewBaseTool(
		tools.WithName("echo"),
		tools.WithDescription("Echoes back the input"),
		tools.WithExecuteFunc(func(ctx context.Context, params map[string]any) (any, error) {
			message, _ := params["message"].(string)
			return map[string]any{"result": "Echo: " + message}, nil
		}),
	)

	// Register the tool
	err := agent.AddTool(tool)
	if err != nil {
		t.Fatalf("Failed to add tool: %v", err)
	}

	// Create a function call
	functionCall := &genai.FunctionCall{
		Name: "echo",
		Args: map[string]any{
			"message": "Hello, tool!",
		},
	}

	// Simulate a function call from the LLM
	err = agent.handleFunctionCall(context.Background(), functionCall)
	if err != nil {
		t.Fatalf("Failed to handle function call: %v", err)
	}

	// Verify a tool call event was emitted
	found := false
	for _, event := range emittedEvents {
		if event.Type == events.EventTypeToolCall {
			toolCall, err := event.GetToolCallContent()
			if err != nil {
				t.Fatalf("Failed to get tool call content: %v", err)
			}

			if toolCall.Name == "echo" &&
				toolCall.Parameters["message"] == "Hello, tool!" {
				found = true
				break
			}
		}
	}

	if !found {
		t.Error("Expected to find a tool call event for 'echo', but none was found")
	}
}

// TestChildAgentInteraction tests the interaction between a parent and child agent.
func TestChildAgentInteraction(t *testing.T) {
	// Create parent agent
	parentAgent := NewAgent(
		WithID("parent-agent"),
		WithName("Parent Agent"),
		WithSessionID("test-session"),
	)

	// Create child agent
	childAgent := NewAgent(
		WithID("child-agent"),
		WithName("Child Agent"),
		WithDescription("A child agent that helps the parent"),
		WithSessionID("test-session"),
	)

	// Create a mock model for the child agent that returns a predefined response
	mockChildModel := &MockModel{
		GenerateContentFunc: func(ctx context.Context, request *model.LLMRequest) (*model.LLMResponse, error) {
			return &model.LLMResponse{
				Candidates: []*model.Candidate{
					{
						Content: &genai.Content{
							Role: model.RoleAssistant,
							Parts: []*genai.Part{
								{Text: "Child agent response"},
							},
						},
					},
				},
			}, nil
		},
	}
	childAgent.model = mockChildModel

	// Add the child agent to the parent
	parentAgent.AddChildAgent(childAgent)

	// Verify the parent has a tool for the child agent
	tool, exists := parentAgent.toolRegistry.GetTool("agent:" + childAgent.ID())
	if !exists {
		t.Fatal("Expected parent to have a tool for the child agent, but none was found")
	}

	// Simulate a call to the child agent tool
	result, err := tool.Execute(context.Background(), map[string]any{
		"input": "Hello from parent!",
	})
	if err != nil {
		t.Fatalf("Failed to execute child agent tool: %v", err)
	}

	// Verify the result contains the child agent's response
	content, ok := result.(*genai.Content)
	if !ok {
		t.Fatalf("Expected result to be a genai.Content, got %T", result)
	}

	expectedText := "Child agent response"
	actualText := ""
	if len(content.Parts) > 0 {
		actualText = content.Parts[0].Text
	}

	if actualText != expectedText {
		t.Errorf("Expected child agent response to be '%s', got '%s'", expectedText, actualText)
	}
}
