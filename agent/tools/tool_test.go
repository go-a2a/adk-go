// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"testing"

	"github.com/go-a2a/adk-go/agent/events"
	"github.com/go-a2a/adk-go/internal/jsonschema"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/genai"
)

// TestBaseTool tests the creation and usage of a basic tool.
func TestBaseTool(t *testing.T) {
	// Create a schema for the tool input
	inputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"message": {
				Type:        "string",
				Description: "The message to echo",
			},
			"count": {
				Type:        "number",
				Description: "The number of times to repeat the message",
			},
		},
		Required: []string{"message"},
	}

	// Create a schema for the tool output
	outputSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"result": {
				Type:        "string",
				Description: "The echoed message",
			},
		},
		Required: []string{"result"},
	}

	// Create a tool execution function
	executeFn := func(ctx context.Context, params map[string]any) (any, error) {
		message, _ := params["message"].(string)
		count, ok := params["count"].(float64)
		if !ok {
			count = 1
		}

		result := ""
		for i := 0; i < int(count); i++ {
			if i > 0 {
				result += " "
			}
			result += message
		}

		return map[string]any{
			"result": result,
		}, nil
	}

	// Create a tool
	tool := NewBaseTool(
		WithName("echo"),
		WithDescription("Echoes back the input message"),
		WithInputSchema(inputSchema),
		WithOutputSchema(outputSchema),
		WithExecuteFunc(executeFn),
	)

	// Verify the tool properties
	if tool.Name() != "echo" {
		t.Errorf("Expected tool name to be 'echo', got %s", tool.Name())
	}

	if tool.Description() != "Echoes back the input message" {
		t.Errorf("Expected tool description to be 'Echoes back the input message', got %s", tool.Description())
	}

	// Test tool execution with valid parameters
	result, err := tool.Execute(context.Background(), map[string]any{
		"message": "Hello",
		"count":   float64(3),
	})
	if err != nil {
		t.Fatalf("Failed to execute tool: %v", err)
	}

	// Verify the result
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Expected result to be a map, got %T", result)
	}

	expectedResult := "Hello Hello Hello"
	if resultMap["result"] != expectedResult {
		t.Errorf("Expected result to be '%s', got '%s'", expectedResult, resultMap["result"])
	}

	// Test conversion to genai.Tool
	genaiTool := tool.ToGenAITool()

	if len(genaiTool.FunctionDeclarations) != 1 {
		t.Fatalf("Expected 1 function declaration, got %d", len(genaiTool.FunctionDeclarations))
	}

	if genaiTool.FunctionDeclarations[0].Name != "echo" {
		t.Errorf("Expected function name to be 'echo', got %s", genaiTool.FunctionDeclarations[0].Name)
	}

	if genaiTool.FunctionDeclarations[0].Description != "Echoes back the input message" {
		t.Errorf("Expected function description to be 'Echoes back the input message', got %s", genaiTool.FunctionDeclarations[0].Description)
	}
}

// TestToolRegistry tests the creation and usage of a tool registry.
func TestToolRegistry(t *testing.T) {
	// Create a tool registry
	registry := NewRegistry()

	// Create a simple tool
	tool1 := NewBaseTool(
		WithName("tool1"),
		WithDescription("Tool 1"),
		WithExecuteFunc(func(ctx context.Context, params map[string]any) (any, error) {
			return "tool1-result", nil
		}),
	)

	// Create another tool
	tool2 := NewBaseTool(
		WithName("tool2"),
		WithDescription("Tool 2"),
		WithExecuteFunc(func(ctx context.Context, params map[string]any) (any, error) {
			return "tool2-result", nil
		}),
	)

	// Register the tools
	err := registry.RegisterTool(tool1)
	if err != nil {
		t.Fatalf("Failed to register tool1: %v", err)
	}

	err = registry.RegisterTool(tool2)
	if err != nil {
		t.Fatalf("Failed to register tool2: %v", err)
	}

	// Verify the tools were registered
	if len(registry.ListTools()) != 2 {
		t.Errorf("Expected 2 tools, got %d", len(registry.ListTools()))
	}

	// Retrieve and verify a tool
	retrievedTool, exists := registry.GetTool("tool1")
	if !exists {
		t.Fatal("Expected to find tool1, but it was not found")
	}

	if retrievedTool.Name() != "tool1" {
		t.Errorf("Expected tool name to be 'tool1', got %s", retrievedTool.Name())
	}

	// Execute a tool
	result, err := registry.ExecuteTool(context.Background(), "tool2", map[string]any{})
	if err != nil {
		t.Fatalf("Failed to execute tool2: %v", err)
	}

	if result != "tool2-result" {
		t.Errorf("Expected result to be 'tool2-result', got %v", result)
	}
}

// TestHandleToolCall tests the handling of tool call events.
func TestHandleToolCall(t *testing.T) {
	// Create a tool registry
	registry := NewRegistry()

	// Create a tool
	tool := NewBaseTool(
		WithName("echo"),
		WithDescription("Echoes back the input"),
		WithExecuteFunc(func(ctx context.Context, params map[string]any) (any, error) {
			message, _ := params["message"].(string)
			return map[string]any{"result": "Echo: " + message}, nil
		}),
	)

	// Register the tool
	err := registry.RegisterTool(tool)
	if err != nil {
		t.Fatalf("Failed to register tool: %v", err)
	}

	// Create a tool call event
	event, err := events.NewToolCallEvent("test-session", "test-agent", "echo", map[string]any{
		"message": "Hello, world!",
	}, "parent-event-id")
	if err != nil {
		t.Fatalf("Failed to create tool call event: %v", err)
	}

	// Track emitted events
	var emittedEvent *events.Event

	// Create an event emitter function
	emitEvent := func(e *events.Event) error {
		emittedEvent = e
		return nil
	}

	// Handle the tool call
	err = registry.HandleToolCall(context.Background(), event, emitEvent)
	if err != nil {
		t.Fatalf("Failed to handle tool call: %v", err)
	}

	// Verify an event was emitted
	if emittedEvent == nil {
		t.Fatal("Expected an event to be emitted, but none was")
	}

	// Verify the event is a tool response
	if emittedEvent.Type != events.EventTypeToolResponse {
		t.Errorf("Expected event type to be ToolResponse, got %s", emittedEvent.Type)
	}

	// Verify the event has the correct session ID
	if emittedEvent.SessionID != "test-session" {
		t.Errorf("Expected session ID to be 'test-session', got %s", emittedEvent.SessionID)
	}

	// Verify the event has the correct agent ID
	if emittedEvent.AgentID != "test-agent" {
		t.Errorf("Expected agent ID to be 'test-agent', got %s", emittedEvent.AgentID)
	}

	// Verify the event has the correct parent event ID
	if emittedEvent.ParentEventID != event.ID {
		t.Errorf("Expected parent event ID to be '%s', got %s", event.ID, emittedEvent.ParentEventID)
	}

	// Extract and verify the tool response content
	responseContent, err := emittedEvent.GetToolResponseContent()
	if err != nil {
		t.Fatalf("Failed to extract tool response content: %v", err)
	}

	resultMap, ok := responseContent.Result.(map[string]any)
	if !ok {
		t.Fatalf("Expected result to be a map, got %T", responseContent.Result)
	}

	expectedResult := "Echo: Hello, world!"
	if resultMap["result"] != expectedResult {
		t.Errorf("Expected result to be '%s', got '%v'", expectedResult, resultMap["result"])
	}
}