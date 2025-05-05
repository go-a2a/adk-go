// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"testing"
)

func TestBaseAgent(t *testing.T) {
	// Create a base agent
	agent := NewBaseAgent("TestAgent")

	// Check name
	if agent.Name() != "TestAgent" {
		t.Errorf("Expected name to be TestAgent, got %s", agent.Name())
	}

	// Check tools
	if len(agent.Tools()) != 0 {
		t.Errorf("Expected 0 tools, got %d", len(agent.Tools()))
	}

	// Add a tool
	tool := NewTool(
		WithName("test_tool"),
		WithDescription("A test tool"),
	)

	if err := agent.AddTool(tool); err != nil {
		t.Errorf("Failed to add tool: %v", err)
	}

	// Check tools again
	if len(agent.Tools()) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(agent.Tools()))
	}

	// Check streaming
	if agent.IsStreaming() {
		t.Errorf("Expected IsStreaming to be false")
	}
}

func TestSimpleMemory(t *testing.T) {
	// Create a memory
	memory := NewSimpleMemory(5)

	// Add messages
	for i := 0; i < 10; i++ {
		err := memory.Add("user", "Message "+string(rune('0'+i)))
		if err != nil {
			t.Fatalf("Failed to add message: %v", err)
		}
	}

	// Get messages
	messages, err := memory.Get()
	if err != nil {
		t.Fatalf("Failed to get messages: %v", err)
	}

	// Check that we only have 5 messages (due to max size)
	if len(messages) != 5 {
		t.Errorf("Expected 5 messages, got %d", len(messages))
	}

	// Check that we have the last 5 messages
	for i, msg := range messages {
		expected := "Message " + string(rune('0'+i+5))
		if msg.Content != expected {
			t.Errorf("Expected message %d to be %s, got %s", i, expected, msg.Content)
		}
	}

	// Clear memory
	err = memory.Clear()
	if err != nil {
		t.Fatalf("Failed to clear memory: %v", err)
	}

	// Check that memory is empty
	messages, err = memory.Get()
	if err != nil {
		t.Fatalf("Failed to get messages: %v", err)
	}

	if len(messages) != 0 {
		t.Errorf("Expected 0 messages after clear, got %d", len(messages))
	}
}

func TestTool(t *testing.T) {
	// Create a tool
	tool := NewTool(
		WithName("calculator"),
		WithDescription("A simple calculator"),
		WithSchema(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"operation": map[string]any{
					"type": "string",
					"enum": []string{"add", "subtract", "multiply", "divide"},
				},
				"a": map[string]any{
					"type": "number",
				},
				"b": map[string]any{
					"type": "number",
				},
			},
			"required": []string{"operation", "a", "b"},
		}),
		WithExecutor(func(ctx context.Context, input any) (any, error) {
			// Parse input
			inputMap, ok := input.(map[string]any)
			if !ok {
				t.Fatalf("Input is not a map")
			}

			operation := inputMap["operation"].(string)
			a := inputMap["a"].(float64)
			b := inputMap["b"].(float64)

			var result float64
			switch operation {
			case "add":
				result = a + b
			case "subtract":
				result = a - b
			case "multiply":
				result = a * b
			case "divide":
				result = a / b
			}

			return map[string]any{
				"result": result,
			}, nil
		}),
	)

	// Check tool properties
	if tool.Name() != "calculator" {
		t.Errorf("Expected name to be calculator, got %s", tool.Name())
	}

	if tool.Description() != "A simple calculator" {
		t.Errorf("Expected description to be 'A simple calculator', got %s", tool.Description())
	}

	// Execute tool
	input := map[string]any{
		"operation": "add",
		"a":         5.0,
		"b":         3.0,
	}

	result, err := tool.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("Failed to execute tool: %v", err)
	}

	// Check result
	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("Result is not a map")
	}

	if resultMap["result"].(float64) != 8.0 {
		t.Errorf("Expected result to be 8.0, got %f", resultMap["result"].(float64))
	}
}
