// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package message_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/message"
)

func TestNewUserMessage(t *testing.T) {
	content := "Hello, world!"
	msg := message.NewUserMessage(content)

	if diff := cmp.Diff(message.RoleUser, msg.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(content, msg.Content); diff != "" {
		t.Errorf("incorrect content (-want +got):\n%s", diff)
	}
	if msg.ID == "" {
		t.Error("expected non-empty ID")
	}
	if msg.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestNewSystemMessage(t *testing.T) {
	content := "System instruction"
	msg := message.NewSystemMessage(content)

	if diff := cmp.Diff(message.RoleSystem, msg.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(content, msg.Content); diff != "" {
		t.Errorf("incorrect content (-want +got):\n%s", diff)
	}
	if msg.ID == "" {
		t.Error("expected non-empty ID")
	}
	if msg.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestNewAssistantMessage(t *testing.T) {
	content := "Assistant response"
	msg := message.NewAssistantMessage(content)

	if diff := cmp.Diff(message.RoleAssistant, msg.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(content, msg.Content); diff != "" {
		t.Errorf("incorrect content (-want +got):\n%s", diff)
	}
	if msg.ID == "" {
		t.Error("expected non-empty ID")
	}
	if msg.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestNewToolResultMessage(t *testing.T) {
	callID := "tool_call_123"
	content := "Tool result content"
	msg := message.NewToolResultMessage(callID, content)

	if diff := cmp.Diff(message.RoleTool, msg.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if msg.ID == "" {
		t.Error("expected non-empty ID")
	}
	if msg.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if len(msg.ToolResults) != 1 {
		t.Errorf("expected 1 tool result, got %d", len(msg.ToolResults))
	} else {
		if diff := cmp.Diff(callID, msg.ToolResults[0].CallID); diff != "" {
			t.Errorf("incorrect callID (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(content, msg.ToolResults[0].Content); diff != "" {
			t.Errorf("incorrect content (-want +got):\n%s", diff)
		}
	}
}

func TestNewAssistantToolCallMessage(t *testing.T) {
	toolCalls := []message.ToolCall{
		{
			ID:   "tool_call_1",
			Name: "search",
			Args: []byte(`{"query": "test"}`),
		},
		{
			ID:   "tool_call_2",
			Name: "calculate",
			Args: []byte(`{"expression": "1+1"}`),
		},
	}

	msg := message.NewAssistantToolCallMessage(toolCalls)

	if diff := cmp.Diff(message.RoleAssistant, msg.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if msg.ID == "" {
		t.Error("expected non-empty ID")
	}
	if msg.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if len(msg.ToolCalls) != 2 {
		t.Errorf("expected 2 tool calls, got %d", len(msg.ToolCalls))
	}
	if diff := cmp.Diff(toolCalls, msg.ToolCalls); diff != "" {
		t.Errorf("incorrect tool calls (-want +got):\n%s", diff)
	}
}

func TestToJSON(t *testing.T) {
	msg := message.Message{
		Role:      message.RoleAssistant,
		Content:   "Test content",
		ID:        "msg_123",
		Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		ToolCalls: []message.ToolCall{
			{
				ID:   "tool_call_1",
				Name: "search",
				Args: []byte(`{"query": "test"}`),
			},
		},
	}

	jsonData, err := msg.ToJSON()
	if err != nil {
		t.Fatalf("Failed to marshal message to JSON: %v", err)
	}
	if len(jsonData) == 0 {
		t.Error("expected non-empty JSON data")
	}

	// Parse back into a message
	parsedMsg, err := message.MessageFromJSON(jsonData)
	if err != nil {
		t.Fatalf("Failed to unmarshal message from JSON: %v", err)
	}

	// Verify fields
	if diff := cmp.Diff(msg.Role, parsedMsg.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(msg.Content, parsedMsg.Content); diff != "" {
		t.Errorf("incorrect content (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(msg.ID, parsedMsg.ID); diff != "" {
		t.Errorf("incorrect ID (-want +got):\n%s", diff)
	}
	if msg.Timestamp.Unix() != parsedMsg.Timestamp.Unix() {
		t.Errorf("incorrect timestamp: want %v, got %v", msg.Timestamp.Unix(), parsedMsg.Timestamp.Unix())
	}
	if len(parsedMsg.ToolCalls) != 1 {
		t.Errorf("expected 1 tool call, got %d", len(parsedMsg.ToolCalls))
		return
	}
	if diff := cmp.Diff(msg.ToolCalls[0].ID, parsedMsg.ToolCalls[0].ID); diff != "" {
		t.Errorf("incorrect tool call ID (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(msg.ToolCalls[0].Name, parsedMsg.ToolCalls[0].Name); diff != "" {
		t.Errorf("incorrect tool call name (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(string(msg.ToolCalls[0].Args), string(parsedMsg.ToolCalls[0].Args)); diff != "" {
		t.Errorf("incorrect tool call args (-want +got):\n%s", diff)
	}
}

func TestMessageFromJSON(t *testing.T) {
	jsonData := []byte(`
	{
		"role": "assistant",
		"content": "Test content",
		"id": "msg_123",
		"timestamp": "2023-01-01T12:00:00Z",
		"tool_calls": [
			{
				"id": "tool_call_1",
				"name": "search",
				"args": {"query": "test"}
			}
		]
	}`)

	msg, err := message.MessageFromJSON(jsonData)
	if err != nil {
		t.Fatalf("Failed to unmarshal message from JSON: %v", err)
	}

	if diff := cmp.Diff(message.RoleAssistant, msg.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("Test content", msg.Content); diff != "" {
		t.Errorf("incorrect content (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("msg_123", msg.ID); diff != "" {
		t.Errorf("incorrect ID (-want +got):\n%s", diff)
	}
	if msg.Timestamp.Year() != 2023 {
		t.Errorf("incorrect year: want 2023, got %d", msg.Timestamp.Year())
	}
	if len(msg.ToolCalls) != 1 {
		t.Errorf("expected 1 tool call, got %d", len(msg.ToolCalls))
		return
	}
	if diff := cmp.Diff("tool_call_1", msg.ToolCalls[0].ID); diff != "" {
		t.Errorf("incorrect tool call ID (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("search", msg.ToolCalls[0].Name); diff != "" {
		t.Errorf("incorrect tool call name (-want +got):\n%s", diff)
	}
}

func TestClone(t *testing.T) {
	original := message.Message{
		Role:      message.RoleAssistant,
		Content:   "Original content",
		ID:        "original_id",
		Timestamp: time.Now(),
		ToolCalls: []message.ToolCall{
			{
				ID:   "tool_call_1",
				Name: "search",
				Args: []byte(`{"query": "test"}`),
			},
		},
		ToolResults: []message.ToolResult{
			{
				CallID:  "tool_call_1",
				Content: "Search results",
			},
		},
	}

	clone := original.Clone()

	// Verify all fields are copied
	if diff := cmp.Diff(original.Role, clone.Role); diff != "" {
		t.Errorf("incorrect role (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(original.Content, clone.Content); diff != "" {
		t.Errorf("incorrect content (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(original.ID, clone.ID); diff != "" {
		t.Errorf("incorrect ID (-want +got):\n%s", diff)
	}
	if !original.Timestamp.Equal(clone.Timestamp) {
		t.Errorf("incorrect timestamp: want %v, got %v", original.Timestamp, clone.Timestamp)
	}
	if len(clone.ToolCalls) != 1 {
		t.Errorf("expected 1 tool call, got %d", len(clone.ToolCalls))
		return
	}
	if diff := cmp.Diff(original.ToolCalls[0].ID, clone.ToolCalls[0].ID); diff != "" {
		t.Errorf("incorrect tool call ID (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(original.ToolCalls[0].Name, clone.ToolCalls[0].Name); diff != "" {
		t.Errorf("incorrect tool call name (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(string(original.ToolCalls[0].Args), string(clone.ToolCalls[0].Args)); diff != "" {
		t.Errorf("incorrect tool call args (-want +got):\n%s", diff)
	}
	if len(clone.ToolResults) != 1 {
		t.Errorf("expected 1 tool result, got %d", len(clone.ToolResults))
		return
	}
	if diff := cmp.Diff(original.ToolResults[0].CallID, clone.ToolResults[0].CallID); diff != "" {
		t.Errorf("incorrect tool result callID (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(original.ToolResults[0].Content, clone.ToolResults[0].Content); diff != "" {
		t.Errorf("incorrect tool result content (-want +got):\n%s", diff)
	}

	// Verify deep copy by modifying the clone
	clone.ToolCalls[0].Name = "modified"
	clone.ToolResults[0].Content = "modified"

	if original.ToolCalls[0].Name == clone.ToolCalls[0].Name {
		t.Error("expected tool call name to be different after modification")
	}
	if original.ToolResults[0].Content == clone.ToolResults[0].Content {
		t.Error("expected tool result content to be different after modification")
	}
}

func TestGetToolByName(t *testing.T) {
	msg := message.Message{
		ToolCalls: []message.ToolCall{
			{
				ID:   "tool_call_1",
				Name: "search",
				Args: []byte(`{"query": "test"}`),
			},
			{
				ID:   "tool_call_2",
				Name: "calculator",
				Args: []byte(`{"expression": "1+1"}`),
			},
		},
	}

	// Find existing tool
	tool, found := msg.GetToolByName("calculator")
	if !found {
		t.Error("expected to find tool with name 'calculator'")
	}
	if diff := cmp.Diff("tool_call_2", tool.ID); diff != "" {
		t.Errorf("incorrect tool ID (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("calculator", tool.Name); diff != "" {
		t.Errorf("incorrect tool name (-want +got):\n%s", diff)
	}

	// Try to find non-existent tool
	_, found = msg.GetToolByName("non_existent")
	if found {
		t.Error("expected not to find tool with name 'non_existent'")
	}
}

func TestGetToolResultByCallID(t *testing.T) {
	msg := message.Message{
		ToolResults: []message.ToolResult{
			{
				CallID:  "tool_call_1",
				Content: "Search results",
			},
			{
				CallID:  "tool_call_2",
				Content: "Calculation result: 2",
			},
		},
	}

	// Find existing tool result
	result, found := msg.GetToolResultByCallID("tool_call_2")
	if !found {
		t.Error("expected to find tool result with callID 'tool_call_2'")
	}
	if diff := cmp.Diff("tool_call_2", result.CallID); diff != "" {
		t.Errorf("incorrect result callID (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff("Calculation result: 2", result.Content); diff != "" {
		t.Errorf("incorrect result content (-want +got):\n%s", diff)
	}

	// Try to find non-existent tool result
	_, found = msg.GetToolResultByCallID("non_existent")
	if found {
		t.Error("expected not to find tool result with callID 'non_existent'")
	}
}
