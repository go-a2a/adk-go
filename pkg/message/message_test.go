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

package message_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/message"
)

func TestNewUserMessage(t *testing.T) {
	content := "Hello, world!"
	msg := message.NewUserMessage(content)

	assert.Equal(t, message.RoleUser, msg.Role)
	assert.Equal(t, content, msg.Content)
	assert.NotEmpty(t, msg.ID)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestNewSystemMessage(t *testing.T) {
	content := "System instruction"
	msg := message.NewSystemMessage(content)

	assert.Equal(t, message.RoleSystem, msg.Role)
	assert.Equal(t, content, msg.Content)
	assert.NotEmpty(t, msg.ID)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestNewAssistantMessage(t *testing.T) {
	content := "Assistant response"
	msg := message.NewAssistantMessage(content)

	assert.Equal(t, message.RoleAssistant, msg.Role)
	assert.Equal(t, content, msg.Content)
	assert.NotEmpty(t, msg.ID)
	assert.False(t, msg.Timestamp.IsZero())
}

func TestNewToolResultMessage(t *testing.T) {
	callID := "tool_call_123"
	content := "Tool result content"
	msg := message.NewToolResultMessage(callID, content)

	assert.Equal(t, message.RoleTool, msg.Role)
	assert.NotEmpty(t, msg.ID)
	assert.False(t, msg.Timestamp.IsZero())
	assert.Len(t, msg.ToolResults, 1)
	assert.Equal(t, callID, msg.ToolResults[0].CallID)
	assert.Equal(t, content, msg.ToolResults[0].Content)
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

	assert.Equal(t, message.RoleAssistant, msg.Role)
	assert.NotEmpty(t, msg.ID)
	assert.False(t, msg.Timestamp.IsZero())
	assert.Len(t, msg.ToolCalls, 2)
	assert.Equal(t, toolCalls, msg.ToolCalls)
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
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Parse back into a message
	parsedMsg, err := message.MessageFromJSON(jsonData)
	assert.NoError(t, err)

	// Verify fields
	assert.Equal(t, msg.Role, parsedMsg.Role)
	assert.Equal(t, msg.Content, parsedMsg.Content)
	assert.Equal(t, msg.ID, parsedMsg.ID)
	assert.Equal(t, msg.Timestamp.Unix(), parsedMsg.Timestamp.Unix())
	assert.Len(t, parsedMsg.ToolCalls, 1)
	assert.Equal(t, msg.ToolCalls[0].ID, parsedMsg.ToolCalls[0].ID)
	assert.Equal(t, msg.ToolCalls[0].Name, parsedMsg.ToolCalls[0].Name)
	assert.Equal(t, string(msg.ToolCalls[0].Args), string(parsedMsg.ToolCalls[0].Args))
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
	assert.NoError(t, err)

	assert.Equal(t, message.RoleAssistant, msg.Role)
	assert.Equal(t, "Test content", msg.Content)
	assert.Equal(t, "msg_123", msg.ID)
	assert.Equal(t, 2023, msg.Timestamp.Year())
	assert.Len(t, msg.ToolCalls, 1)
	assert.Equal(t, "tool_call_1", msg.ToolCalls[0].ID)
	assert.Equal(t, "search", msg.ToolCalls[0].Name)
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
	assert.Equal(t, original.Role, clone.Role)
	assert.Equal(t, original.Content, clone.Content)
	assert.Equal(t, original.ID, clone.ID)
	assert.Equal(t, original.Timestamp, clone.Timestamp)
	assert.Len(t, clone.ToolCalls, 1)
	assert.Equal(t, original.ToolCalls[0].ID, clone.ToolCalls[0].ID)
	assert.Equal(t, original.ToolCalls[0].Name, clone.ToolCalls[0].Name)
	assert.Equal(t, string(original.ToolCalls[0].Args), string(clone.ToolCalls[0].Args))
	assert.Len(t, clone.ToolResults, 1)
	assert.Equal(t, original.ToolResults[0].CallID, clone.ToolResults[0].CallID)
	assert.Equal(t, original.ToolResults[0].Content, clone.ToolResults[0].Content)

	// Verify deep copy by modifying the clone
	clone.ToolCalls[0].Name = "modified"
	clone.ToolResults[0].Content = "modified"

	assert.NotEqual(t, clone.ToolCalls[0].Name, original.ToolCalls[0].Name)
	assert.NotEqual(t, clone.ToolResults[0].Content, original.ToolResults[0].Content)
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
	assert.True(t, found)
	assert.Equal(t, "tool_call_2", tool.ID)
	assert.Equal(t, "calculator", tool.Name)

	// Try to find non-existent tool
	_, found = msg.GetToolByName("non_existent")
	assert.False(t, found)
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
	assert.True(t, found)
	assert.Equal(t, "tool_call_2", result.CallID)
	assert.Equal(t, "Calculation result: 2", result.Content)

	// Try to find non-existent tool result
	_, found = msg.GetToolResultByCallID("non_existent")
	assert.False(t, found)
}
