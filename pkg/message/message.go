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

package message

import (
	"encoding/json"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
)

// Role represents who sent a message.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleSystem    Role = "system"
	RoleTool      Role = "tool"
)

// Message represents a message in a conversation.
type Message struct {
	Role        Role         `json:"role"`
	Content     string       `json:"content,omitempty"`
	ID          string       `json:"id,omitempty"`
	ToolCalls   []ToolCall   `json:"tool_calls,omitempty"`
	ToolResults []ToolResult `json:"tool_results,omitempty"`
	Timestamp   time.Time    `json:"timestamp,omitzero"`
}

// ToolCall represents a request to use a tool.
type ToolCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

// ToolResult represents the result of a tool call.
type ToolResult struct {
	CallID  string `json:"call_id"`
	Content string `json:"content"`
}

// NewUserMessage creates a new message from the user.
func NewUserMessage(content string) Message {
	return Message{
		Role:      RoleUser,
		Content:   content,
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
	}
}

// NewSystemMessage creates a new system message.
func NewSystemMessage(content string) Message {
	return Message{
		Role:      RoleSystem,
		Content:   content,
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
	}
}

// NewAssistantMessage creates a new assistant message.
func NewAssistantMessage(content string) Message {
	return Message{
		Role:      RoleAssistant,
		Content:   content,
		ID:        uuid.NewString(),
		Timestamp: time.Now(),
	}
}

// NewToolResultMessage creates a new tool result message.
func NewToolResultMessage(callID, content string) Message {
	return Message{
		Role: RoleTool,
		ID:   uuid.NewString(),
		ToolResults: []ToolResult{
			{
				CallID:  callID,
				Content: content,
			},
		},
		Timestamp: time.Now(),
	}
}

// NewAssistantToolCallMessage creates a message with tool calls.
func NewAssistantToolCallMessage(toolCalls []ToolCall) Message {
	return Message{
		Role:      RoleAssistant,
		ID:        uuid.NewString(),
		ToolCalls: toolCalls,
		Timestamp: time.Now(),
	}
}

// ToJSON serializes the message to JSON.
func (m Message) ToJSON() ([]byte, error) {
	return sonic.Marshal(m)
}

// MessageFromJSON deserializes a JSON string into a Message.
func MessageFromJSON(data []byte) (Message, error) {
	var msg Message
	err := sonic.Unmarshal(data, &msg)
	return msg, err
}

// Clone creates a deep copy of the message.
func (m Message) Clone() Message {
	clone := Message{
		Role:      m.Role,
		Content:   m.Content,
		ID:        m.ID,
		Timestamp: m.Timestamp,
	}

	if len(m.ToolCalls) > 0 {
		clone.ToolCalls = make([]ToolCall, len(m.ToolCalls))
		for i, tc := range m.ToolCalls {
			clone.ToolCalls[i] = ToolCall{
				ID:   tc.ID,
				Name: tc.Name,
				Args: tc.Args,
			}
		}
	}

	if len(m.ToolResults) > 0 {
		clone.ToolResults = make([]ToolResult, len(m.ToolResults))
		for i, tr := range m.ToolResults {
			clone.ToolResults[i] = ToolResult{
				CallID:  tr.CallID,
				Content: tr.Content,
			}
		}
	}

	return clone
}

// GetToolByName returns a tool call by name if it exists in the message.
func (m Message) GetToolByName(name string) (ToolCall, bool) {
	for _, tc := range m.ToolCalls {
		if tc.Name == name {
			return tc, true
		}
	}
	return ToolCall{}, false
}

// GetToolResultByCallID returns a tool result by call ID if it exists in the message.
func (m Message) GetToolResultByCallID(callID string) (ToolResult, bool) {
	for _, tr := range m.ToolResults {
		if tr.CallID == callID {
			return tr, true
		}
	}
	return ToolResult{}, false
}
