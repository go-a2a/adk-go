// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package events defines the event system for the ADK agents.
package events

import (
	"encoding/json"
	"time"

	"github.com/bytedance/sonic"
	"google.golang.org/genai"
)

// EventType represents the type of an event.
type EventType string

const (
	// EventTypeUserMessage represents a message from the user.
	EventTypeUserMessage EventType = "user_message"

	// EventTypeAgentResponse represents a response from the agent.
	EventTypeAgentResponse EventType = "agent_response"

	// EventTypeToolCall represents a tool call.
	EventTypeToolCall EventType = "tool_call"

	// EventTypeToolResponse represents a response from a tool.
	EventTypeToolResponse EventType = "tool_response"

	// EventTypeStateChange represents a state change.
	EventTypeStateChange EventType = "state_change"

	// EventTypeError represents an error.
	EventTypeError EventType = "error"
)

// Event represents an event in the agent system.
type Event struct {
	// ID is the unique identifier for the event.
	ID string `json:"id"`

	// Type is the type of the event.
	Type EventType `json:"type"`

	// Timestamp is the time when the event was created.
	Timestamp time.Time `json:"timestamp"`

	// SessionID is the ID of the session that the event belongs to.
	SessionID string `json:"session_id"`

	// AgentID is the ID of the agent that the event belongs to.
	AgentID string `json:"agent_id,omitempty"`

	// ParentEventID is the ID of the parent event, if any.
	ParentEventID string `json:"parent_event_id,omitempty"`

	// Content is the content of the event.
	Content json.RawMessage `json:"content"`
}

// UserMessageContent represents the content of a user message event.
type UserMessageContent struct {
	// Message is the user message.
	Message *genai.Content `json:"message"`
}

// AgentResponseContent represents the content of an agent response event.
type AgentResponseContent struct {
	// Response is the agent's response.
	Response *genai.Content `json:"response"`
}

// ToolCallContent represents the content of a tool call event.
type ToolCallContent struct {
	// Name is the name of the tool.
	Name string `json:"name"`

	// Parameters is the parameters for the tool call.
	Parameters map[string]any `json:"parameters"`
}

// ToolResponseContent represents the content of a tool response event.
type ToolResponseContent struct {
	// Result is the result of the tool call.
	Result any `json:"result"`

	// Error is the error message if the tool call failed.
	Error string `json:"error,omitempty"`
}

// StateChangeContent represents the content of a state change event.
type StateChangeContent struct {
	// Updates is the map of state updates.
	Updates map[string]any `json:"updates"`
}

// ErrorContent represents the content of an error event.
type ErrorContent struct {
	// Message is the error message.
	Message string `json:"message"`

	// Code is the error code.
	Code string `json:"code,omitempty"`
}

// NewUserMessageEvent creates a new user message event.
func NewUserMessageEvent(sessionID string, message *genai.Content) (*Event, error) {
	content := UserMessageContent{
		Message: message,
	}
	
	contentBytes, err := sonic.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	return &Event{
		ID:        generateID(),
		Type:      EventTypeUserMessage,
		Timestamp: time.Now(),
		SessionID: sessionID,
		Content:   contentBytes,
	}, nil
}

// NewAgentResponseEvent creates a new agent response event.
func NewAgentResponseEvent(sessionID, agentID string, response *genai.Content, parentEventID string) (*Event, error) {
	content := AgentResponseContent{
		Response: response,
	}
	
	contentBytes, err := sonic.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	return &Event{
		ID:            generateID(),
		Type:          EventTypeAgentResponse,
		Timestamp:     time.Now(),
		SessionID:     sessionID,
		AgentID:       agentID,
		ParentEventID: parentEventID,
		Content:       contentBytes,
	}, nil
}

// NewToolCallEvent creates a new tool call event.
func NewToolCallEvent(sessionID, agentID string, toolName string, parameters map[string]any, parentEventID string) (*Event, error) {
	content := ToolCallContent{
		Name:       toolName,
		Parameters: parameters,
	}
	
	contentBytes, err := sonic.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	return &Event{
		ID:            generateID(),
		Type:          EventTypeToolCall,
		Timestamp:     time.Now(),
		SessionID:     sessionID,
		AgentID:       agentID,
		ParentEventID: parentEventID,
		Content:       contentBytes,
	}, nil
}

// NewToolResponseEvent creates a new tool response event.
func NewToolResponseEvent(sessionID, agentID string, result any, errMsg string, parentEventID string) (*Event, error) {
	content := ToolResponseContent{
		Result: result,
		Error:  errMsg,
	}
	
	contentBytes, err := sonic.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	return &Event{
		ID:            generateID(),
		Type:          EventTypeToolResponse,
		Timestamp:     time.Now(),
		SessionID:     sessionID,
		AgentID:       agentID,
		ParentEventID: parentEventID,
		Content:       contentBytes,
	}, nil
}

// NewStateChangeEvent creates a new state change event.
func NewStateChangeEvent(sessionID, agentID string, updates map[string]any) (*Event, error) {
	content := StateChangeContent{
		Updates: updates,
	}
	
	contentBytes, err := sonic.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	return &Event{
		ID:        generateID(),
		Type:      EventTypeStateChange,
		Timestamp: time.Now(),
		SessionID: sessionID,
		AgentID:   agentID,
		Content:   contentBytes,
	}, nil
}

// NewErrorEvent creates a new error event.
func NewErrorEvent(sessionID, agentID, message, code, parentEventID string) (*Event, error) {
	content := ErrorContent{
		Message: message,
		Code:    code,
	}
	
	contentBytes, err := sonic.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	return &Event{
		ID:            generateID(),
		Type:          EventTypeError,
		Timestamp:     time.Now(),
		SessionID:     sessionID,
		AgentID:       agentID,
		ParentEventID: parentEventID,
		Content:       contentBytes,
	}, nil
}

// GetUserMessageContent extracts the user message content from the event.
func (e *Event) GetUserMessageContent() (*UserMessageContent, error) {
	if e.Type != EventTypeUserMessage {
		return nil, ErrInvalidEventType
	}
	
	var content UserMessageContent
	if err := sonic.Unmarshal(e.Content, &content); err != nil {
		return nil, err
	}
	
	return &content, nil
}

// GetAgentResponseContent extracts the agent response content from the event.
func (e *Event) GetAgentResponseContent() (*AgentResponseContent, error) {
	if e.Type != EventTypeAgentResponse {
		return nil, ErrInvalidEventType
	}
	
	var content AgentResponseContent
	if err := sonic.Unmarshal(e.Content, &content); err != nil {
		return nil, err
	}
	
	return &content, nil
}

// GetToolCallContent extracts the tool call content from the event.
func (e *Event) GetToolCallContent() (*ToolCallContent, error) {
	if e.Type != EventTypeToolCall {
		return nil, ErrInvalidEventType
	}
	
	var content ToolCallContent
	if err := sonic.Unmarshal(e.Content, &content); err != nil {
		return nil, err
	}
	
	return &content, nil
}

// GetToolResponseContent extracts the tool response content from the event.
func (e *Event) GetToolResponseContent() (*ToolResponseContent, error) {
	if e.Type != EventTypeToolResponse {
		return nil, ErrInvalidEventType
	}
	
	var content ToolResponseContent
	if err := sonic.Unmarshal(e.Content, &content); err != nil {
		return nil, err
	}
	
	return &content, nil
}

// GetStateChangeContent extracts the state change content from the event.
func (e *Event) GetStateChangeContent() (*StateChangeContent, error) {
	if e.Type != EventTypeStateChange {
		return nil, ErrInvalidEventType
	}
	
	var content StateChangeContent
	if err := sonic.Unmarshal(e.Content, &content); err != nil {
		return nil, err
	}
	
	return &content, nil
}

// GetErrorContent extracts the error content from the event.
func (e *Event) GetErrorContent() (*ErrorContent, error) {
	if e.Type != EventTypeError {
		return nil, ErrInvalidEventType
	}
	
	var content ErrorContent
	if err := sonic.Unmarshal(e.Content, &content); err != nil {
		return nil, err
	}
	
	return &content, nil
}

// ToJSON converts the event to a JSON string.
func (e *Event) ToJSON() (string, error) {
	bytes, err := sonic.ConfigFastest.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}