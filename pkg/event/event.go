// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package event

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Some constants and error definitions
var (
	// ErrInvalidEventID indicates an invalid event ID.
	ErrInvalidEventID = errors.New("invalid event ID")

	// ErrEmptyAuthor indicates an empty author field.
	ErrEmptyAuthor = errors.New("author cannot be empty")

	// DefaultIDLength is the default length of generated IDs.
	DefaultIDLength = 8
)

// FunctionCall represents a function call made by an agent.
type FunctionCall struct {
	// ID is the unique identifier for this function call.
	ID string `json:"id,omitempty"`

	// Name is the name of the function.
	Name string `json:"name"`

	// Parameters contains the parameters passed to the function.
	Parameters map[string]any `json:"parameters"`

	// Response contains the response from the function call.
	Response map[string]any `json:"response,omitempty"`

	// IsLongRunning indicates if this is a long-running function call.
	IsLongRunning bool `json:"is_long_running,omitempty"`
}

// Event represents an event in a conversation between agents and users.
type Event struct {
	// InvocationID is a unique identifier for this event.
	InvocationID string `json:"invocation_id"`

	// Author is who created the event ("user" or agent name).
	Author string `json:"author"`

	// Content is the text content of the event.
	Content string `json:"content"`

	// Actions contains actions taken by the agent.
	Actions *EventActions `json:"actions,omitempty"`

	// FunctionCalls contains the function calls in this event.
	FunctionCalls []FunctionCall `json:"function_calls,omitempty"`

	// LongRunningToolIDs contains IDs of long-running function calls.
	LongRunningToolIDs []string `json:"long_running_tool_ids,omitempty"`

	// Branch tracks the agent conversation hierarchy.
	Branch string `json:"branch,omitempty"`

	// Timestamp is when the event was created.
	Timestamp time.Time `json:"timestamp"`
}

// NewEvent creates a new Event instance.
func NewEvent(author, content string) (*Event, error) {
	if author == "" {
		return nil, ErrEmptyAuthor
	}

	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID: %w", err)
	}

	return &Event{
		InvocationID:       id,
		Author:             author,
		Content:            content,
		Actions:            NewEventActions(),
		FunctionCalls:      []FunctionCall{},
		LongRunningToolIDs: []string{},
		Timestamp:          time.Now(),
	}, nil
}

// NewUserEvent creates a new event from a user.
func NewUserEvent(content string) (*Event, error) {
	return NewEvent("user", content)
}

// NewAgentEvent creates a new event from an agent.
func NewAgentEvent(agentName, content string) (*Event, error) {
	return NewEvent(agentName, content)
}

// WithBranch sets the branch field.
func (e *Event) WithBranch(branch string) *Event {
	e.Branch = branch
	return e
}

// AddFunctionCall adds a function call to the event.
func (e *Event) AddFunctionCall(name string, parameters map[string]any) (*FunctionCall, error) {
	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate function call ID: %w", err)
	}

	fc := FunctionCall{
		ID:         id,
		Name:       name,
		Parameters: parameters,
	}

	e.FunctionCalls = append(e.FunctionCalls, fc)
	return &fc, nil
}

// AddLongRunningFunctionCall adds a long-running function call to the event.
func (e *Event) AddLongRunningFunctionCall(name string, parameters map[string]any) (*FunctionCall, error) {
	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate function call ID: %w", err)
	}

	fc := FunctionCall{
		ID:            id,
		Name:          name,
		Parameters:    parameters,
		IsLongRunning: true,
	}

	e.FunctionCalls = append(e.FunctionCalls, fc)
	e.LongRunningToolIDs = append(e.LongRunningToolIDs, id)

	return &fc, nil
}

// SetFunctionResponse sets the response for a function call.
func (e *Event) SetFunctionResponse(id string, response map[string]any) error {
	for i, fc := range e.FunctionCalls {
		if fc.ID == id {
			e.FunctionCalls[i].Response = response
			return nil
		}
	}

	return fmt.Errorf("function call with ID %s not found", id)
}

// IsFinalResponse determines if this is the final agent response.
func (e *Event) IsFinalResponse() bool {
	// If it's a user event, it's not a final response
	if e.Author == "user" {
		return false
	}

	// If there are long-running tools, it's not final
	if len(e.LongRunningToolIDs) > 0 {
		return false
	}

	// Check if all function calls have responses
	for _, fc := range e.FunctionCalls {
		if fc.Response == nil {
			return false
		}
	}

	return true
}

// GetFunctionCalls retrieves function calls in the event.
func (e *Event) GetFunctionCalls() []FunctionCall {
	// Return a copy to prevent modification
	calls := make([]FunctionCall, len(e.FunctionCalls))
	copy(calls, e.FunctionCalls)
	return calls
}

// GetFunctionResponses retrieves function responses.
func (e *Event) GetFunctionResponses() map[string]map[string]any {
	responses := make(map[string]map[string]any)

	for _, fc := range e.FunctionCalls {
		if fc.Response != nil {
			responses[fc.Name] = fc.Response
		}
	}

	return responses
}

// HasTrailingCodeExecutionResult checks for code execution results.
func (e *Event) HasTrailingCodeExecutionResult() bool {
	return strings.Contains(e.Content, "<code_execution_result>") &&
		strings.HasSuffix(strings.TrimSpace(e.Content), "</code_execution_result>")
}

// NewID generates a random ID with the default length.
func NewID() (string, error) {
	return GenerateRandomID(DefaultIDLength)
}

// GenerateRandomID generates a random ID with the specified length.
func GenerateRandomID(length int) (string, error) {
	bytes := make([]byte, length/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
