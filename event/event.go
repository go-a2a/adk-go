// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model/models"
)

// DefaultIDLength is the default length of generated IDs.
const DefaultIDLength = 8

// Some constants and error definitions.
var (
	// ErrInvalidEventID indicates an invalid event ID.
	ErrInvalidEventID = errors.New("invalid event ID")

	// ErrEmptyAuthor indicates an empty author field.
	ErrEmptyAuthor = errors.New("author cannot be empty")
)

// Event represents an event in a conversation between agents and users.
type Event struct {
	*models.LlmResponse

	// InvocationID is the invocation ID of the event.
	InvocationID string

	// Author is who created the event ("user" or agent name).
	Author string

	// Actions contains actions taken by the agent.
	Actions *EventActions

	// LongRunningToolIDs contains IDs of long-running function calls.
	//
	// Set of ids of the long running function calls.
	// Agent client will know from this field about which function call is long running.
	// Only valid for function call event
	LongRunningToolIDs []string

	// Branch tracks the agent conversation hierarchy.
	Branch string

	// ID is the unique identifier of the event.
	ID string

	// Timestamp is when the event was created.
	Timestamp time.Time
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

	ev := &Event{
		LlmResponse: &models.LlmResponse{
			Content: genai.NewContentFromText(content, genai.RoleUser),
		},
		ID:        id,
		Author:    author,
		Timestamp: time.Now(),
	}
	if author != "assistant" {
		ev.Actions = NewEventActions()
	}

	return ev, nil
}

// NewUserEvent creates a new event from a user.
func NewUserEvent(content string) (*Event, error) {
	return NewEvent("user", content)
}

// NewAgentEvent creates a new event from an agent.
func NewAgentEvent(author, content string) (*Event, error) {
	return NewEvent(author, content)
}

// WithBranch sets the branch field.
func (e *Event) WithBranch(branch string) *Event {
	e.Branch = branch
	return e
}

// IsFinalResponse returns whether the event is the final response of the agent.
func (e *Event) IsFinalResponse() bool {
	if e.Actions == nil {
		return false
	}
	// Returns whether the event is the final response of the agent
	if e.Actions.SkipSummarization || len(e.LongRunningToolIDs) > 0 {
		return true
	}

	return len(e.FunctionCalls()) != 0 && len(e.FunctionResponses()) != 0 && !e.Partial && e.HasTrailingCodeExecutionResult()
}

// FunctionCalls returns the function calls in the event.
func (e *Event) FunctionCalls() []genai.FunctionCall {
	if e.Content == nil {
		e.Content = &genai.Content{
			Parts: []*genai.Part{},
		}
	}

	// return a copy to prevent modification
	calls := make([]genai.FunctionCall, 0, len(e.Content.Parts))
	for _, part := range e.Content.Parts {
		if fncall := part.FunctionCall; fncall != nil {
			calls = append(calls, *fncall)
		}
	}

	return calls
}

// AddFunctionCall adds a function call to the event.
func (e *Event) AddFunctionCall(name string, args map[string]any) (*genai.FunctionCall, error) {
	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate function call ID: %w", err)
	}

	fc := genai.FunctionCall{
		ID:   id,
		Args: args,
		Name: name,
	}
	if e.Content == nil {
		e.Content = &genai.Content{
			Parts: []*genai.Part{},
		}
	}

	e.Content.Parts = append(e.Content.Parts, &genai.Part{FunctionCall: &fc})

	return &fc, nil
}

// AddLongRunningFunctionCall adds a long-running function call to the event.
func (e *Event) AddLongRunningFunctionCall(name string, args map[string]any) (*genai.FunctionCall, error) {
	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate function call ID: %w", err)
	}

	fc := genai.FunctionCall{
		ID:   id,
		Name: name,
		Args: args,
	}
	if e.Content == nil {
		e.Content = &genai.Content{
			Parts: []*genai.Part{},
		}
		e.LongRunningToolIDs = append(e.LongRunningToolIDs, id)
		return &fc, nil
	}

	// for i, part := range e.Content.Parts {
	// 	if part.FunctionResponse == nil {
	// 		part.FunctionCall = &fc
	// 		break
	// 	}
	// 	// if id == part.FunctionResponse.ID {
	// 	e.Content.Parts[i].FunctionCall = &fc
	// 	// }
	// }

	e.Content.Parts = append(e.Content.Parts, &genai.Part{FunctionCall: &fc})
	// for i, part := range e.Content.Parts {
	// 	if part.FunctionCall == nil {
	// 		e.Content.Parts[i].FunctionCall = &fc
	// 	}
	// }
	e.LongRunningToolIDs = append(e.LongRunningToolIDs, id)

	return &fc, nil
}

// FunctionResponses returns the function responses in the event.
func (e *Event) FunctionResponses() []*genai.FunctionResponse {
	if e.Content == nil {
		e.Content = &genai.Content{
			Parts: []*genai.Part{},
		}
	}

	responses := make([]*genai.FunctionResponse, 0, len(e.Content.Parts))
	for _, part := range e.Content.Parts {
		if fncresp := part.FunctionResponse; fncresp != nil {
			responses = append(responses, fncresp)
		}
	}

	return responses
}

// AddFunctionResponse sets the response for a function call.
func (e *Event) AddFunctionResponse(id string, response *genai.FunctionResponse) error {
	if e.Content == nil {
		e.Content = &genai.Content{
			Parts: []*genai.Part{},
		}
	}

	found := false
	for i, part := range e.Content.Parts {
		if part.FunctionCall == nil {
			continue
		}
		if id == part.FunctionCall.ID {
			e.Content.Parts[i].FunctionResponse = response
			e.Content.Parts[i].FunctionResponse.ID = id
			e.Content.Parts[i].FunctionResponse.Name = part.FunctionCall.Name
			found = true
		}
	}

	if !found {
		return ErrInvalidEventID
	}

	return nil
}

// HasTrailingCodeExecutionResult checks for code execution results.
func (e *Event) HasTrailingCodeExecutionResult() bool {
	if e.Content == nil || len(e.Content.Parts) == 0 {
		return false
	}

	parts := e.Content.Parts
	return parts[len(parts)-1].CodeExecutionResult != nil
}

// NewID generates a random ID with the default length.
func NewID() (string, error) {
	bytes := make([]byte, DefaultIDLength/2)
	rand.Read(bytes)

	return hex.EncodeToString(bytes), nil
}
