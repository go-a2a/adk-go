// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package event

import (
	rand "math/rand/v2"
	"time"
	"unsafe"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
)

// Event represents an event in a conversation between agents and users.
//
// It is used to store the content of the conversation, as well as the actions
// taken by the agents like function calls, etc.
type Event struct {
	*model.LLMResponse

	// InvocationID is The invocation ID of the event.
	InvocationID string

	// Author is the 'user' or the name of the agent, indicating who appended the event to the session.
	Author string

	// Actions is the Actions taken by the agent
	Actions EventActions

	// LongRunningToolIDs set of ids of the long running function calls.
	// Agent client will know from this field about which function call is long running.
	// only valid for function call event
	LongRunningToolIDs []string

	// Branch is The Branch of the event.
	//
	// The format is like agent_1.agent_2.agent_3, where agent_1 is the parent of
	// agent_2, and agent_2 is the parent of agent_3.
	//
	// Branch is used when multiple sub-agent shouldn't see their peer agents'
	// conversation history.
	Branch string

	// ID is the unique identifier of the event.
	ID string

	// Timestamp is The Timestamp of the event.
	Timestamp time.Time
}

// NewEvent creates a new event with a unique ID and timestamp.
func NewEvent() *Event {
	ev := &Event{
		ID:        newID(),
		Timestamp: time.Now(),
	}
	return ev
}

// IsFinalResponse returns whether the event is the final response of the agent.
func (e *Event) IsFinalResponse() bool {
	if e.Actions.SkipSummarization || len(e.LongRunningToolIDs) > 0 {
		return true
	}

	return len(e.GetFunctionCalls()) == 0 && len(e.GetFunctionResponses()) == 0 && !e.Partial && !e.HasTrailingCodeExecutionResult()
}

// GetFunctionCalls returns the function calls in the event.
func (e *Event) GetFunctionCalls() []*genai.FunctionCall {
	var funcCalls []*genai.FunctionCall
	if e.Content != nil && len(e.Content.Parts) > 0 {
		for _, part := range e.Content.Parts {
			if part.FunctionCall != nil {
				funcCalls = append(funcCalls, part.FunctionCall)
			}
		}
	}

	return funcCalls
}

// GetFunctionResponses returns the function responses in the event.
func (e *Event) GetFunctionResponses() []*genai.FunctionResponse {
	var funcResponse []*genai.FunctionResponse
	if e.Content != nil && len(e.Content.Parts) > 0 {
		for _, part := range e.Content.Parts {
			if part.FunctionResponse != nil {
				funcResponse = append(funcResponse, part.FunctionResponse)
			}
		}
	}

	return funcResponse
}

// HasTrailingCodeExecutionResult returns whether the event has a trailing code execution result.
func (e *Event) HasTrailingCodeExecutionResult() bool {
	if e.Content != nil && len(e.Content.Parts) > 0 {
		return e.Content.Parts[len(e.Content.Parts)-1].CodeExecutionResult != nil
	}
	return false
}

// NewID generates a new random ID for the event.
func (e *Event) NewID() string {
	return newID()
}

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func newID() string {
	b := make([]byte, 8)
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax letters!
	for i, cache, remain := 8-1, rand.Int64(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int64(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}
