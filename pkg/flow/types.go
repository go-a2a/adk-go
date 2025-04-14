// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package flow

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/event"
)

// InvocationContext contains the context information for a flow invocation.
type InvocationContext struct {
	// SessionID is the unique identifier for the session.
	SessionID string

	// ExecutionID is the unique identifier for this execution.
	ExecutionID string

	// Events is the list of events in the conversation history.
	Events []*event.Event

	// Properties contains additional properties for the invocation.
	Properties map[string]any
}

// NewInvocationContext creates a new InvocationContext with the given session ID.
func NewInvocationContext(sessionID string) *InvocationContext {
	return &InvocationContext{
		SessionID:   sessionID,
		ExecutionID: "",
		Events:      []*event.Event{},
		Properties:  make(map[string]any),
	}
}

// WithExecutionID sets the execution ID.
func (ic *InvocationContext) WithExecutionID(executionID string) *InvocationContext {
	ic.ExecutionID = executionID
	return ic
}

// WithEvents sets the events.
func (ic *InvocationContext) WithEvents(events []*event.Event) *InvocationContext {
	ic.Events = events
	return ic
}

// AddEvent adds an event to the context.
func (ic *InvocationContext) AddEvent(event *event.Event) *InvocationContext {
	ic.Events = append(ic.Events, event)
	return ic
}

// WithProperty sets a property in the context.
func (ic *InvocationContext) WithProperty(key string, value any) *InvocationContext {
	ic.Properties[key] = value
	return ic
}

// LLMRequest represents a request to an LLM.
type LLMRequest struct {
	// Model is the name of the model to use.
	Model string

	// Messages is the list of messages in the conversation.
	Messages []Message

	// Tools is the list of tools available to the model.
	Tools []Tool

	// GenerationConfig contains the generation configuration.
	GenerationConfig *GenerationConfig

	// System is the system message for the conversation.
	System string

	// ConnectionOptions contains connection-specific options.
	ConnectionOptions map[string]any
}

// Message represents a message in a conversation.
type Message struct {
	// Role is the role of the message sender (e.g., "user", "assistant").
	Role string

	// Content is the text content of the message.
	Content string

	// Name is an optional name for the message author.
	Name string

	// FunctionCalls contains any function calls in the message.
	FunctionCalls []event.FunctionCall
}

// Tool represents a tool available to the model.
type Tool struct {
	// Name is the name of the tool.
	Name string

	// Description is a description of what the tool does.
	Description string

	// InputSchema is the JSON schema for the tool input.
	InputSchema map[string]any
}

// GenerationConfig contains configuration for text generation.
type GenerationConfig struct {
	// Temperature controls randomness in generation (0.0-1.0).
	Temperature float64

	// MaxTokens is the maximum number of tokens to generate.
	MaxTokens int

	// TopP controls diversity via nucleus sampling (0.0-1.0).
	TopP float64

	// TopK controls diversity via top-k sampling.
	TopK int

	// StopSequences are sequences that stop generation when encountered.
	StopSequences []string
}

// LLMResponse represents a response from an LLM.
type LLMResponse struct {
	// Content is the text content of the response.
	Content string

	// FunctionCalls contains any function calls in the response.
	FunctionCalls []event.FunctionCall
}

// Flow defines the interface for a flow that processes requests.
type Flow interface {
	// Run executes the flow with the given context and returns a channel of events.
	Run(ctx context.Context, ic *InvocationContext) (<-chan *event.Event, error)

	// RunLive executes the flow with the given context and streams events to the callback.
	RunLive(ctx context.Context, ic *InvocationContext, callback func(*event.Event)) error
}
