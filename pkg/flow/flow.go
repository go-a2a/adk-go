// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package flow provides structures and functionality for defining and executing
// LLM-powered agent flows and interactions.
package flow

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/event"
)

// InvocationContext contains the context information for a flow invocation.
type InvocationContext struct {
	// UserID identifies the user for this flow invocation.
	UserID string

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
func NewInvocationContext(userID, sessionID string) *InvocationContext {
	return &InvocationContext{
		UserID:      userID,
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

// ProcessorConfig encapsulates configuration for flow processors.
type ProcessorConfig struct {
	// Logger is the logger to use for flow processing.
	Logger *slog.Logger

	// RequestProcessors is the list of processors to use for requests.
	RequestProcessors []RequestProcessor

	// ResponseProcessors is the list of processors to use for responses.
	ResponseProcessors []ResponseProcessor
}

// FlowOptions contains options for flow creation.
type FlowOptions struct {
	// Logger is the logger to use for the flow.
	Logger *slog.Logger

	// ProcessorConfig provides the configuration for processors in this flow.
	ProcessorConfig ProcessorConfig
}

// WithLogger sets the logger for the flow options.
func (o *FlowOptions) WithLogger(logger *slog.Logger) *FlowOptions {
	o.Logger = logger
	o.ProcessorConfig.Logger = logger
	return o
}

// WithRequestProcessor adds a request processor to the flow options.
func (o *FlowOptions) WithRequestProcessor(processor RequestProcessor) *FlowOptions {
	o.ProcessorConfig.RequestProcessors = append(o.ProcessorConfig.RequestProcessors, processor)
	return o
}

// WithResponseProcessor adds a response processor to the flow options.
func (o *FlowOptions) WithResponseProcessor(processor ResponseProcessor) *FlowOptions {
	o.ProcessorConfig.ResponseProcessors = append(o.ProcessorConfig.ResponseProcessors, processor)
	return o
}

// DefaultFlowOptions creates a new set of default flow options.
func DefaultFlowOptions() *FlowOptions {
	logger := slog.Default()
	return &FlowOptions{
		Logger: logger,
		ProcessorConfig: ProcessorConfig{
			Logger:             logger,
			RequestProcessors:  []RequestProcessor{},
			ResponseProcessors: []ResponseProcessor{},
		},
	}
}

// RunFlowWithOptions runs a flow with the given invocation context and options.
// This is a convenience function for simple flow execution.
func RunFlowWithOptions(ctx context.Context, ic *InvocationContext, client any, options *FlowOptions) (<-chan *event.Event, error) {
	// Create a flow based on the options
	if options == nil {
		options = DefaultFlowOptions()
	}

	// Create a flow registry to find the appropriate flow
	registry := NewFlowRegistry()

	// Register default flow types
	registry.RegisterDefaultFlows()

	// Find a suitable flow for the client type
	flow, err := registry.CreateFlowForClient(client, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create flow for client: %w", err)
	}

	// Run the flow
	return flow.Run(ctx, ic)
}

// FlowRegistry manages flow creation and registration.
type FlowRegistry struct {
	factories map[string]FlowFactory
}

// FlowFactory creates a flow for a given client and options.
type FlowFactory func(client any, options *FlowOptions) (Flow, error)

// NewFlowRegistry creates a new flow registry.
func NewFlowRegistry() *FlowRegistry {
	return &FlowRegistry{
		factories: make(map[string]FlowFactory),
	}
}

// RegisterFlow registers a flow factory for a given client type.
func (r *FlowRegistry) RegisterFlow(clientType string, factory FlowFactory) {
	r.factories[clientType] = factory
}

// RegisterDefaultFlows registers the default flow types.
func (r *FlowRegistry) RegisterDefaultFlows() {
	// Register default flows here
	// These would be concrete implementations in a real codebase
}

// CreateFlowForClient creates a flow for the given client and options.
func (r *FlowRegistry) CreateFlowForClient(client any, options *FlowOptions) (Flow, error) {
	// Get the client type
	clientType := fmt.Sprintf("%T", client)

	// Look up the factory
	factory, ok := r.factories[clientType]
	if !ok {
		return nil, fmt.Errorf("no flow factory registered for client type: %s", clientType)
	}

	// Create the flow
	return factory(client, options)
}
