// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

// Package flow provides structures and functionality for defining and executing
// LLM-powered agent flows and interactions.
package flow

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/message"
)

// Flow defines the interface for message flow processing.
type Flow interface {
	// Run executes the flow with the given invocation context.
	Run(ctx context.Context, ic *InvocationContext) (<-chan *event.Event, error)
}

// InvocationContext contains contextual information for a flow invocation.
type InvocationContext struct {
	// UserID identifies the user for this flow invocation.
	UserID string

	// SessionID identifies the session for this flow invocation.
	SessionID string

	// Messages contains the messages for this invocation.
	Messages []message.Message

	// Artifacts contains any artifacts associated with this invocation.
	Artifacts map[string][]byte

	// State contains arbitrary state for this invocation.
	State map[string]any
}

// NewInvocationContext creates a new InvocationContext.
func NewInvocationContext(userID, sessionID string) *InvocationContext {
	return &InvocationContext{
		UserID:    userID,
		SessionID: sessionID,
		Messages:  []message.Message{},
		Artifacts: make(map[string][]byte),
		State:     make(map[string]any),
	}
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
func RunFlowWithOptions(
	ctx context.Context,
	ic *InvocationContext,
	client interface{},
	options *FlowOptions,
) (<-chan *event.Event, error) {
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
type FlowFactory func(client interface{}, options *FlowOptions) (Flow, error)

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
func (r *FlowRegistry) CreateFlowForClient(client interface{}, options *FlowOptions) (Flow, error) {
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
