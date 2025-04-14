// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

// Package flow provides structures and functionality for defining and executing
// LLM-powered agent flows and interactions.
package flow

import (
	"context"
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/event"
)

// FlowOptions contains options for flow creation.
type FlowOptions struct {
	// Logger is the logger to use for the flow.
	Logger *slog.Logger

	// RequestProcessors is the list of processors to use for requests.
	RequestProcessors []RequestProcessor

	// ResponseProcessors is the list of processors to use for responses.
	ResponseProcessors []ResponseProcessor
}

// WithLogger sets the logger for the flow options.
func (o *FlowOptions) WithLogger(logger *slog.Logger) *FlowOptions {
	o.Logger = logger
	return o
}

// WithRequestProcessor adds a request processor to the flow options.
func (o *FlowOptions) WithRequestProcessor(processor RequestProcessor) *FlowOptions {
	o.RequestProcessors = append(o.RequestProcessors, processor)
	return o
}

// WithResponseProcessor adds a response processor to the flow options.
func (o *FlowOptions) WithResponseProcessor(processor ResponseProcessor) *FlowOptions {
	o.ResponseProcessors = append(o.ResponseProcessors, processor)
	return o
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
	// In a real implementation, this would create a specific flow type
	// based on the options and client
	flow := createFlow(client, options)

	// Run the flow
	return flow.Run(ctx, ic)
}

// createFlow is a helper function to create a flow.
// This would be implemented with real flow creation logic in an actual implementation.
func createFlow(client interface{}, options *FlowOptions) Flow {
	// This is a placeholder - in a real implementation,
	// this would create and configure a specific flow type
	// based on the client and options

	// For now, we'll return a nil implementation as this is just a placeholder
	return nil
}