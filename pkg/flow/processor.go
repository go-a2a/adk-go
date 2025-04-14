// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/observability"
)

// RequestProcessor processes a request message before it is sent to the model.
type RequestProcessor interface {
	// Name returns the name of the processor.
	Name() string

	// ProcessRequest processes a request message.
	ProcessRequest(ctx context.Context, ic *InvocationContext, req message.Message) (message.Message, error)
}

// ResponseProcessor processes a response message after it is received from the model.
type ResponseProcessor interface {
	// Name returns the name of the processor.
	Name() string

	// ProcessResponse processes a response message.
	ProcessResponse(ctx context.Context, ic *InvocationContext, resp message.Message) (message.Message, error)
}

// BaseProcessor provides a base implementation for processors.
type BaseProcessor struct {
	name string
}

// NewBaseProcessor creates a new base processor.
func NewBaseProcessor(name string) *BaseProcessor {
	return &BaseProcessor{
		name: name,
	}
}

// Name returns the name of the processor.
func (p *BaseProcessor) Name() string {
	return p.name
}

// ProcessorChain runs a series of processors on a message.
type ProcessorChain struct {
	logger *slog.Logger
}

// NewProcessorChain creates a new processor chain.
func NewProcessorChain(logger *slog.Logger) *ProcessorChain {
	if logger == nil {
		logger = slog.Default()
	}

	return &ProcessorChain{
		logger: logger,
	}
}

// RunRequestProcessors runs a message through a chain of request processors.
func (pc *ProcessorChain) RunRequestProcessors(ctx context.Context, ic *InvocationContext, req message.Message, processors []RequestProcessor) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "flow.RunRequestProcessors")
	defer span.End()

	span.SetAttributes(attribute.Int("processor.count", len(processors)))

	// If no processors, return the original message
	if len(processors) == 0 {
		return req, nil
	}

	// Process the message through each processor in sequence
	currentMsg := req
	var err error

	for i, processor := range processors {
		span.SetAttributes(attribute.Int("processor.current", i))

		observability.Logger(ctx).InfoContext(ctx, "Running request processor",
			slog.String("processor", processor.Name()),
			slog.Int("index", i))

		// Process with the current processor
		currentMsg, err = processor.ProcessRequest(ctx, ic, currentMsg)
		if err != nil {
			observability.Error(ctx, err, "Request processor failed",
				slog.String("processor", processor.Name()),
				slog.Int("index", i))
			return currentMsg, err
		}
	}

	return currentMsg, nil
}

// RunResponseProcessors runs a message through a chain of response processors.
func (pc *ProcessorChain) RunResponseProcessors(ctx context.Context, ic *InvocationContext, resp message.Message, processors []ResponseProcessor) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "flow.RunResponseProcessors")
	defer span.End()

	span.SetAttributes(attribute.Int("processor.count", len(processors)))

	// If no processors, return the original message
	if len(processors) == 0 {
		return resp, nil
	}

	// Process the message through each processor in sequence
	currentMsg := resp
	var err error

	for i, processor := range processors {
		span.SetAttributes(attribute.Int("processor.current", i))

		observability.Logger(ctx).InfoContext(ctx, "Running response processor",
			slog.String("processor", processor.Name()),
			slog.Int("index", i))

		// Process with the current processor
		currentMsg, err = processor.ProcessResponse(ctx, ic, currentMsg)
		if err != nil {
			observability.Error(ctx, err, "Response processor failed",
				slog.String("processor", processor.Name()),
				slog.Int("index", i))
			return currentMsg, err
		}
	}

	return currentMsg, nil
}
