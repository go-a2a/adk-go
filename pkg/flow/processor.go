// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"github.com/go-a2a/adk-go/pkg/event"
)

// Processor represents a general processor for handling events in a flow.
type Processor interface {
	// Run processes events and returns a channel of processed events.
	Run(ctx *InvocationContext, input <-chan event.Event) (<-chan event.Event, error)
}

// ProcessorFunc is a function that can be used as a Processor.
type ProcessorFunc func(ctx *InvocationContext, input <-chan event.Event) (<-chan event.Event, error)

// Run implements the Processor interface.
func (f ProcessorFunc) Run(ctx *InvocationContext, input <-chan event.Event) (<-chan event.Event, error) {
	return f(ctx, input)
}
