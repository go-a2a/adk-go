// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/flow"
	"github.com/go-a2a/adk-go/session"
)

// AutoFlow is an advanced LLM flow that automatically selects the appropriate flow.
// It can dynamically choose between SingleFlow or other specialized flows based on context.
type AutoFlow struct {
	model  string
	config *genai.GenerateContentConfig
	tools  []*genai.Tool
}

var _ flow.Flow = (*AutoFlow)(nil)

// NewAutoFlow creates a new AutoFlow instance.
func NewAutoFlow(model string, config *genai.GenerateContentConfig) *AutoFlow {
	return &AutoFlow{
		model:  model,
		config: config,
	}
}

// SetTools sets the tools available to the language model.
func (f *AutoFlow) SetTools(tools ...*genai.Tool) {
	f.tools = tools
}

// Run executes the flow and returns a channel of events.
func (f *AutoFlow) Run(ctx context.Context, sess *session.Session) (<-chan event.Event, error) {
	// Determine which flow to use based on session context
	flow, err := f.selectFlow(ctx, sess)
	if err != nil {
		return nil, fmt.Errorf("failed to select flow: %w", err)
	}

	// Set tools for the selected flow
	if toolsProvider, ok := flow.(interface{ SetTools(...*genai.Tool) }); ok {
		toolsProvider.SetTools(f.tools...)
	}

	// Execute the selected flow
	return flow.Run(ctx, sess)
}

// RunLive executes the flow in streaming mode and returns a channel of events.
func (f *AutoFlow) RunLive(ctx context.Context, sess *session.Session) (<-chan event.Event, error) {
	// Determine which flow to use based on session context
	flow, err := f.selectFlow(ctx, sess)
	if err != nil {
		return nil, fmt.Errorf("failed to select flow: %w", err)
	}

	// Set tools for the selected flow
	if toolsProvider, ok := flow.(interface{ SetTools(...*genai.Tool) }); ok {
		toolsProvider.SetTools(f.tools...)
	}

	// Execute the selected flow in live mode
	return flow.RunLive(ctx, sess)
}

// selectFlow determines which flow to use based on the session context.
func (f *AutoFlow) selectFlow(ctx context.Context, sess *session.Session) (flow.Flow, error) {
	// For now, default to SingleFlow
	// In a more advanced implementation, this would analyze the session
	// and determine which flow is most appropriate
	slog.InfoContext(ctx, "Auto-selecting flow", "selected", "SingleFlow")
	return NewSingleFlow(f.model, f.config), nil
}
