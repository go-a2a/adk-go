// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
	"github.com/go-a2a/adk-go/pkg/model/models"
	"github.com/go-a2a/adk-go/pkg/session"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// AutoFlow is an advanced LLM flow that automatically selects the appropriate flow.
// It can dynamically choose between SingleFlow or other specialized flows based on context.
type AutoFlow struct {
	modelID      string
	modelOptions models.Option
	tools        []tool.Tool
}

// NewAutoFlow creates a new AutoFlow instance.
func NewAutoFlow(modelID string, modelOptions models.Option) *AutoFlow {
	return &AutoFlow{
		modelID:      modelID,
		modelOptions: modelOptions,
	}
}

// SetTools sets the tools available to the language model.
func (f *AutoFlow) SetTools(tools []tool.Tool) {
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
	if toolsProvider, ok := flow.(interface{ SetTools([]tool.Tool) }); ok {
		toolsProvider.SetTools(f.tools)
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
	if toolsProvider, ok := flow.(interface{ SetTools([]tool.Tool) }); ok {
		toolsProvider.SetTools(f.tools)
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
	return NewSingleFlow(f.modelID, f.modelOptions), nil
}
