// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/agent"
	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/session"
)

// Flow represents a basic flow that can be executed in a session.
type Flow interface {
	// Run executes the flow and returns a channel of events.
	Run(ctx context.Context, sess *session.Session) (<-chan event.Event, error)

	// RunLive executes the flow in streaming mode and returns a channel of events.
	RunLive(ctx context.Context, sess *session.Session) (<-chan event.Event, error)
}

// LlmFlowContext extends the InvocationContext with LLM flow-specific functionality.
type LlmFlowContext struct {
	*agent.InvocationContext

	Models   *genai.Models
	Provider model.ModelProvider
}

// NewLlmFlowContext creates a new LlmFlowContext.
func NewLlmFlowContext(ctx context.Context, appName string, sess *session.Session, models *genai.Models) *LlmFlowContext {
	return &LlmFlowContext{
		InvocationContext: agent.NewInvocationContext(ctx, appName, sess),
		Models:            models,
	}
}
