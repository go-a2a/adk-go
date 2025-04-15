// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/artifacts"
	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/memory"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/session"
)

// Flow represents a basic flow that can be executed in a session.
type Flow interface {
	// Run executes the flow and returns a channel of events.
	Run(ctx context.Context, sess *session.Session) (<-chan event.Event, error)

	// RunLive executes the flow in streaming mode and returns a channel of events.
	RunLive(ctx context.Context, sess *session.Session) (<-chan event.Event, error)
}

// InvocationContext contains necessary context for processing events and invoking tools.
type InvocationContext struct {
	Context         context.Context
	ArtifactService artifacts.ArtifactService
	SessionService  session.SessionService
	MemoryService   memory.MemoryService
	ID              string
	Branch          string
	Agent           *agent.BaseAgent
	UserContent     *genai.Content
	Session         *session.Session
	EndInvocation   bool
}

// NewInvocationContext creates a new InvocationContext with the provided context and session.
func NewInvocationContext(ctx context.Context, sess *session.Session) *InvocationContext {
	return &InvocationContext{
		Context: ctx,
		Session: sess,
	}
}

// LlmFlowContext extends the InvocationContext with LLM flow-specific functionality.
type LlmFlowContext struct {
	*InvocationContext

	Models   *genai.Models
	Provider model.ModelProvider
}

// NewLlmFlowContext creates a new LlmFlowContext.
func NewLlmFlowContext(ctx context.Context, sess *session.Session, models *genai.Models) *LlmFlowContext {
	return &LlmFlowContext{
		InvocationContext: NewInvocationContext(ctx, sess),
		Models:            models,
	}
}
