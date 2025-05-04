// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/event"
)

// BeforeAgentCallback callback signature that is invoked before the agent run.
//
// Returns the content to return to the user. When set, the agent run will skipped and the provided content will be returned to user.
type BeforeAgentCallback func(cctx *CallbackContext) *genai.Content

// AfterAgentCallback callback signature that is invoked after the agent run.
//
// Returns the content to return to the user. When set, the agent run will skipped and the provided content will be appended to event history as agent response.
type AfterAgentCallback func(cctx *CallbackContext) *genai.Content

// Base for all agents in Agent Development Kit.
type Config struct {
	name        string
	description string
	parentAgent Agent
	subAgents   []Agent
}

// Agent represents an interface for an all agents in Agent Development Kit.
type Agent interface {
	// Name returns the agent's name.
	Name() string

	// Process processes and returns any response events via text-based conversation.
	Process(ctx context.Context, ictx *InvocationContext) (*event.Event, error)

	// ProcessLive processes and returns any response events via video/audio-based conversation.
	ProcessLive(ctx context.Context, ictx *InvocationContext) (*event.Event, error)
}
