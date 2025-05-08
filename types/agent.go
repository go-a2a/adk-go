// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"

	"google.golang.org/genai"
)

// Agent is the interface that all agents must implement.
type Agent interface {
	// Name returns the agent's name.
	Name() string

	// ParentAgent is the parent agent of this agent.
	//
	// Note that an agent can ONLY be added as sub-agent once.
	//
	// If you want to add one agent twice as sub-agent, consider to create two agent
	// instances with identical config, but with different name and add them to the
	// agent tree.
	ParentAgent() Agent

	FindAgent(name string) Agent

	// Execute runs the agent with the given input and context.
	Execute(ctx context.Context, input map[string]any, opts ...RunOption) (*LLMResponse, error)
}

// BeforeAgentCallback is a function that is called before the agent executes.
type BeforeAgentCallback func(*CallbackContext) (*genai.Content, error)

// AfterAgentCallback is a function that is called after the agent executes.
type AfterAgentCallback func(*CallbackContext) (*genai.Content, error)
