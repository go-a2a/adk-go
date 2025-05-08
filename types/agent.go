// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"iter"

	"google.golang.org/genai"
)

// Agent represents an all agents in Agent Development Kit.
type Agent interface {
	// Name returns the agent's name.
	//
	// Agent name must be a Python identifier and unique within the agent tree.
	// Agent name cannot be "user", since it's reserved for end-user's input.
	Name() string

	// Description returns the description about the agent's capability.
	//
	// The model uses this to determine whether to delegate control to the agent.
	// One-line description is enough and preferred.
	Description() string

	// ParentAgent is the parent agent of this agent.
	//
	// Note that an agent can ONLY be added as sub-agent once.
	//
	// If you want to add one agent twice as sub-agent, consider to create two agent
	// instances with identical config, but with different name and add them to the
	// agent tree.
	ParentAgent() Agent

	// SubAgents returns the sub-agents of this agent.
	SubAgents() []Agent

	// FindAgent finds the agent with the given name in this agent and its descendants.
	FindAgent(name string) Agent

	// Run entry method to run an agent via text-based conversation.
	Run(ctx context.Context, parentContext *InvocationContext) iter.Seq2[*Event, error]

	// RunLive entry method to run an agent via video/audio-based conversation.
	RunLive(ctx context.Context, parentContext *InvocationContext) iter.Seq2[*Event, error]

	// Execute runs the agent with the given input and context.
	Execute(ctx context.Context, input map[string]any, opts ...RunOption) (*LLMResponse, error)
}

// AgentCallback is a function that is called the agent executes.
type AgentCallback func(*CallbackContext) (*genai.Content, error)
