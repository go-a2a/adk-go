// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent provides functionality for creating and managing agents.
package agent

import (
	"context"
	"iter"

	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

// BaseAgent is the interface that all agents must implement.
type BaseAgent interface {
	// InvokeAsync invokes the agent and returns a stream of responses.
	InvokeAsync(ctx context.Context, invocationCtx InvocationContext) iter.Seq2[*genai.Content, error]

	// Invoke synchronously invokes the agent and returns the final response.
	Invoke(ctx context.Context, invocationCtx InvocationContext) (*genai.Content, error)

	// Name returns the name of the agent.
	Name() string

	// AddTool adds a tool to the agent.
	AddTool(tool Tool) error

	// Tools returns all tools registered with the agent.
	Tools() []Tool
}

// Agent is a base implementation of the BaseAgent interface.
type Agent struct {
	name  string
	tools []Tool
}

// AgentConfig is used to configure an Agent instance.
type AgentConfig struct {
	name  string
	tools []Tool
}

// AgentOption is a function that modifies the AgentConfig.
type AgentOption interface {
	apply(config *AgentConfig) *AgentConfig
}

type nameOption string

func (o nameOption) apply(config *AgentConfig) *AgentConfig {
	config.name = string(o)
	return config
}

// WithName sets the name for the agent.
func WithName(name string) AgentOption {
	return nameOption(name)
}

type toolsOption []Tool

func (o toolsOption) apply(config *AgentConfig) *AgentConfig {
	config.tools = o
	return config
}

// WithTools sets the tools for the agent.
func WithTools(tools []Tool) AgentOption {
	return toolsOption(tools)
}

// NewAgent creates a new Agent with the given options.
func NewAgent(options ...AgentOption) *Agent {
	config := &AgentConfig{
		name:  "agent",
		tools: []Tool{},
	}

	for _, option := range options {
		config = option.apply(config)
	}

	return &Agent{
		name:  config.name,
		tools: config.tools,
	}
}

// Invoke synchronously invokes the agent and returns the final response.
// Implementation depends on the specific agent type.
func (a *Agent) Invoke(ctx context.Context, invocationCtx InvocationContext) (*genai.Content, error) {
	var lastContent *genai.Content

	iterator := a.InvokeAsync(ctx, invocationCtx)
	for content, err := range iterator {
		if err != nil {
			return nil, err
		}
		lastContent = content
	}

	return lastContent, nil
}

// InvokeAsync invokes the agent and returns a stream of responses.
// This is a placeholder implementation that should be overridden by specific agent types.
func (a *Agent) InvokeAsync(ctx context.Context, invocationCtx InvocationContext) iter.Seq2[*genai.Content, error] {
	return func(yield func(*genai.Content, error) bool) {
		resp := &genai.Content{
			Parts: []*genai.Part{genai.NewPartFromText("Base agent implementation - override in concrete types")},
			Role:  model.RoleAssistant,
		}
		if !yield(resp, nil) {
			return
		}
	}
}

// Name returns the name of the agent.
func (a *Agent) Name() string {
	return a.name
}

// AddTool adds a tool to the agent.
func (a *Agent) AddTool(tool Tool) error {
	a.tools = append(a.tools, tool)
	return nil
}

// Tools returns all tools registered with the agent.
func (a *Agent) Tools() []Tool {
	return a.tools
}
