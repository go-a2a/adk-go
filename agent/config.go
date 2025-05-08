// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"

	"github.com/go-a2a/adk-go/types"
)

// Config represents the configuration for an [types.Agent].
type Config struct {
	// The agent's name.
	//
	// Agent name must be a Go identifier and unique within the agent tree.
	// Agent name cannot be "user", since it's reserved for end-user's input.
	name string

	// Description about the agent's capability.
	//
	// The model uses this to determine whether to delegate control to the agent.
	// One-line description is enough and preferred.
	description string

	// The parent agent of this agent.
	//
	// Note that an agent can ONLY be added as sub-agent once.
	//
	// If you want to add one agent twice as sub-agent, consider to create two agent
	// instances with identical config, but with different name and add them to the
	// agent tree.
	parentAgent types.Agent

	// The sub-agents of this agent.
	subAgents []types.Agent

	// Callback signature that is invoked before the agent run.
	beforeAgentCallback types.BeforeAgentCallback

	// Callback signature that is invoked after the agent run.
	afterAgentCallback types.AfterAgentCallback

	logger *slog.Logger
}

// Option configures a [Config].
type Option interface {
	apply(*Config)
}

type optionFunc func(*Config)

func (o optionFunc) apply(c *Config) { o(c) }

// WithParentAgent sets the parentAgent for the [Config].
func WithParentAgent(parentAgent types.Agent) Option {
	return optionFunc(func(c *Config) {
		c.parentAgent = parentAgent
	})
}

// WithSubAgents adds sub-agents for the [Config].
func WithSubAgents(agents ...types.Agent) Option {
	return optionFunc(func(c *Config) {
		c.subAgents = append(c.subAgents, agents...)
	})
}

// WithLogger sets the logger for the [Config].
func WithLogger(logger *slog.Logger) Option {
	return optionFunc(func(c *Config) {
		c.logger = logger
	})
}

// NewConfig creates a new agent configuration with the given name.
func NewConfig(name string, opts ...Option) *Config {
	c := &Config{
		name:   name,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt.apply(c)
	}

	return c
}
