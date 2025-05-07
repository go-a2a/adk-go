// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"

	"github.com/go-a2a/adk-go/types"
)

// BaseAgent provides common functionality for all agents.
type Config struct {
	name        string
	description string
	parentAgent types.Agent
	subAgents   []types.Agent
	tools       []types.Tool
	logger      *slog.Logger
	callbacks   map[string][]types.CallbackFunc
}

// NewConfig creates a new agent configuration with the given name.
func NewConfig(name string) *Config {
	return &Config{
		name: name,
	}
}

// Option configures a [Config].
type Option func(*Config)

// WithParentAgent sets the parentAgent for the [Config].
func WithParentAgent(parentAgent types.Agent) Option {
	return func(a *Config) {
		a.parentAgent = parentAgent
	}
}

// WithSubAgents adds sub-agents for the [Config].
func WithSubAgents(agents ...types.Agent) Option {
	return func(a *Config) {
		a.subAgents = append(a.subAgents, agents...)
	}
}

// WithTools sets the initial tools for the [Config].
func WithTools(tools ...types.Tool) Option {
	return func(a *Config) {
		a.tools = append(a.tools, tools...)
	}
}

// WithLogger sets the logger for the [Config].
func WithLogger(logger *slog.Logger) Option {
	return func(a *Config) {
		a.logger = logger
	}
}

// RegisterCallback registers a callback for an event.
func (a *Config) RegisterCallback(event string, callback types.CallbackFunc) {
	if a.callbacks == nil {
		a.callbacks = make(map[string][]types.CallbackFunc)
	}
	a.callbacks[event] = append(a.callbacks[event], callback)
}

// TriggerCallbacks triggers all callbacks for an event.
func (a *Config) TriggerCallbacks(ctx context.Context, event string, callbackCtx *types.CallbackContext) error {
	if a.callbacks == nil {
		return nil
	}

	callbacks, ok := a.callbacks[event]
	if !ok {
		return nil
	}

	for _, callback := range callbacks {
		if err := callback(callbackCtx); err != nil {
			a.logger.ErrorContext(ctx, "callback error", slog.Any("event", event), slog.Any("err", err))
			return err
		}
	}

	return nil
}
