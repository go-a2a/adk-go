// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
)

// BaseAgent provides common functionality for all agents.
type BaseAgent struct {
	name      string
	tools     []Tool
	logger    *slog.Logger
	callbacks map[string][]CallbackFunc
}

// BaseAgentOption configures a BaseAgent.
type BaseAgentOption func(*BaseAgent)

// WithLogger sets the logger for the agent.
func WithLogger(logger *slog.Logger) BaseAgentOption {
	return func(a *BaseAgent) {
		a.logger = logger
	}
}

// WithTools sets the initial tools for the agent.
func WithTools(tools ...Tool) BaseAgentOption {
	return func(a *BaseAgent) {
		a.tools = append(a.tools, tools...)
	}
}

// NewBaseAgent creates a new BaseAgent with the given name and options.
func NewBaseAgent(name string, opts ...BaseAgentOption) *BaseAgent {
	agent := &BaseAgent{
		name:      name,
		tools:     make([]Tool, 0),
		callbacks: make(map[string][]CallbackFunc),
		logger:    slog.Default(),
	}

	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

// Name returns the agent's name.
func (a *BaseAgent) Name() string {
	return a.name
}

// AddTool adds a tool to the agent.
func (a *BaseAgent) AddTool(tool Tool) error {
	a.tools = append(a.tools, tool)
	return nil
}

// Tools returns the agent's tools.
func (a *BaseAgent) Tools() []Tool {
	return a.tools
}

// IsStreaming returns whether the agent is streaming.
func (a *BaseAgent) IsStreaming() bool {
	return false
}

// RegisterCallback registers a callback for an event.
func (a *BaseAgent) RegisterCallback(event string, callback CallbackFunc) {
	if a.callbacks == nil {
		a.callbacks = make(map[string][]CallbackFunc)
	}
	a.callbacks[event] = append(a.callbacks[event], callback)
}

// TriggerCallbacks triggers all callbacks for an event.
func (a *BaseAgent) TriggerCallbacks(ctx context.Context, event string, callbackCtx *CallbackContext) error {
	if a.callbacks == nil {
		return nil
	}

	callbacks, ok := a.callbacks[event]
	if !ok {
		return nil
	}

	for _, callback := range callbacks {
		if err := callback(callbackCtx); err != nil {
			a.logger.ErrorContext(ctx, "callback error",
				"event", event,
				"error", err)
			return err
		}
	}

	return nil
}

// Execute is a placeholder that should be overridden by implementing agents.
func (a *BaseAgent) Execute(ctx context.Context, input any, opts ...RunOption) (Response, error) {
	return Response{}, ErrUnsupportedOperation
}

// FindTool finds a tool by name.
func (a *BaseAgent) FindTool(name string) Tool {
	for _, tool := range a.tools {
		if tool.Name() == name {
			return tool
		}
	}
	return nil
}
