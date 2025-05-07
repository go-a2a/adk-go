// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

// Common callback event types
const (
	// Before agent execution.
	CallbackBeforeExecution = "before_execution"

	// After agent execution.
	CallbackAfterExecution = "after_execution"

	// Before tool execution.
	CallbackBeforeToolExecution = "before_tool_execution"

	// After tool execution.
	CallbackAfterToolExecution = "after_tool_execution"

	// On error.
	CallbackOnError = "on_error"
)

// CallbackFunc is the function type for callbacks.
type CallbackFunc func(*CallbackContext) error

// CallbackContext provides context for callbacks.
type CallbackContext struct {
	// Agent is the agent executing the callback.
	Agent Agent

	// Input is the input provided to the agent.
	Input map[string]any

	// Response is the current response.
	Response *LLMResponse

	// ToolCall is the tool call being executed, if any.
	ToolCall *ToolCall

	// Metadata contains additional information.
	Metadata map[string]any
}

type CallbackContextOption func(*CallbackContext)

// WithResponse adds a response to the callback context.
func WithResponse(response *LLMResponse) CallbackContextOption {
	return func(cc *CallbackContext) {
		cc.Response = response
	}
}

// WithToolCall adds a tool call to the callback context.
func WithToolCall(toolCall *ToolCall) CallbackContextOption {
	return func(cc *CallbackContext) {
		cc.ToolCall = toolCall
	}
}

// NewCallbackContext creates a new [*CallbackContext] with the given args.
func NewCallbackContext(agent Agent, input map[string]any, opts ...CallbackContextOption) *CallbackContext {
	cc := &CallbackContext{
		Agent:    agent,
		Input:    input,
		Metadata: make(map[string]any),
	}
	for _, opt := range opts {
		opt(cc)
	}

	return cc
}

// GetMetadata gets a metadata value.
func (c *CallbackContext) GetMetadata(key string) any {
	return c.Metadata[key]
}

// SetMetadata sets a metadata value.
func (c *CallbackContext) SetMetadata(key string, value any) {
	c.Metadata[key] = value
}
