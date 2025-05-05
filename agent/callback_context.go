// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

// CallbackFunc is the function type for callbacks.
type CallbackFunc func(*CallbackContext) error

// CallbackContext provides context for callbacks.
type CallbackContext struct {
	// Agent is the agent executing the callback.
	Agent Agent

	// Input is the input provided to the agent.
	Input any

	// Response is the current response.
	Response *Response

	// ToolCall is the tool call being executed, if any.
	ToolCall *ToolCall

	// Metadata contains additional information.
	Metadata map[string]any
}

// NewCallbackContext creates a new callback context.
func NewCallbackContext(agent Agent, input any, response *Response) *CallbackContext {
	return &CallbackContext{
		Agent:    agent,
		Input:    input,
		Response: response,
		Metadata: make(map[string]any),
	}
}

// WithToolCall adds a tool call to the callback context.
func (c *CallbackContext) WithToolCall(toolCall *ToolCall) *CallbackContext {
	c.ToolCall = toolCall
	return c
}

// SetMetadata sets a metadata value.
func (c *CallbackContext) SetMetadata(key string, value any) {
	c.Metadata[key] = value
}

// GetMetadata gets a metadata value.
func (c *CallbackContext) GetMetadata(key string) any {
	return c.Metadata[key]
}

// Common callback event types
const (
	// Before agent execution
	CallbackBeforeExecution = "before_execution"

	// After agent execution
	CallbackAfterExecution = "after_execution"

	// Before tool execution
	CallbackBeforeToolExecution = "before_tool_execution"

	// After tool execution
	CallbackAfterToolExecution = "after_tool_execution"

	// On error
	CallbackOnError = "on_error"
)
