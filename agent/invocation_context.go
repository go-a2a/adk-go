// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"google.golang.org/genai"
)

// BeforeAgentCallback is a callback that is called before an agent is invoked.
type BeforeAgentCallback func(ctx *CallbackContext) *genai.Content

// AfterAgentCallback is a callback that is called after an agent is invoked.
type AfterAgentCallback func(ctx *CallbackContext) *genai.Content

// InvocationContext provides context for agent invocations.
type InvocationContext struct {
	// History is the conversation history.
	history []*genai.Content

	// Request is the user's request.
	request *genai.Content

	// Metadata is additional metadata for the invocation.
	metadata map[string]any

	// BeforeCallbacks are callbacks that are called before the agent is invoked.
	beforeCallbacks []BeforeAgentCallback

	// AfterCallbacks are callbacks that are called after the agent is invoked.
	afterCallbacks []AfterAgentCallback
}

// NewInvocationContext creates a new invocation context.
func NewInvocationContext() *InvocationContext {
	return &InvocationContext{
		history:         []*genai.Content{},
		metadata:        make(map[string]any),
		beforeCallbacks: []BeforeAgentCallback{},
		afterCallbacks:  []AfterAgentCallback{},
	}
}

// InvocationContextOption is a function that modifies an InvocationContext.
type InvocationContextOption func(*InvocationContext)

// WithInvocationHistory sets the history for the invocation context.
func WithInvocationHistory(history []*genai.Content) InvocationContextOption {
	return func(ctx *InvocationContext) {
		ctx.history = history
	}
}

// WithInvocationRequest sets the request for the invocation context.
func WithInvocationRequest(request *genai.Content) InvocationContextOption {
	return func(ctx *InvocationContext) {
		ctx.request = request
	}
}

// WithInvocationMetadata sets a metadata value for the invocation context.
func WithInvocationMetadata(key string, value any) InvocationContextOption {
	return func(ctx *InvocationContext) {
		ctx.metadata[key] = value
	}
}

// WithBeforeCallback adds a before callback to the invocation context.
func WithBeforeCallback(callback BeforeAgentCallback) InvocationContextOption {
	return func(ctx *InvocationContext) {
		ctx.beforeCallbacks = append(ctx.beforeCallbacks, callback)
	}
}

// WithAfterCallback adds an after callback to the invocation context.
func WithAfterCallback(callback AfterAgentCallback) InvocationContextOption {
	return func(ctx *InvocationContext) {
		ctx.afterCallbacks = append(ctx.afterCallbacks, callback)
	}
}

// NewInvocationContextWithOptions creates a new invocation context with the given options.
func NewInvocationContextWithOptions(options ...InvocationContextOption) *InvocationContext {
	ctx := NewInvocationContext()

	for _, option := range options {
		option(ctx)
	}

	return ctx
}

// SetHistory sets the history for the invocation context.
func (c *InvocationContext) SetHistory(history []*genai.Content) {
	c.history = history
}

// GetHistory returns the history for the invocation context.
func (c *InvocationContext) GetHistory() []*genai.Content {
	return c.history
}

// AddToHistory adds a content to the history.
func (c *InvocationContext) AddToHistory(content *genai.Content) {
	c.history = append(c.history, content)
}

// SetRequest sets the request for the invocation context.
func (c *InvocationContext) SetRequest(request *genai.Content) {
	c.request = request
}

// GetRequest returns the request for the invocation context.
func (c *InvocationContext) GetRequest() *genai.Content {
	return c.request
}

// SetMetadata sets a metadata value for the invocation context.
func (c *InvocationContext) SetMetadata(key string, value any) {
	c.metadata[key] = value
}

// GetMetadata returns a metadata value for the invocation context.
func (c *InvocationContext) GetMetadata(key string) (any, bool) {
	value, ok := c.metadata[key]
	return value, ok
}

// AddBeforeCallback adds a before callback to the invocation context.
func (c *InvocationContext) AddBeforeCallback(callback BeforeAgentCallback) {
	c.beforeCallbacks = append(c.beforeCallbacks, callback)
}

// AddAfterCallback adds an after callback to the invocation context.
func (c *InvocationContext) AddAfterCallback(callback AfterAgentCallback) {
	c.afterCallbacks = append(c.afterCallbacks, callback)
}

// ExecuteBeforeCallbacks executes all before callbacks.
func (c *InvocationContext) ExecuteBeforeCallbacks(callbackCtx *CallbackContext) *genai.Content {
	var result *genai.Content

	for _, callback := range c.beforeCallbacks {
		resp := callback(callbackCtx)
		if resp != nil {
			result = resp
		}
	}

	return result
}

// ExecuteAfterCallbacks executes all after callbacks.
func (c *InvocationContext) ExecuteAfterCallbacks(callbackCtx *CallbackContext) *genai.Content {
	var result *genai.Content

	for _, callback := range c.afterCallbacks {
		resp := callback(callbackCtx)
		if resp != nil {
			result = resp
		}
	}

	return result
}
