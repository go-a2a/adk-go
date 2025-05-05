// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"time"

	"google.golang.org/genai"
)

// CallbackContext provides context for agent callbacks.
type CallbackContext struct {
	// Content is the content being processed.
	content *genai.Content

	// History is the conversation history.
	history []*genai.Content

	// Request is the user's request being processed.
	request *genai.Content

	// StartTime is the time when processing started.
	startTime time.Time

	// EndTime is the time when processing ended.
	endTime time.Time

	// Metadata is additional metadata for the callback.
	metadata map[string]any
}

// NewCallbackContext creates a new callback context.
func NewCallbackContext() *CallbackContext {
	return &CallbackContext{
		startTime: time.Now(),
		metadata:  make(map[string]any),
	}
}

// CallbackContextOption is a function that modifies a CallbackContext.
type CallbackContextOption func(*CallbackContext)

// WithContent sets the content for the callback context.
func WithContent(content *genai.Content) CallbackContextOption {
	return func(ctx *CallbackContext) {
		ctx.content = content
	}
}

// WithHistory sets the history for the callback context.
func WithHistory(history []*genai.Content) CallbackContextOption {
	return func(ctx *CallbackContext) {
		ctx.history = history
	}
}

// WithRequest sets the request for the callback context.
func WithRequest(request *genai.Content) CallbackContextOption {
	return func(ctx *CallbackContext) {
		ctx.request = request
	}
}

// WithMetadata sets a metadata value for the callback context.
func WithMetadata(key string, value any) CallbackContextOption {
	return func(ctx *CallbackContext) {
		ctx.metadata[key] = value
	}
}

// NewCallbackContextWithOptions creates a new callback context with the given options.
func NewCallbackContextWithOptions(options ...CallbackContextOption) *CallbackContext {
	ctx := NewCallbackContext()

	for _, option := range options {
		option(ctx)
	}

	return ctx
}

// SetContent sets the content for the callback context.
func (c *CallbackContext) SetContent(content *genai.Content) {
	c.content = content
}

// GetContent returns the content for the callback context.
func (c *CallbackContext) GetContent() *genai.Content {
	return c.content
}

// SetHistory sets the history for the callback context.
func (c *CallbackContext) SetHistory(history []*genai.Content) {
	c.history = history
}

// GetHistory returns the history for the callback context.
func (c *CallbackContext) GetHistory() []*genai.Content {
	return c.history
}

// SetRequest sets the request for the callback context.
func (c *CallbackContext) SetRequest(request *genai.Content) {
	c.request = request
}

// GetRequest returns the request for the callback context.
func (c *CallbackContext) GetRequest() *genai.Content {
	return c.request
}

// SetMetadata sets a metadata value for the callback context.
func (c *CallbackContext) SetMetadata(key string, value any) {
	c.metadata[key] = value
}

// GetMetadata returns a metadata value for the callback context.
func (c *CallbackContext) GetMetadata(key string) (any, bool) {
	value, ok := c.metadata[key]
	return value, ok
}

// MarkEnd marks the end of processing.
func (c *CallbackContext) MarkEnd() {
	c.endTime = time.Now()
}

// Duration returns the duration of processing.
func (c *CallbackContext) Duration() time.Duration {
	end := c.endTime
	if end.IsZero() {
		end = time.Now()
	}

	return end.Sub(c.startTime)
}
