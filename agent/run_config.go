// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"time"
)

// RunConfig contains settings for agent execution.
type RunConfig struct {
	// Timeout is the maximum time the agent can run for.
	Timeout time.Duration

	// MaxTokens is the maximum number of tokens the agent can generate.
	MaxTokens int

	// Temperature controls randomness in generation (0.0 to 1.0).
	Temperature float64

	// MemoryEnabled controls whether the agent uses memory.
	MemoryEnabled bool

	// StreamingEnabled controls whether the agent streams responses.
	StreamingEnabled bool

	// Callbacks for various events.
	Callbacks map[string][]CallbackFunc

	// Custom metadata for the run.
	Metadata map[string]any
}

// DefaultRunConfig returns a RunConfig with default values.
func DefaultRunConfig() *RunConfig {
	return &RunConfig{
		Timeout:          30 * time.Second,
		MaxTokens:        2048,
		Temperature:      0.7,
		MemoryEnabled:    true,
		StreamingEnabled: false,
		Callbacks:        make(map[string][]CallbackFunc),
		Metadata:         make(map[string]any),
	}
}

// RunOption configures a RunConfig.
type RunOption func(*RunConfig)

// WithTimeout sets the timeout for agent execution.
func WithTimeout(timeout time.Duration) RunOption {
	return func(c *RunConfig) {
		c.Timeout = timeout
	}
}

// WithMaxTokens sets the maximum number of tokens for generation.
func WithMaxTokens(maxTokens int) RunOption {
	return func(c *RunConfig) {
		c.MaxTokens = maxTokens
	}
}

// WithTemperature sets the temperature for generation.
func WithTemperature(temperature float64) RunOption {
	return func(c *RunConfig) {
		c.Temperature = temperature
	}
}

// WithMemoryEnabled enables or disables memory.
func WithMemoryEnabled(enabled bool) RunOption {
	return func(c *RunConfig) {
		c.MemoryEnabled = enabled
	}
}

// WithStreamingEnabled enables or disables streaming.
func WithStreamingEnabled(enabled bool) RunOption {
	return func(c *RunConfig) {
		c.StreamingEnabled = enabled
	}
}

// WithRunCallback adds a callback for an event.
func WithRunCallback(event string, callback CallbackFunc) RunOption {
	return func(c *RunConfig) {
		if c.Callbacks == nil {
			c.Callbacks = make(map[string][]CallbackFunc)
		}
		c.Callbacks[event] = append(c.Callbacks[event], callback)
	}
}

// WithMetadata adds metadata to the run configuration.
func WithMetadata(key string, value any) RunOption {
	return func(c *RunConfig) {
		if c.Metadata == nil {
			c.Metadata = make(map[string]any)
		}
		c.Metadata[key] = value
	}
}
