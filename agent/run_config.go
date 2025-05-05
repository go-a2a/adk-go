// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"
	"time"
)

// RunConfig represents the configuration for running an agent.
type RunConfig struct {
	// timeout is the maximum time to wait for the agent to respond.
	timeout time.Duration

	// maxRetries is the maximum number of retries to attempt.
	maxRetries int

	// retryDelay is the delay between retries.
	retryDelay time.Duration

	// logger is the logger to use for logging.
	logger *slog.Logger

	// metadata is additional metadata for the run.
	metadata map[string]any
}

// NewRunConfig creates a new run configuration with default values.
func NewRunConfig() *RunConfig {
	return &RunConfig{
		timeout:    30 * time.Second,
		maxRetries: 3,
		retryDelay: 1 * time.Second,
		logger:     slog.Default(),
		metadata:   make(map[string]any),
	}
}

// RunConfigOption is a function that modifies a RunConfig.
type RunConfigOption func(*RunConfig)

// WithTimeout sets the timeout for the run configuration.
func WithTimeout(timeout time.Duration) RunConfigOption {
	return func(config *RunConfig) {
		config.timeout = timeout
	}
}

// WithMaxRetries sets the maximum number of retries for the run configuration.
func WithMaxRetries(maxRetries int) RunConfigOption {
	return func(config *RunConfig) {
		config.maxRetries = maxRetries
	}
}

// WithRetryDelay sets the retry delay for the run configuration.
func WithRetryDelay(retryDelay time.Duration) RunConfigOption {
	return func(config *RunConfig) {
		config.retryDelay = retryDelay
	}
}

// WithConfigLogger sets the logger for the run configuration.
func WithConfigLogger(logger *slog.Logger) RunConfigOption {
	return func(config *RunConfig) {
		config.logger = logger
	}
}

// WithConfigMetadata sets a metadata value for the run configuration.
func WithConfigMetadata(key string, value any) RunConfigOption {
	return func(config *RunConfig) {
		config.metadata[key] = value
	}
}

// NewRunConfigWithOptions creates a new run configuration with the given options.
func NewRunConfigWithOptions(options ...RunConfigOption) *RunConfig {
	config := NewRunConfig()

	for _, option := range options {
		option(config)
	}

	return config
}

// GetTimeout returns the timeout for the run configuration.
func (c *RunConfig) GetTimeout() time.Duration {
	return c.timeout
}

// GetMaxRetries returns the maximum number of retries for the run configuration.
func (c *RunConfig) GetMaxRetries() int {
	return c.maxRetries
}

// GetRetryDelay returns the retry delay for the run configuration.
func (c *RunConfig) GetRetryDelay() time.Duration {
	return c.retryDelay
}

// GetLogger returns the logger for the run configuration.
func (c *RunConfig) GetLogger() *slog.Logger {
	return c.logger
}

// GetMetadata returns a metadata value for the run configuration.
func (c *RunConfig) GetMetadata(key string) (any, bool) {
	value, ok := c.metadata[key]
	return value, ok
}

// SetMetadata sets a metadata value for the run configuration.
func (c *RunConfig) SetMetadata(key string, value any) {
	c.metadata[key] = value
}
