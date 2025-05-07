// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"

	"google.golang.org/genai"
)

// ExecuteFunc is the function type that executes a tool.
type ExecuteFunc func(ctx context.Context, params map[string]any) (any, error)

// Config is the configuration for a [Tool].
type Config struct {
	name          string
	description   string
	isLongNunning bool
	innputSchema  *genai.Schema
	executor      ExecuteFunc
}

// ToolOption configures a [Config].
type ToolOption func(*Config)

// WithIsLongNunning sets the isLongNunning of the [Config].
func WithIsLongNunning(isLongNunning bool) ToolOption {
	return func(t *Config) {
		t.isLongNunning = isLongNunning
	}
}

// WithInputSchema sets the input schema of the [Config].
func WithInputSchema(schema *genai.Schema) ToolOption {
	return func(t *Config) {
		t.innputSchema = schema
	}
}

// WithToolExecuteFunc sets the execute function of the [Config].
func WithToolExecuteFunc(executeFunc ExecuteFunc) ToolOption {
	return func(t *Config) {
		t.executor = executeFunc
	}
}

// NewConfig creates a new [Config] with the given name and description.
func NewConfig(name, description string, opts ...ToolOption) *Config {
	c := &Config{
		name:        name,
		description: description,
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}
