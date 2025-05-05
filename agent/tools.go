// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Tool is the interface that all tools must implement.
type Tool interface {
	// Name returns the tool's name.
	Name() string

	// Description returns the tool description.
	Description() string

	// Execute runs the tool with the given input.
	Execute(ctx context.Context, input any) (any, error)

	// Schema returns the JSON schema for the tool's input.
	Schema() map[string]any
}

// ToolExecutor is the function type that executes a tool.
type ToolExecutor func(ctx context.Context, input any) (any, error)

// BaseTool represents a tool that an agent can use.
type BaseTool struct {
	name        string
	description string
	schema      map[string]any
	executor    ToolExecutor
}

// ToolOption configures a BaseTool.
type ToolOption func(*BaseTool)

// WithName sets the tool's name.
func WithName(name string) ToolOption {
	return func(t *BaseTool) {
		t.name = name
	}
}

// WithDescription sets the tool's description.
func WithDescription(description string) ToolOption {
	return func(t *BaseTool) {
		t.description = description
	}
}

// WithSchema sets the tool's input schema.
func WithSchema(schema map[string]any) ToolOption {
	return func(t *BaseTool) {
		t.schema = schema
	}
}

// WithExecutor sets the tool's execution function.
func WithExecutor(executor ToolExecutor) ToolOption {
	return func(t *BaseTool) {
		t.executor = executor
	}
}

// NewTool creates a new tool with the given options.
func NewTool(opts ...ToolOption) *BaseTool {
	tool := &BaseTool{
		schema: make(map[string]any),
	}

	for _, opt := range opts {
		opt(tool)
	}

	return tool
}

// Name returns the tool's name.
func (t *BaseTool) Name() string {
	return t.name
}

// Description returns the tool's description.
func (t *BaseTool) Description() string {
	return t.description
}

// Schema returns the tool's input schema.
func (t *BaseTool) Schema() map[string]any {
	return t.schema
}

// Execute runs the tool with the given input.
func (t *BaseTool) Execute(ctx context.Context, input any) (any, error) {
	if t.executor == nil {
		return nil, errors.New("tool executor not set")
	}
	return t.executor(ctx, input)
}

// FormatToolsAsJSON formats tools as a JSON array for LLM consumption.
func FormatToolsAsJSON(tools []Tool) (string, error) {
	type toolJSON struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Schema      map[string]any `json:"schema"`
	}

	toolDefs := make([]toolJSON, len(tools))
	for i, tool := range tools {
		toolDefs[i] = toolJSON{
			Name:        tool.Name(),
			Description: tool.Description(),
			Schema:      tool.Schema(),
		}
	}

	bytes, err := json.MarshalIndent(toolDefs, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal tools to JSON: %w", err)
	}

	return string(bytes), nil
}
