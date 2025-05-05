// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrToolExecutionFailed is returned when a tool execution fails.
	ErrToolExecutionFailed = errors.New("tool execution failed")

	// ErrInvalidParameters is returned when invalid parameters are provided to a tool.
	ErrInvalidParameters = errors.New("invalid parameters")
)

// Parameter represents a parameter for a tool.
type Parameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Default     any      `json:"default,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

// ToolInterface defines the interface that all tools must implement.
type ToolInterface interface {
	// Execute executes the tool with the given parameters.
	Execute(ctx context.Context, params map[string]any) (any, error)

	// Name returns the name of the tool.
	Name() string

	// Description returns the description of the tool.
	Description() string

	// Parameters returns the parameters that the tool accepts.
	Parameters() []Parameter

	// JSONSchema returns a JSON schema representation of the tool.
	JSONSchema() (string, error)
}

// Tool is an alias for ToolInterface to maintain backward compatibility.
type Tool = ToolInterface

// BaseTool is a basic implementation of the Tool interface.
type BaseTool struct {
	name        string
	description string
	parameters  []Parameter
	executeFunc func(ctx context.Context, params map[string]any) (any, error)
}

// Execute executes the tool with the given parameters.
func (t *BaseTool) Execute(ctx context.Context, params map[string]any) (any, error) {
	if t.executeFunc == nil {
		return nil, fmt.Errorf("%w: execute function not set", ErrToolExecutionFailed)
	}

	// Validate parameters
	if err := t.validateParameters(params); err != nil {
		return nil, err
	}

	return t.executeFunc(ctx, params)
}

// validateParameters validates the parameters against the tool's parameter specification.
func (t *BaseTool) validateParameters(params map[string]any) error {
	// Check required parameters
	for _, param := range t.parameters {
		if param.Required {
			if _, ok := params[param.Name]; !ok {
				return fmt.Errorf("%w: required parameter %s is missing", ErrInvalidParameters, param.Name)
			}
		}
	}

	// TODO: Add type validation

	return nil
}

// Name returns the name of the tool.
func (t *BaseTool) Name() string {
	return t.name
}

// Description returns the description of the tool.
func (t *BaseTool) Description() string {
	return t.description
}

// Parameters returns the parameters that the tool accepts.
func (t *BaseTool) Parameters() []Parameter {
	return t.parameters
}

// JSONSchema returns a JSON schema representation of the tool.
func (t *BaseTool) JSONSchema() (string, error) {
	properties := make(map[string]any)
	required := []string{}

	for _, param := range t.parameters {
		propDef := map[string]any{
			"type":        param.Type,
			"description": param.Description,
		}

		if param.Default != nil {
			propDef["default"] = param.Default
		}

		if len(param.Enum) > 0 {
			propDef["enum"] = param.Enum
		}

		properties[param.Name] = propDef

		if param.Required {
			required = append(required, param.Name)
		}
	}

	schema := map[string]any{
		"type": "function",
		"function": map[string]any{
			"name":        t.name,
			"description": t.description,
			"parameters": map[string]any{
				"type":       "object",
				"properties": properties,
				"required":   required,
			},
		},
	}

	jsonSchema, err := json.Marshal(schema)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON schema: %w", err)
	}

	return string(jsonSchema), nil
}

// ToolOption is a function that modifies the BaseTool.
type ToolOption func(*BaseTool)

// WithToolName sets the name of the tool.
func WithToolName(name string) ToolOption {
	return func(t *BaseTool) {
		t.name = name
	}
}

// WithToolDescription sets the description of the tool.
func WithToolDescription(description string) ToolOption {
	return func(t *BaseTool) {
		t.description = description
	}
}

// WithToolParameters sets the parameters of the tool.
func WithToolParameters(parameters []Parameter) ToolOption {
	return func(t *BaseTool) {
		t.parameters = parameters
	}
}

// WithToolExecuteFunc sets the execute function of the tool.
func WithToolExecuteFunc(executeFunc func(ctx context.Context, params map[string]any) (any, error)) ToolOption {
	return func(t *BaseTool) {
		t.executeFunc = executeFunc
	}
}

// NewTool creates a new BaseTool with the given options.
func NewTool(options ...ToolOption) *BaseTool {
	tool := &BaseTool{
		name:        "",
		description: "",
		parameters:  []Parameter{},
		executeFunc: nil,
	}

	for _, option := range options {
		option(tool)
	}

	return tool
}
