// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package tools provides the tool abstractions for ADK agents.
package tools

import (
	"context"
	"fmt"
	
	"github.com/bytedance/sonic"
	"github.com/go-a2a/adk-go/agent/events"
	"github.com/go-a2a/adk-go/internal/jsonschema"
	"google.golang.org/genai"
)

// Tool represents a capability that an agent can use.
type Tool interface {
	// Name returns the name of the tool.
	Name() string
	
	// Description returns a description of what the tool does.
	Description() string
	
	// InputSchema returns the JSON schema for the tool's input parameters.
	InputSchema() *jsonschema.Schema
	
	// OutputSchema returns the JSON schema for the tool's output.
	OutputSchema() *jsonschema.Schema
	
	// Execute executes the tool with the given parameters.
	Execute(ctx context.Context, params map[string]any) (any, error)
	
	// ToGenAITool converts the tool to a genai.Tool representation.
	ToGenAITool() *genai.Tool
}

// ToolOption is a function that configures a BaseTool.
type ToolOption func(*BaseTool)

// BaseTool provides a base implementation of the Tool interface.
type BaseTool struct {
	name         string
	description  string
	inputSchema  *jsonschema.Schema
	outputSchema *jsonschema.Schema
	executeFn    func(ctx context.Context, params map[string]any) (any, error)
}

// WithName sets the name of the tool.
func WithName(name string) ToolOption {
	return func(t *BaseTool) {
		t.name = name
	}
}

// WithDescription sets the description of the tool.
func WithDescription(description string) ToolOption {
	return func(t *BaseTool) {
		t.description = description
	}
}

// WithInputSchema sets the input schema of the tool.
func WithInputSchema(schema *jsonschema.Schema) ToolOption {
	return func(t *BaseTool) {
		t.inputSchema = schema
	}
}

// WithOutputSchema sets the output schema of the tool.
func WithOutputSchema(schema *jsonschema.Schema) ToolOption {
	return func(t *BaseTool) {
		t.outputSchema = schema
	}
}

// WithExecuteFunc sets the execute function of the tool.
func WithExecuteFunc(fn func(ctx context.Context, params map[string]any) (any, error)) ToolOption {
	return func(t *BaseTool) {
		t.executeFn = fn
	}
}

// NewBaseTool creates a new BaseTool with the given options.
func NewBaseTool(opts ...ToolOption) *BaseTool {
	tool := &BaseTool{}
	for _, opt := range opts {
		opt(tool)
	}
	return tool
}

// Name returns the name of the tool.
func (t *BaseTool) Name() string {
	return t.name
}

// Description returns a description of what the tool does.
func (t *BaseTool) Description() string {
	return t.description
}

// InputSchema returns the JSON schema for the tool's input parameters.
func (t *BaseTool) InputSchema() *jsonschema.Schema {
	return t.inputSchema
}

// OutputSchema returns the JSON schema for the tool's output.
func (t *BaseTool) OutputSchema() *jsonschema.Schema {
	return t.outputSchema
}

// Execute executes the tool with the given parameters.
func (t *BaseTool) Execute(ctx context.Context, params map[string]any) (any, error) {
	if t.executeFn == nil {
		return nil, fmt.Errorf("tool %s has no execute function", t.name)
	}
	
	// Validate input parameters against the schema if provided
	if t.inputSchema != nil {
		if err := jsonschema.Validate(params, t.inputSchema); err != nil {
			return nil, fmt.Errorf("invalid parameters for tool %s: %w", t.name, err)
		}
	}
	
	result, err := t.executeFn(ctx, params)
	if err != nil {
		return nil, err
	}
	
	// Validate output against the schema if provided
	if t.outputSchema != nil {
		if err := jsonschema.Validate(result, t.outputSchema); err != nil {
			return nil, fmt.Errorf("invalid output from tool %s: %w", t.name, err)
		}
	}
	
	return result, nil
}

// ToGenAITool converts the tool to a genai.Tool representation.
func (t *BaseTool) ToGenAITool() *genai.Tool {
	// Convert jsonschema to JSON string
	inputSchemaJSON, _ := sonic.ConfigFastest.Marshal(t.inputSchema)
	
	functionDeclaration := &genai.FunctionDeclaration{
		Name:        t.name,
		Description: t.description,
		Parameters: map[string]any{
			"type":       "object",
			"properties": t.inputSchema.Properties,
			"required":   t.inputSchema.Required,
		},
	}
	
	return &genai.Tool{
		FunctionDeclarations: []*genai.FunctionDeclaration{functionDeclaration},
	}
}

// Registry maintains a collection of tools that can be used by agents.
type Registry struct {
	tools map[string]Tool
}

// NewRegistry creates a new tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]Tool),
	}
}

// RegisterTool adds a tool to the registry.
func (r *Registry) RegisterTool(tool Tool) error {
	name := tool.Name()
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool with name %s already registered", name)
	}
	
	r.tools[name] = tool
	return nil
}

// GetTool retrieves a tool from the registry by name.
func (r *Registry) GetTool(name string) (Tool, bool) {
	tool, exists := r.tools[name]
	return tool, exists
}

// ListTools returns a list of all registered tools.
func (r *Registry) ListTools() []Tool {
	tools := make([]Tool, 0, len(r.tools))
	for _, tool := range r.tools {
		tools = append(tools, tool)
	}
	return tools
}

// ToGenAITools converts all registered tools to genai.Tool representations.
func (r *Registry) ToGenAITools() []*genai.Tool {
	tools := make([]*genai.Tool, 0, len(r.tools))
	for _, tool := range r.tools {
		tools = append(tools, tool.ToGenAITool())
	}
	return tools
}

// ExecuteTool executes a tool by name with the given parameters and returns the result.
func (r *Registry) ExecuteTool(ctx context.Context, name string, params map[string]any) (any, error) {
	tool, exists := r.tools[name]
	if !exists {
		return nil, fmt.Errorf("tool %s not found", name)
	}
	
	return tool.Execute(ctx, params)
}

// HandleToolCall handles a tool call event and generates a tool response event.
func (r *Registry) HandleToolCall(ctx context.Context, event *events.Event, emitEvent func(*events.Event) error) error {
	toolCall, err := event.GetToolCallContent()
	if err != nil {
		return err
	}
	
	result, err := r.ExecuteTool(ctx, toolCall.Name, toolCall.Parameters)
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	
	responseEvent, err := events.NewToolResponseEvent(
		event.SessionID,
		event.AgentID,
		result,
		errMsg,
		event.ID,
	)
	if err != nil {
		return err
	}
	
	return emitEvent(responseEvent)
}