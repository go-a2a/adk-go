// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"errors"

	"google.golang.org/genai"
)

// Tool defines the interface that all tools must implement.
type Tool interface {
	// Name returns the name of the tool.
	Name() string

	// Description returns the description of the tool.
	Description() string

	// InputSchema returns the JSON schema for the tool's input.
	InputSchema() *genai.Schema

	// Execute executes the tool with the given parameters.
	Execute(ctx context.Context, params map[string]any, toolCtx *ToolContext) (any, error)

	ProcessLLMRequest(toolCtx *ToolContext, llmRequest *LLMRequest)

	FunctionDeclarations() []*genai.FunctionDeclaration
}

type tool struct {
	name        string
	description string
	inputSchema *genai.Schema
}

func NewTool(name, description string, inputSchema *genai.Schema) Tool {
	return &tool{
		name:        name,
		description: description,
		inputSchema: inputSchema,
	}
}

var _ Tool = (*tool)(nil)

func (t *tool) Name() string {
	return t.name
}

func (t *tool) Description() string {
	return t.description
}

func (t *tool) InputSchema() *genai.Schema {
	return t.inputSchema
}

// Execute executes the tool with the given parameters.
func (t *tool) Execute(ctx context.Context, params map[string]any, toolCtx *ToolContext) (any, error) {
	return nil, errors.New("not implemented")
}

func (t *tool) ProcessLLMRequest(*ToolContext, *LLMRequest) {}

func (t *tool) FunctionDeclarations() []*genai.FunctionDeclaration {
	return []*genai.FunctionDeclaration{
		{
			Name:        t.name,
			Description: t.description,
			Parameters:  t.inputSchema,
		},
	}
}

// TODO(zchee): implements methods.
type Toolset interface{}

// ToolContext holds the context for executing a tool.
type ToolContext struct {
	*CallbackContext

	InvocationContext *InvocationContext
	functionCallID    string
	eventActions      *EventActions
}

func (tc *ToolContext) WithFunctionCallID(funcCallID string) *ToolContext {
	tc.functionCallID = funcCallID
	return tc
}

func (tc *ToolContext) WithEventActions(eventActions *EventActions) *ToolContext {
	tc.eventActions = eventActions
	return tc
}

// NewToolContext creates a new ToolContext with the given function call ID.
func NewToolContext(ic *InvocationContext) *ToolContext {
	return &ToolContext{
		InvocationContext: ic,
	}
}

// Actions returns the event actions for the tool context.
func (tc *ToolContext) Actions() *EventActions {
	return tc.eventActions
}
