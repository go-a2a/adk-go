// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// Agent is a [tool.Tool] that wraps an agent.
//
// This tool allows an agent to be called as a tool within a larger application.
// The agent's input schema is used to define the tool's input parameters, and
// the agent's output is returned as the tool's result.
type Agent struct {
	*Config

	skipSummarization bool
}

var _ types.Tool = (*Agent)(nil)

// NewAgent creates a new [Agent] tool with the given options.
func NewAgent(name, description string, opts ...ToolOption) *Agent {
	tool := &Agent{
		Config: &Config{
			name:        name,
			description: description,
		},
	}
	for _, opt := range opts {
		opt(tool.Config)
	}

	return tool
}

// Name returns the tool name.
func (t *Agent) Name() string {
	return t.name
}

// Description returns the description.
func (t *Agent) Description() string {
	return t.description
}

// InputSchema returns the input schema.
func (t *Agent) InputSchema() *genai.Schema {
	return t.innputSchema
}

// Execute runs the tool with the given params.
func (t *Agent) Execute(ctx context.Context, params map[string]any, toolCtx *types.ToolContext) (any, error) {
	if t.executor == nil {
		return nil, errors.New("tool executor not set")
	}
	return t.executor(ctx, params)
}

func (t *Agent) ProcessLLMRequest(toolCtx *types.ToolContext, llmRequest *types.LLMRequest) {}

func (t *Agent) FunctionDeclarations() []*genai.FunctionDeclaration {
	return []*genai.FunctionDeclaration{
		{
			Name:        t.name,
			Description: t.description,
			Parameters:  t.innputSchema,
		},
	}
}
