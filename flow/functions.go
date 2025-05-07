// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"fmt"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/types"
)

// FunctionsFlow is a flow that processes tool/function calls.
type FunctionsFlow struct {
	*LLMFlow
	tools []types.Tool
}

var _ Flow = (*FunctionsFlow)(nil)

// NewFunctionsFlow creates a new FunctionsFlow with the given model and options.
func NewFunctionsFlow(model model.Model, tools []types.Tool, opts ...FlowOption) (*FunctionsFlow, error) {
	base, err := NewLLMFlow(model, opts...)
	if err != nil {
		return nil, err
	}

	return &FunctionsFlow{
		LLMFlow: base,
		tools:   tools,
	}, nil
}

// Process implements [Flow].
func (f *FunctionsFlow) Process(ctx context.Context, input any) (any, error) {
	contents, ok := input.([]*genai.Content)
	if !ok {
		return nil, fmt.Errorf("input must be a slice of genai.Content, got %T", input)
	}

	// Create request with tools
	req := &types.LLMRequest{
		Contents: contents,
		ToolMap:  make(map[string]types.Tool),
	}

	// Add tools to request
	for _, t := range f.tools {
		req.ToolMap[t.Name()] = types.NewTool(t.Name(), t.Description(), t.InputSchema())
	}

	// Generate content
	resp, err := f.GetModel().GenerateContent(ctx, req)
	if err != nil {
		return nil, err
	}

	// If there are tool calls, execute them
	if resp != nil && len(resp.ToolCalls) > 0 {
		for _, tc := range resp.ToolCalls {
			f.executeToolCall(ctx, tc, resp)
		}
	}

	return resp, nil
}

// executeToolCall executes a tool call and updates the response.
func (f *FunctionsFlow) executeToolCall(ctx context.Context, tc *types.ToolCall, resp *types.LLMResponse) {
	// Find the tool
	var selectedTool types.Tool
	for _, t := range f.tools {
		if t.Name() == tc.Name {
			selectedTool = t
			break
		}
	}

	if selectedTool == nil {
		f.logger.WarnContext(ctx, "tool not found", "tool", tc.Name)
		tc.Output = map[string]any{
			"error": fmt.Sprintf("tool %q not found", tc.Name),
		}
		return
	}

	// Create tool context
	toolCtx := &types.ToolContext{
		CallbackContext: &types.CallbackContext{
			Input:    tc.Input,
			Response: resp,
		},
		FunctionCallID: tc.Name,
	}

	// Execute the tool
	result, err := selectedTool.Execute(ctx, tc.Input, toolCtx)
	if err != nil {
		f.logger.ErrorContext(ctx, "tool execution failed", "tool", tc.Name, "error", err)
		tc.Output = map[string]any{
			"error": err.Error(),
		}
	} else {
		tc.Output = map[string]any{
			"result": result,
		}
	}
}

// AddTool adds a tool to the flow.
func (f *FunctionsFlow) AddTool(t types.Tool) {
	f.tools = append(f.tools, t)
}
