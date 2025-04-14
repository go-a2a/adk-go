// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package tool_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
)

func TestNewBaseTool(t *testing.T) {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "Search query",
			},
		},
		"required": []string{"query"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		var params struct {
			Query string `json:"query"`
		}
		if err := sonic.Unmarshal(args, &params); err != nil {
			return "", err
		}
		return fmt.Sprintf("Results for: %s", params.Query), nil
	}

	bt := tool.NewBaseTool(
		"search",
		"Search for information",
		paramSchema,
		executeFn,
	)

	if bt == nil {
		t.Fatalf("bt is nil, want non-nil")
	}
	if got, want := bt.Name(), "search"; !cmp.Equal(got, want) {
		t.Errorf("bt.Name( = %v, want %v", got, want)
	}
	if got, want := bt.Description(), "Search for information"; !cmp.Equal(got, want) {
		t.Errorf("bt.Description( = %v, want %v", got, want)
	}
	if got, want := bt.ParameterSchema(), paramSchema; !cmp.Equal(got, want) {
		t.Errorf("bt.ParameterSchema( = %v, want %v", got, want)
	}
	if bt.IsAsyncExecutionSupported() {
		t.Errorf("expected bt.IsAsyncExecutionSupported( to be false")
	}
}

func TestBaseTool_WithAsyncSupport(t *testing.T) {
	bt := tool.NewBaseTool(
		"sample",
		"Sample tool",
		model.ToolParameterSpec{},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			return "result", nil
		},
	)

	// By default, should not support async
	if bt.IsAsyncExecutionSupported() {
		t.Errorf("expected bt.IsAsyncExecutionSupported( to be false")
	}

	// Add async support
	bt = bt.WithAsyncSupport()
	if !bt.IsAsyncExecutionSupported() {
		t.Errorf("expected bt.IsAsyncExecutionSupported( to be true")
	}
}

func TestBaseTool_Execute(t *testing.T) {
	executed := false
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"input": map[string]any{
				"type": "string",
			},
		},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		executed = true
		var params struct {
			Input string `json:"input"`
		}
		err := sonic.Unmarshal(args, &params)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("Processed: %s", params.Input), nil
	}

	bt := tool.NewBaseTool(
		"processor",
		"Process input",
		paramSchema,
		executeFn,
	)

	// Create arguments
	args, err := sonic.Marshal(map[string]string{
		"input": "test data",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Execute the tool
	result, err := bt.Execute(context.Background(), args)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !executed {
		t.Errorf("expected executed to be true")
	}
	if got, want := result, "Processed: test data"; !cmp.Equal(got, want) {
		t.Errorf("result = %v, want %v", got, want)
	}
}

func TestBaseTool_ExecuteError(t *testing.T) {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"input": map[string]any{
				"type": "string",
			},
		},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		return "", fmt.Errorf("execution failed")
	}

	bt := tool.NewBaseTool(
		"error_tool",
		"Always fails",
		paramSchema,
		executeFn,
	)

	// Create arguments
	args, err := sonic.Marshal(map[string]string{
		"input": "test data",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Execute the tool
	result, err := bt.Execute(context.Background(), args)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	if len(result) != 0 {
		t.Errorf("result is not empty, len = %d", len(result))
	}
	if !strings.Contains(err.Error(), "failed to execute tool 'error_tool'") {
		t.Errorf("err.Error() does not contain %q", "failed to execute tool 'error_tool'")
	}
	if !strings.Contains(err.Error(), "execution failed") {
		t.Errorf("err.Error() does not contain %q", "execution failed")
	}
}

func TestBaseTool_ToToolDefinition(t *testing.T) {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{
				"type": "string",
			},
		},
	}

	bt := tool.NewBaseTool(
		"search",
		"Search for information",
		paramSchema,
		func(ctx context.Context, args json.RawMessage) (string, error) {
			return "result", nil
		},
	)

	toolDef := bt.ToToolDefinition()

	if got, want := toolDef.Name, "search"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Name = %v, want %v", got, want)
	}
	if got, want := toolDef.Description, "Search for information"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Description = %v, want %v", got, want)
	}
	if got, want := toolDef.Parameters, paramSchema; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Parameters = %v, want %v", got, want)
	}
}

func TestNewAsyncTool(t *testing.T) {
	baseTool := tool.NewBaseTool(
		"async_sample",
		"Sample async tool",
		model.ToolParameterSpec{},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			return "result", nil
		},
	)

	asyncTool := tool.NewAsyncTool(baseTool)

	if asyncTool == nil {
		t.Fatalf("asyncTool is nil, want non-nil")
	}
	if got, want := asyncTool.Name(), "async_sample"; !cmp.Equal(got, want) {
		t.Errorf("asyncTool.Name( = %v, want %v", got, want)
	}
	if got, want := asyncTool.Description(), "Sample async tool"; !cmp.Equal(got, want) {
		t.Errorf("asyncTool.Description( = %v, want %v", got, want)
	}
	if !asyncTool.IsAsyncExecutionSupported() {
		t.Errorf("expected asyncTool.IsAsyncExecutionSupported( to be true")
	}
}

func TestAsyncTool_Execute(t *testing.T) {
	executionDone := false
	var executionMu sync.Mutex

	baseTool := tool.NewBaseTool(
		"long_running",
		"Long running operation",
		model.ToolParameterSpec{},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Simulate long-running task
			time.Sleep(200 * time.Millisecond)
			executionMu.Lock()
			executionDone = true
			executionMu.Unlock()
			return "Long operation complete", nil
		},
	)

	asyncTool := tool.NewAsyncTool(baseTool)

	// Execute the async tool
	result, err := asyncTool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Request ID:") {
		t.Errorf("result does not contain %q", "Request ID:")
	}

	// Request ID should be in the format: tool_name-timestamp
	if !strings.Contains(result, "long_running-") {
		t.Errorf("result does not contain %q", "long_running-")
	}

	// Extract request ID
	var requestID string
	_, err = fmt.Sscanf(result, "Request ID: %s", &requestID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Initially, result should not be available immediately
	executionMu.Lock()
	isDone := executionDone
	executionMu.Unlock()
	if isDone {
		t.Errorf("expected executionDone to be false")
	}
	_, exists := asyncTool.GetResult(requestID)
	if exists {
		t.Errorf("expected exists to be false")
	}

	// Wait for the operation to complete
	time.Sleep(300 * time.Millisecond)

	// Now result should be available
	executionMu.Lock()
	isDone = executionDone
	executionMu.Unlock()
	if !isDone {
		t.Errorf("expected executionDone to be true")
	}
	toolResult, exists := asyncTool.GetResult(requestID)
	if !exists {
		t.Errorf("expected exists to be true")
	}
	if got, want := toolResult, "Long operation complete"; !cmp.Equal(got, want) {
		t.Errorf("toolResult = %v, want %v", got, want)
	}
}

func TestAsyncTool_ExecuteWithError(t *testing.T) {
	baseTool := tool.NewBaseTool(
		"error_prone",
		"Tool that produces errors",
		model.ToolParameterSpec{},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			return "", fmt.Errorf("execution failed")
		},
	)

	asyncTool := tool.NewAsyncTool(baseTool)

	// Execute the async tool
	result, err := asyncTool.Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Request ID:") {
		t.Errorf("result does not contain %q", "Request ID:")
	}

	// Extract request ID
	var requestID string
	_, err = fmt.Sscanf(result, "Request ID: %s", &requestID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Wait for operation to complete
	time.Sleep(100 * time.Millisecond)

	// Result should be an error message
	toolResult, exists := asyncTool.GetResult(requestID)
	if !exists {
		t.Errorf("expected exists to be true")
	}
	if !strings.Contains(toolResult, "Error:") {
		t.Errorf("toolResult does not contain %q", "Error:")
	}
	if !strings.Contains(toolResult, "execution failed") {
		t.Errorf("toolResult does not contain %q", "execution failed")
	}
}

func TestToolRegistry(t *testing.T) {
	registry := tool.NewToolRegistry()
	if registry == nil {
		t.Fatalf("registry is nil, want non-nil")
	}

	// Create sample tools
	tool1 := tool.NewBaseTool(
		"tool1",
		"First tool",
		model.ToolParameterSpec{},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			return "result1", nil
		},
	)

	tool2 := tool.NewBaseTool(
		"tool2",
		"Second tool",
		model.ToolParameterSpec{},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			return "result2", nil
		},
	)

	// Register tools
	registry.Register(tool1)
	registry.Register(tool2)

	// Get a tool by name
	retrievedTool, exists := registry.Get("tool1")
	if !exists {
		t.Errorf("expected exists to be true")
	}
	if got, want := retrievedTool.Name(), "tool1"; !cmp.Equal(got, want) {
		t.Errorf("retrievedTool.Name( = %v, want %v", got, want)
	}

	// Try to get a non-existent tool
	_, exists = registry.Get("non_existent")
	if exists {
		t.Errorf("expected exists to be false")
	}

	// Get all tools
	allTools := registry.GetAll()
	if got, want := len(allTools), 2; got != want {
		t.Errorf("len(allTools) = %d, want %d", got, want)
	}

	// Tools can be in any order, so check both possibilities
	if allTools[0].Name() == "tool1" {
		if got, want := allTools[1].Name(), "tool2"; !cmp.Equal(got, want) {
			t.Errorf("allTools[1].Name( = %v, want %v", got, want)
		}
	} else {
		if got, want := allTools[0].Name(), "tool2"; !cmp.Equal(got, want) {
			t.Errorf("allTools[0].Name( = %v, want %v", got, want)
		}
		if got, want := allTools[1].Name(), "tool1"; !cmp.Equal(got, want) {
			t.Errorf("allTools[1].Name( = %v, want %v", got, want)
		}
	}
}
