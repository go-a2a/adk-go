// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
)

// Tool represents a function that can be called by an agent.
type Tool interface {
	// Name returns the name of the tool.
	Name() string

	// Description returns a description of what the tool does.
	Description() string

	// ParameterSchema returns the JSON schema for the tool's parameters.
	ParameterSchema() model.ToolParameterSpec

	// Execute runs the tool with the given arguments.
	Execute(ctx context.Context, args json.RawMessage) (string, error)

	// ToToolDefinition converts the tool to a ToolDefinition that can be passed to a model.
	ToToolDefinition() model.ToolDefinition

	// IsAsyncExecutionSupported returns true if the tool supports asynchronous execution.
	IsAsyncExecutionSupported() bool
}

// BaseTool provides a common implementation for tools.
type BaseTool struct {
	name                    string
	description             string
	paramSchema             model.ToolParameterSpec
	executeFn               func(ctx context.Context, args json.RawMessage) (string, error)
	asyncExecutionSupported bool
}

// NewBaseTool creates a new base tool with the provided configuration.
func NewBaseTool(
	name string,
	description string,
	paramSchema model.ToolParameterSpec,
	executeFn func(ctx context.Context, args json.RawMessage) (string, error),
) *BaseTool {
	return &BaseTool{
		name:                    name,
		description:             description,
		paramSchema:             paramSchema,
		executeFn:               executeFn,
		asyncExecutionSupported: false,
	}
}

// WithAsyncSupport marks the tool as supporting asynchronous execution.
func (t *BaseTool) WithAsyncSupport() *BaseTool {
	t.asyncExecutionSupported = true
	return t
}

// Name returns the name of the tool.
func (t *BaseTool) Name() string {
	return t.name
}

// Description returns a description of what the tool does.
func (t *BaseTool) Description() string {
	return t.description
}

// ParameterSchema returns the JSON schema for the tool's parameters.
func (t *BaseTool) ParameterSchema() model.ToolParameterSpec {
	return t.paramSchema
}

// Execute runs the tool with the given arguments.
func (t *BaseTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	logger := observability.Logger(ctx)
	logger.Debug("Executing tool",
		slog.String("tool", t.name),
		slog.String("args", string(args)),
	)

	// Start a new span for the tool execution
	ctx, span := observability.StartSpan(ctx, fmt.Sprintf("tool.%s", t.name))
	defer span.End()

	// Add attributes to the span
	span.SetAttributes(
		attribute.String("tool.name", t.name),
		attribute.String("tool.args", string(args)),
	)

	// Record metrics for the tool execution
	latencyRecorder := observability.MeasureLatency(ctx, "tool_execution",
		attribute.String("tool.name", t.name),
	)
	defer latencyRecorder()

	// Execute the tool
	startTime := time.Now()
	result, err := t.executeFn(ctx, args)
	duration := time.Since(startTime)

	// Record metrics and tracing data
	span.SetAttributes(attribute.Int64("duration_ms", duration.Milliseconds()))

	if err != nil {
		observability.IncrementFailures(ctx, attribute.String("tool.name", t.name))
		observability.Error(ctx, err, "Tool execution failed",
			slog.String("tool", t.name),
			slog.String("args", string(args)),
			slog.Duration("duration", duration),
		)
		span.RecordError(err)
		return "", fmt.Errorf("failed to execute tool '%s': %w", t.name, err)
	}

	logger.Debug("Tool execution completed",
		slog.String("tool", t.name),
		slog.Duration("duration", duration),
		slog.Int("result_length", len(result)),
	)

	return result, nil
}

// ToToolDefinition converts the tool to a ToolDefinition that can be passed to a model.
func (t *BaseTool) ToToolDefinition() model.ToolDefinition {
	return model.ToolDefinition{
		Name:        t.name,
		Description: t.description,
		Parameters:  t.paramSchema,
	}
}

// IsAsyncExecutionSupported returns true if the tool supports asynchronous execution.
func (t *BaseTool) IsAsyncExecutionSupported() bool {
	return t.asyncExecutionSupported
}

// AsyncTool is a wrapper around a Tool that supports asynchronous execution.
type AsyncTool struct {
	tool        Tool
	resultCache map[string]string
	cacheMutex  sync.RWMutex
}

// NewAsyncTool creates a new async tool wrapper around a regular tool.
func NewAsyncTool(tool Tool) *AsyncTool {
	return &AsyncTool{
		tool:        tool,
		resultCache: make(map[string]string),
		cacheMutex:  sync.RWMutex{},
	}
}

// Name returns the name of the tool.
func (a *AsyncTool) Name() string {
	return a.tool.Name()
}

// Description returns a description of what the tool does.
func (a *AsyncTool) Description() string {
	return a.tool.Description()
}

// ParameterSchema returns the JSON schema for the tool's parameters.
func (a *AsyncTool) ParameterSchema() model.ToolParameterSpec {
	return a.tool.ParameterSchema()
}

// Execute runs the tool asynchronously.
func (a *AsyncTool) Execute(ctx context.Context, args json.RawMessage) (string, error) {
	// Generate a unique request ID
	requestID := fmt.Sprintf("%s-%d", a.tool.Name(), time.Now().UnixNano())

	// Start a new goroutine to execute the tool
	go func() {
		subCtx, span := observability.StartSpan(
			context.Background(),
			fmt.Sprintf("async_tool.%s", a.tool.Name()),
		)
		defer span.End()

		subCtx = trace.ContextWithSpanContext(subCtx, trace.SpanContextFromContext(ctx))

		result, err := a.tool.Execute(subCtx, args)
		if err != nil {
			observability.Error(subCtx, err, "Async tool execution failed",
				slog.String("tool", a.tool.Name()),
				slog.String("requestID", requestID),
			)
			a.cacheMutex.Lock()
			a.resultCache[requestID] = fmt.Sprintf("Error: %v", err)
			a.cacheMutex.Unlock()
			return
		}

		// Store the result in the cache
		a.cacheMutex.Lock()
		a.resultCache[requestID] = result
		a.cacheMutex.Unlock()

		observability.Logger(subCtx).Debug("Async tool execution completed",
			slog.String("tool", a.tool.Name()),
			slog.String("requestID", requestID),
		)
	}()

	// Return immediately with the request ID
	return fmt.Sprintf("Request ID: %s", requestID), nil
}

// GetResult retrieves the result of an asynchronous tool execution.
func (a *AsyncTool) GetResult(requestID string) (string, bool) {
	a.cacheMutex.RLock()
	defer a.cacheMutex.RUnlock()

	result, exists := a.resultCache[requestID]
	return result, exists
}

// ToToolDefinition converts the tool to a ToolDefinition that can be passed to a model.
func (a *AsyncTool) ToToolDefinition() model.ToolDefinition {
	return a.tool.ToToolDefinition()
}

// IsAsyncExecutionSupported returns true as this is an async tool.
func (a *AsyncTool) IsAsyncExecutionSupported() bool {
	return true
}

// ToolRegistry provides a registry for tools.
type ToolRegistry struct {
	tools map[string]Tool
	mu    sync.RWMutex
}

// NewToolRegistry creates a new tool registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]Tool),
	}
}

// Register registers a tool in the registry.
func (r *ToolRegistry) Register(tool Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[tool.Name()] = tool
}

// Get retrieves a tool from the registry.
func (r *ToolRegistry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, exists := r.tools[name]
	return tool, exists
}

// GetAll returns all registered tools.
func (r *ToolRegistry) GetAll() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]Tool, 0, len(r.tools))
	for _, tool := range r.tools {
		tools = append(tools, tool)
	}

	return tools
}
