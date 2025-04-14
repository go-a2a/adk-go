// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// FunctionToolConfig defines the configuration for a function tool.
type FunctionToolConfig struct {
	Name           string
	Description    string
	ParameterSchema model.ToolParameterSpec
	Function       func(ctx context.Context, args json.RawMessage) (string, error)
}

// NewFunctionTool creates a new tool that wraps a custom function.
// This allows users to easily create custom tools with custom functionality.
func NewFunctionTool(config FunctionToolConfig) *tool.BaseTool {
	if config.Name == "" {
		config.Name = "custom_function"
	}

	if config.Description == "" {
		config.Description = "Executes a custom function with the provided parameters."
	}

	if config.ParameterSchema == nil {
		config.ParameterSchema = model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{},
		}
	}

	if config.Function == nil {
		// Provide a default function that returns an error
		config.Function = func(ctx context.Context, args json.RawMessage) (string, error) {
			return "", fmt.Errorf("function not implemented for tool %s", config.Name)
		}
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		logger := observability.Logger(ctx)
		logger.Debug("Executing function tool",
			slog.String("tool", config.Name),
			slog.String("args", string(args)),
		)

		ctx, span := observability.StartSpan(ctx, fmt.Sprintf("tool.function.%s", config.Name))
		defer span.End()

		startTime := time.Now()
		result, err := config.Function(ctx, args)
		duration := time.Since(startTime)

		if err != nil {
			observability.Error(ctx, err, "Function tool execution failed",
				slog.String("tool", config.Name),
				slog.String("args", string(args)),
				slog.Duration("duration", duration),
			)
			return "", fmt.Errorf("function tool execution failed: %w", err)
		}

		logger.Debug("Function tool execution completed",
			slog.String("tool", config.Name),
			slog.Duration("duration", duration),
			slog.Int("result_length", len(result)),
		)

		return result, nil
	}

	return tool.NewBaseTool(
		config.Name,
		config.Description,
		config.ParameterSchema,
		executeFn,
	)
}