// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// GoogleAPIAuth contains authentication information for Google APIs.
type GoogleAPIAuth struct {
	APIKey     string
	HTTPClient *http.Client
}

// NewGoogleAPITool creates a basic Google API tool.
// This is a base tool that other Google API-specific tools can build upon.
func NewGoogleAPITool(
	name string,
	description string,
	paramSchema model.ToolParameterSpec,
	executeFn func(ctx context.Context, auth GoogleAPIAuth, args json.RawMessage) (string, error),
	auth GoogleAPIAuth,
) *tool.BaseTool {
	wrappedExecuteFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		ctx, span := observability.StartSpan(ctx, fmt.Sprintf("tool.google_api.%s", name))
		defer span.End()

		logger := observability.Logger(ctx)
		logger.Debug("Executing Google API tool",
			slog.String("tool", name),
			slog.String("args", string(args)),
		)

		// Record request time
		startTime := time.Now()
		result, err := executeFn(ctx, auth, args)
		duration := time.Since(startTime)

		// Log completion
		if err != nil {
			observability.Error(ctx, err, "Google API tool execution failed",
				slog.String("tool", name),
				slog.String("args", string(args)),
				slog.Duration("duration", duration),
			)
			return "", fmt.Errorf("failed to execute Google API tool: %w", err)
		}

		logger.Debug("Google API tool execution completed",
			slog.String("tool", name),
			slog.Duration("duration", duration),
			slog.Int("result_length", len(result)),
		)

		return result, nil
	}

	return tool.NewBaseTool(
		name,
		description,
		paramSchema,
		wrappedExecuteFn,
	)
}
