// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/tool"
)

// GoogleSearchParams defines the parameters for a Google search.
type GoogleSearchParams struct {
	Query      string `json:"query"`
	NumResults int    `json:"num_results,omitempty"`
}

// NewGoogleSearchTool creates a new Google Search tool.
// Note: This is a mock implementation. In a real implementation, you would
// integrate with Google's Search API or a similar service.
func NewGoogleSearchTool() *tool.BaseTool {
	// Define parameter schema in JSON Schema format
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{
				"type":        "string",
				"description": "The search query",
			},
			"num_results": map[string]any{
				"type":        "integer",
				"description": "Number of results to return",
				"default":     5,
			},
		},
		"required": []string{"query"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		// Parse the arguments
		var params GoogleSearchParams
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf("failed to parse search parameters: %w", err)
		}

		// Set default number of results if not specified
		if params.NumResults <= 0 {
			params.NumResults = 5
		}

		// This is a mock implementation
		// In a real implementation, you would call Google's Search API here
		return fmt.Sprintf("Mock search results for query '%s' (showing %d results)\n\n1. Example search result 1\n2. Example search result 2\n3. Example search result 3",
			params.Query,
			params.NumResults), nil
	}

	return tool.NewBaseTool(
		"google_search",
		"Search Google for information. Use this when you need to find current or factual information.",
		paramSchema,
		executeFn,
	)
}
