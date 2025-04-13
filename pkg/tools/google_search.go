// Copyright 2024 The ADK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
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
