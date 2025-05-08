// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

var (
	// memoryService is a global memory service used by the memory tool.
	// It should be set using SetMemoryService before using the memory tool.
	memoryService types.MemoryService
)

// SetMemoryService sets the memory service used by the memory tool.
func SetMemoryService(svc types.MemoryService) {
	memoryService = svc
}

// LoadMemory is a tool that searches for information in memory.
var LoadMemory = &Config{
	name:        "load_memory",
	description: "Search for information in past conversations or knowledge bases",
	innputSchema: &genai.Schema{
		Type: "object",
		Properties: map[string]*genai.Schema{
			"query": {
				Type:        "string",
				Description: "The search query to find relevant information",
			},
			"app_name": {
				Type:        "string",
				Description: "The application name to search in (optional)",
			},
			"user_id": {
				Type:        "string",
				Description: "Optional user ID to filter results by",
			},
		},
		Required: []string{"query"},
	},
	executor: func(ctx context.Context, params map[string]any) (any, error) {
		if memoryService == nil {
			return nil, fmt.Errorf("memory service not set, call SetMemoryService before using this tool")
		}

		// Extract parameters
		query, ok := params["query"].(string)
		if !ok {
			return nil, fmt.Errorf("query parameter is required and must be a string")
		}

		// Get app name from params or context
		appName := ""
		if appNameParam, ok := params["app_name"].(string); ok && appNameParam != "" {
			appName = appNameParam
		} else {
			// Try to extract from tool context if available
			if toolCtx, ok := ctx.Value("tool_context").(*types.ToolContext); ok {
				if toolCtx.InvocationContext != nil {
					appName = toolCtx.InvocationContext.AppName()
				}
			}

			if appName == "" {
				appName = "default" // Fallback
			}
		}

		// Get user ID from params or context
		userID := ""
		if userIDParam, ok := params["user_id"].(string); ok {
			userID = userIDParam
		}

		// Search memory
		response, err := memoryService.SearchMemory(ctx, appName, userID, query)
		if err != nil {
			return nil, fmt.Errorf("failed to search memory: %w", err)
		}

		// Format response to be more readable for the agent
		formattedResults := []map[string]any{}
		for _, result := range response.Results {
			// Extract text content from events to make it more consumable
			content := ""
			for _, event := range result.Events {
				if event.Author != "" {
					content += fmt.Sprintf("\n%s: ", event.Author)
				}

				if event.Content != nil {
					for _, part := range event.Content.Parts {
						if part.Text != "" {
							content += part.Text + " "
						}
					}
				}
			}

			formattedResults = append(formattedResults, map[string]any{
				"session_id":      result.SessionID,
				"relevance_score": result.RelevanceScore,
				"content":         content,
				"timestamp":       result.Timestamp.Format(time.RFC3339),
			})
		}

		return map[string]any{
			"results": formattedResults,
			"count":   len(formattedResults),
		}, nil
	},
}
