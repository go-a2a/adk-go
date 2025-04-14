// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/artifacts"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// LoadMemoryParams defines parameters for loading memory.
type LoadMemoryParams struct {
	Key      string `json:"key"`
	FullText bool   `json:"full_text,omitempty"`
}

// SaveMemoryParams defines parameters for saving memory.
type SaveMemoryParams struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// LoadArtifactsParams defines parameters for loading artifacts.
type LoadArtifactsParams struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

// NewLoadMemoryTool creates a tool for loading items from agent memory.
func NewLoadMemoryTool(artifactService artifacts.ArtifactService) *tool.BaseTool {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"key": map[string]any{
				"type":        "string",
				"description": "The key to load from memory",
			},
			"full_text": map[string]any{
				"type":        "boolean",
				"description": "Whether to load the full text or a summary",
				"default":     false,
			},
		},
		"required": []string{"key"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		logger := observability.Logger(ctx)

		// Parse parameters
		var params LoadMemoryParams
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf("failed to parse memory parameters: %w", err)
		}

		// Validate parameters
		if params.Key == "" {
			return "", fmt.Errorf("key is required")
		}

		logger.Debug("Loading memory", slog.String("key", params.Key))

		// Load the memory
		content, err := artifactService.GetArtifact(ctx, "memory:"+params.Key)
		if err != nil {
			return "", fmt.Errorf("failed to load memory: %w", err)
		}

		// If content is not found
		if content == "" {
			return fmt.Sprintf("No memory found for key: %s", params.Key), nil
		}

		// If full text is not requested and content is large, create a summary
		if !params.FullText && len(content) > 1000 {
			// In a real implementation, you might use an LLM to generate a summary
			return fmt.Sprintf("Memory for key '%s' (truncated): %s...",
				params.Key,
				content[:997]+"..."), nil
		}

		return fmt.Sprintf("Memory for key '%s': %s", params.Key, content), nil
	}

	return tool.NewBaseTool(
		"load_memory",
		"Loads information from agent memory using a key. Use this to retrieve previously stored information.",
		paramSchema,
		executeFn,
	)
}

// NewSaveMemoryTool creates a tool for saving items to agent memory.
func NewSaveMemoryTool(artifactService artifacts.ArtifactService) *tool.BaseTool {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"key": map[string]any{
				"type":        "string",
				"description": "The key to save the memory under",
			},
			"value": map[string]any{
				"type":        "string",
				"description": "The value to save",
			},
		},
		"required": []string{"key", "value"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		logger := observability.Logger(ctx)

		// Parse parameters
		var params SaveMemoryParams
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf("failed to parse memory parameters: %w", err)
		}

		// Validate parameters
		if params.Key == "" {
			return "", fmt.Errorf("key is required")
		}
		if params.Value == "" {
			return "", fmt.Errorf("value is required")
		}

		logger.Debug("Saving memory",
			slog.String("key", params.Key),
			slog.Int("value_length", len(params.Value)),
		)

		// Save the memory
		if err := artifactService.SaveArtifactByKey(ctx, "memory:"+params.Key, params.Value); err != nil {
			return "", fmt.Errorf("failed to save memory: %w", err)
		}

		return fmt.Sprintf("Successfully saved memory with key: %s", params.Key), nil
	}

	return tool.NewBaseTool(
		"save_memory",
		"Saves information to agent memory using a key. Use this to store information for later retrieval.",
		paramSchema,
		executeFn,
	)
}

// NewLoadArtifactsTool creates a tool for loading artifacts.
func NewLoadArtifactsTool(artifactService artifacts.ArtifactService) *tool.BaseTool {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "The path to load artifacts from",
			},
			"recursive": map[string]any{
				"type":        "boolean",
				"description": "Whether to recursively load artifacts from subdirectories",
				"default":     false,
			},
		},
		"required": []string{"path"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		logger := observability.Logger(ctx)

		// Parse parameters
		var params LoadArtifactsParams
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf("failed to parse artifacts parameters: %w", err)
		}

		// Validate parameters
		if params.Path == "" {
			return "", fmt.Errorf("path is required")
		}

		logger.Debug("Loading artifacts",
			slog.String("path", params.Path),
			slog.Bool("recursive", params.Recursive),
		)

		// List artifacts
		artifacts, err := artifactService.ListArtifacts(ctx, params.Path, params.Recursive)
		if err != nil {
			return "", fmt.Errorf("failed to list artifacts: %w", err)
		}

		if len(artifacts) == 0 {
			return fmt.Sprintf("No artifacts found at path: %s", params.Path), nil
		}

		// Format the result
		result := fmt.Sprintf("Found %d artifacts at path: %s\n\n", len(artifacts), params.Path)
		for i, artifact := range artifacts {
			result += fmt.Sprintf("%d. %s\n", i+1, artifact)
		}

		return result, nil
	}

	return tool.NewBaseTool(
		"load_artifacts",
		"Lists and loads artifacts from a path. Use this to explore and access stored artifacts.",
		paramSchema,
		executeFn,
	)
}
