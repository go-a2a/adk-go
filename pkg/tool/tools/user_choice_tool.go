// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// UserChoiceParams defines parameters for prompting the user with a choice.
type UserChoiceParams struct {
	Question string   `json:"question"`
	Options  []string `json:"options"`
}

// UserChoiceHandler defines an interface for handling user choices.
type UserChoiceHandler interface {
	// GetUserChoice prompts the user with a question and a list of options and returns the chosen option.
	GetUserChoice(ctx context.Context, question string, options []string) (string, error)
}

// NewGetUserChoiceTool creates a tool for getting a choice from the user.
func NewGetUserChoiceTool(handler UserChoiceHandler) *tool.BaseTool {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"question": map[string]any{
				"type":        "string",
				"description": "The question to ask the user",
			},
			"options": map[string]any{
				"type":        "array",
				"description": "The options to present to the user",
				"items": map[string]any{
					"type": "string",
				},
			},
		},
		"required": []string{"question", "options"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		logger := observability.Logger(ctx)

		// Parse parameters
		var params UserChoiceParams
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf("failed to parse user choice parameters: %w", err)
		}

		// Validate parameters
		if params.Question == "" {
			return "", fmt.Errorf("question is required")
		}
		if len(params.Options) == 0 {
			return "", fmt.Errorf("at least one option is required")
		}

		logger.Debug("Getting user choice",
			slog.String("question", params.Question),
			slog.Any("options", params.Options),
		)

		// Get user choice
		choice, err := handler.GetUserChoice(ctx, params.Question, params.Options)
		if err != nil {
			return "", fmt.Errorf("failed to get user choice: %w", err)
		}

		return fmt.Sprintf("User selected: %s", choice), nil
	}

	return tool.NewBaseTool(
		"get_user_choice",
		"Prompts the user with a question and a list of options and returns the chosen option.",
		paramSchema,
		executeFn,
	).WithAsyncSupport() // Mark as async since this requires user interaction
}

// DefaultUserChoiceHandler is a simple implementation of UserChoiceHandler that prints to stdout and reads from stdin.
type DefaultUserChoiceHandler struct{}

// GetUserChoice implements UserChoiceHandler by printing to stdout and reading from stdin.
func (h *DefaultUserChoiceHandler) GetUserChoice(ctx context.Context, question string, options []string) (string, error) {
	// This is a mock implementation that would be replaced with actual UI interaction in a real app
	observability.Logger(ctx).Info("User choice requested",
		slog.String("question", question),
		slog.Any("options", options),
	)

	// Simulate always choosing the first option
	if len(options) > 0 {
		return options[0], nil
	}

	return "", fmt.Errorf("no options provided")
}
