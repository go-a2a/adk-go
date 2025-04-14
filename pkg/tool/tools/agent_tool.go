// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// TransferToAgentParams defines the parameters for transferring to another agent.
type TransferToAgentParams struct {
	AgentID    string `json:"agent_id"`
	Question   string `json:"question"`
	Context    string `json:"context,omitempty"`
	ReturnToMe bool   `json:"return_to_me,omitempty"`
}

// AgentTransferRegistry provides an interface to transfer questions to other agents.
type AgentTransferRegistry interface {
	// TransferQuestion sends a question to another agent and returns the response.
	TransferQuestion(ctx context.Context, agentID string, question string, context string, returnToMe bool) (string, error)

	// ListAgents returns a list of available agents.
	ListAgents(ctx context.Context) ([]AgentInfo, error)
}

// AgentInfo contains information about an agent.
type AgentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// NewTransferToAgentTool creates a new tool for transferring questions to other agents.
func NewTransferToAgentTool(registry AgentTransferRegistry) *tool.BaseTool {
	paramSchema := model.ToolParameterSpec{
		"type": "object",
		"properties": map[string]any{
			"agent_id": map[string]any{
				"type":        "string",
				"description": "The ID of the agent to transfer the question to",
			},
			"question": map[string]any{
				"type":        "string",
				"description": "The question or task to send to the agent",
			},
			"context": map[string]any{
				"type":        "string",
				"description": "Additional context to provide to the agent",
			},
			"return_to_me": map[string]any{
				"type":        "boolean",
				"description": "Whether the agent should return control back to this agent after completion",
				"default":     false,
			},
		},
		"required": []string{"agent_id", "question"},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		// Parse the arguments
		var params TransferToAgentParams
		if err := json.Unmarshal(args, &params); err != nil {
			return "", fmt.Errorf("failed to parse transfer parameters: %w", err)
		}

		// Validate parameters
		if params.AgentID == "" {
			return "", fmt.Errorf("agent_id is required")
		}
		if params.Question == "" {
			return "", fmt.Errorf("question is required")
		}

		// Transfer the question to the specified agent
		response, err := registry.TransferQuestion(
			ctx,
			params.AgentID,
			params.Question,
			params.Context,
			params.ReturnToMe,
		)
		if err != nil {
			return "", fmt.Errorf("failed to transfer question to agent: %w", err)
		}

		return response, nil
	}

	return tool.NewBaseTool(
		"transfer_to_agent",
		"Transfers the current task or question to another specialized agent. Use this when you need expertise from a different agent.",
		paramSchema,
		executeFn,
	)
}

// NewListAgentsTool creates a new tool for listing available agents.
func NewListAgentsTool(registry AgentTransferRegistry) *tool.BaseTool {
	paramSchema := model.ToolParameterSpec{
		"type":       "object",
		"properties": map[string]any{},
	}

	executeFn := func(ctx context.Context, args json.RawMessage) (string, error) {
		agents, err := registry.ListAgents(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to list agents: %w", err)
		}

		if len(agents) == 0 {
			return "No agents are available", nil
		}

		// Format the response
		result := "Available agents:\n\n"
		for _, agent := range agents {
			result += fmt.Sprintf("ID: %s\nName: %s\nDescription: %s\n\n",
				agent.ID,
				agent.Name,
				agent.Description,
			)
		}

		return result, nil
	}

	return tool.NewBaseTool(
		"list_agents",
		"Lists all available agents that you can transfer tasks to using the transfer_to_agent tool.",
		paramSchema,
		executeFn,
	)
}
