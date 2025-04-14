// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// Agent represents a basic agent in the Agent Development Kit.
type Agent struct {
	name        string
	model       model.Model
	instruction string
	description string
	tools       []tool.Tool
	subAgents   []Agent
}

// NewAgent creates a new Agent with the provided configuration.
func NewAgent(name string, model model.Model, instruction, description string, tools []tool.Tool) *Agent {
	return &Agent{
		name:        name,
		model:       model,
		instruction: instruction,
		description: description,
		tools:       tools,
	}
}

// WithSubAgents adds sub-agents to this agent.
func (a *Agent) WithSubAgents(subAgents ...Agent) *Agent {
	a.subAgents = append(a.subAgents, subAgents...)
	return a
}

// Name returns the agent's name.
func (a *Agent) Name() string {
	return a.name
}

// Process handles a user message and returns a response.
func (a *Agent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "agent.Process")
	defer span.End()

	span.SetAttributes(attribute.String("agent.name", a.name))

	// If the agent has a model, process using RunWithTools
	if a.model != nil {
		return a.RunWithTools(ctx, msg)
	}

	// If we have sub-agents, try to delegate to appropriate sub-agent
	if len(a.subAgents) > 0 {
		// In a more sophisticated implementation, we would have logic
		// to select the most appropriate sub-agent
		for _, subAgent := range a.subAgents {
			resp, err := subAgent.Process(ctx, msg)
			if err == nil {
				return resp, nil
			}
			// Log the error but continue trying other sub-agents
			observability.Warn(ctx, "Sub-agent processing failed",
				slog.String("sub_agent", subAgent.Name()),
				slog.String("error", err.Error()))
		}
	}

	return message.Message{}, fmt.Errorf("agent '%s' has no model or viable sub-agents to process message", a.name)
}

// RunWithTools executes a request with the available tools.
func (a *Agent) RunWithTools(ctx context.Context, req message.Message) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "agent.RunWithTools")
	defer span.End()

	span.SetAttributes(attribute.String("agent.name", a.name))

	if a.model == nil {
		return message.Message{}, fmt.Errorf("agent '%s' has no model configured", a.name)
	}

	// Create message context with system instruction
	messages := []message.Message{}

	// Add system instruction if provided
	if a.instruction != "" {
		messages = append(messages, message.NewSystemMessage(a.instruction))
	}

	// Add the user request
	messages = append(messages, req)

	// Prepare tool definitions
	var toolDefs []model.ToolDefinition
	if len(a.tools) > 0 {
		toolDefs = make([]model.ToolDefinition, len(a.tools))
		for i, t := range a.tools {
			toolDefs[i] = t.ToToolDefinition()
		}
	}

	// Generate response with tools
	resp, err := a.model.GenerateWithTools(ctx, messages, toolDefs)
	if err != nil {
		return message.Message{}, fmt.Errorf("model generation failed: %w", err)
	}

	// Process any tool calls in the response
	if len(resp.ToolCalls) > 0 {
		observability.Info(ctx, "Processing tool calls",
			slog.Int("num_calls", len(resp.ToolCalls)))

		// Execute each tool call
		for i, tc := range resp.ToolCalls {
			var tool tool.Tool
			for _, t := range a.tools {
				if t.Name() == tc.Name {
					tool = t
					break
				}
			}

			if tool == nil {
				observability.Warn(ctx, "Tool not found",
					slog.String("tool_name", tc.Name))
				continue
			}

			// Execute the tool
			result, err := tool.Execute(ctx, tc.Arguments)

			// Record the result
			resp.ToolCalls[i].Result = message.ToolResult{
				Content: result,
			}

			if err != nil {
				resp.ToolCalls[i].Result.Error = err.Error()
			}
		}

		// Add the response with tool results to messages
		messages = append(messages, resp)

		// Generate a final response that includes tool results
		finalResp, err := a.model.Generate(ctx, messages)
		if err != nil {
			return resp, nil // Return the original response with tool results if final generation fails
		}

		// Transfer any relevant metadata from the tool response
		finalResp.ToolCalls = resp.ToolCalls

		return finalResp, nil
	}

	return resp, nil
}
