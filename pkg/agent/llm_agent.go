// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// LLMAgent is an agent specifically optimized for language model interaction.
type LLMAgent struct {
	name        string
	model       model.Model
	instruction string
	description string
	tools       []tool.Tool
	subAgents   []any // Can be any Agent implementation
	history     []message.Message
}

// NewLLMAgent creates a new LLM-based agent.
func NewLLMAgent(name string, model model.Model, instruction, description string, tools []tool.Tool) *LLMAgent {
	return &LLMAgent{
		name:        name,
		model:       model,
		instruction: instruction,
		description: description,
		tools:       tools,
		history:     []message.Message{},
	}
}

// WithSubAgents adds sub-agents to this LLM agent.
func (a *LLMAgent) WithSubAgents(subAgents ...any) *LLMAgent {
	a.subAgents = append(a.subAgents, subAgents...)
	return a
}

// Name returns the agent's name.
func (a *LLMAgent) Name() string {
	return a.name
}

// Process handles a user message and returns a response, potentially using tools.
func (a *LLMAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	// Add user message to history
	a.history = append(a.history, msg)

	// Add system instruction if it's the first message
	messages := a.prepareMessages()

	// Convert tools to tool definitions for the model
	toolDefs := make([]model.ToolDefinition, 0, len(a.tools))
	for _, t := range a.tools {
		toolDefs = append(toolDefs, t.ToToolDefinition())
	}

	// Generate response with tools
	response, err := a.model.GenerateWithTools(ctx, messages, toolDefs)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to generate response: %w", err)
	}

	// Check if the model wants to use tools
	if len(response.ToolCalls) > 0 {
		// Process tool calls and get results
		results, err := a.executeToolCalls(ctx, response.ToolCalls)
		if err != nil {
			return message.Message{}, fmt.Errorf("failed to execute tool calls: %w", err)
		}

		// Add the assistant message with tool calls to history
		a.history = append(a.history, response)

		// Add tool results to history
		a.history = append(a.history, results...)

		// Generate a new response with the tool results
		messages = a.prepareMessages()
		finalResponse, err := a.model.Generate(ctx, messages)
		if err != nil {
			return message.Message{}, fmt.Errorf("failed to generate final response: %w", err)
		}

		// Add the final response to history
		a.history = append(a.history, finalResponse)
		return finalResponse, nil
	}

	// If no tool calls, just return the response
	a.history = append(a.history, response)
	return response, nil
}

// prepareMessages prepares the messages for the model, including the system instruction.
func (a *LLMAgent) prepareMessages() []message.Message {
	messages := make([]message.Message, 0, len(a.history)+1)

	// Add system instruction
	if a.instruction != "" {
		messages = append(messages, message.NewSystemMessage(a.instruction))
	}

	// Add conversation history
	messages = append(messages, a.history...)

	return messages
}

// executeToolCalls executes the requested tool calls and returns the results.
func (a *LLMAgent) executeToolCalls(ctx context.Context, toolCalls []message.ToolCall) ([]message.Message, error) {
	results := make([]message.Message, 0, len(toolCalls))

	for _, call := range toolCalls {
		// Find the tool by name
		var selectedTool tool.Tool
		for _, t := range a.tools {
			if t.Name() == call.Name {
				selectedTool = t
				break
			}
		}
		if selectedTool == nil {
			return nil, fmt.Errorf("tool '%s' not found", call.Name)
		}

		// Execute the tool
		result, err := selectedTool.Execute(ctx, call.Args)
		if err != nil {
			// In case of error, create an error result
			errorResult := message.NewToolResultMessage(call.ID, fmt.Sprintf("Error: %v", err))
			results = append(results, errorResult)
			continue
		}

		// Create a tool result message
		resultMsg := message.NewToolResultMessage(call.ID, result)
		results = append(results, resultMsg)
	}

	return results, nil
}

// ClearHistory clears the conversation history.
func (a *LLMAgent) ClearHistory() {
	a.history = []message.Message{}
}
