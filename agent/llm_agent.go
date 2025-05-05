// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"strings"
)

// LLMAgent is an agent powered by a large language model.
type LLMAgent struct {
	*BaseAgent

	model       Model
	instruction string
	memory      Memory
}

// Model represents a language model that can generate content.
type Model interface {
	// Generate generates content based on the given prompt.
	Generate(ctx context.Context, prompt string, opts ...ModelOption) (string, error)

	// GenerateStream streams generated content for the given prompt.
	GenerateStream(ctx context.Context, prompt string, opts ...ModelOption) (<-chan StreamChunk, error)
}

// StreamChunk represents a chunk of streaming content.
type StreamChunk struct {
	Content string
	Error   error
	Done    bool
}

// Memory represents a storage for conversation history.
type Memory interface {
	// Add adds a message to memory.
	Add(role string, content string) error

	// Get retrieves all messages in memory.
	Get() ([]Message, error)

	// Clear clears all messages from memory.
	Clear() error
}

// Message represents a message in a conversation.
type Message struct {
	Role    string
	Content string
}

// ModelOption configures model generation.
type ModelOption func(*ModelConfig)

// ModelConfig contains settings for model generation.
type ModelConfig struct {
	Temperature      float64
	MaxTokens        int
	StopSequences    []string
	TopP             float64
	FrequencyPenalty float64
	PresencePenalty  float64
}

// LLMAgentOption configures an LLMAgent.
type LLMAgentOption func(*LLMAgent)

// WithModel sets the agent's language model.
func WithModel(model Model) LLMAgentOption {
	return func(a *LLMAgent) {
		a.model = model
	}
}

// WithInstruction sets the agent's instruction.
func WithInstruction(instruction string) LLMAgentOption {
	return func(a *LLMAgent) {
		a.instruction = instruction
	}
}

// WithMemory sets the agent's memory.
func WithMemory(memory Memory) LLMAgentOption {
	return func(a *LLMAgent) {
		a.memory = memory
	}
}

// NewLLMAgent creates a new LLM agent with the given name and options.
func NewLLMAgent(name string, opts ...LLMAgentOption) *LLMAgent {
	agent := &LLMAgent{
		BaseAgent: NewBaseAgent(name),
	}

	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

// Execute runs the LLM agent with the given input.
func (a *LLMAgent) Execute(ctx context.Context, input any, opts ...RunOption) (Response, error) {
	// Parse run options
	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	// Convert input to string
	inputStr, ok := input.(string)
	if !ok {
		return Response{}, ErrInvalidInput
	}

	// Create callback context
	callbackCtx := NewCallbackContext(a, input, nil)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackBeforeExecution, callbackCtx); err != nil {
		return Response{}, err
	}

	// Add input to memory
	if a.memory != nil && config.MemoryEnabled {
		if err := a.memory.Add("user", inputStr); err != nil {
			return Response{}, err
		}
	}

	// Build prompt with instruction, memory, and tools
	prompt, err := a.buildPrompt(ctx, inputStr)
	if err != nil {
		return Response{}, err
	}

	// Generate response from model
	var result string
	if a.model == nil {
		return Response{}, fmt.Errorf("model not set")
	}

	// Apply model options from run config
	modelOpts := []ModelOption{
		WithModelTemperature(config.Temperature),
		WithModelMaxTokens(config.MaxTokens),
	}

	result, err = a.model.Generate(ctx, prompt, modelOpts...)
	if err != nil {
		return Response{}, err
	}

	// Parse response for tool calls
	response, toolCalls := a.parseResponse(result)

	// Execute any tool calls
	for i, tc := range toolCalls {
		tool := a.FindTool(tc.Name)
		if tool == nil {
			toolCalls[i].Error = ErrToolNotFound
			continue
		}

		// Create tool callback context
		toolCallbackCtx := NewCallbackContext(a, tc.Input, &response).WithToolCall(&toolCalls[i])

		// Trigger before tool execution callbacks
		if err := a.TriggerCallbacks(ctx, CallbackBeforeToolExecution, toolCallbackCtx); err != nil {
			toolCalls[i].Error = err
			continue
		}

		// Execute tool
		output, err := tool.Execute(ctx, tc.Input)
		toolCalls[i].Output = output
		toolCalls[i].Error = err

		// Trigger after tool execution callbacks
		if err := a.TriggerCallbacks(ctx, CallbackAfterToolExecution, toolCallbackCtx); err != nil {
			// Just log errors here, don't fail the whole execution
			a.logger.WarnContext(ctx, "after tool execution callback error", "error", err)
		}
	}

	// Add response to memory
	if a.memory != nil && config.MemoryEnabled {
		if err := a.memory.Add("assistant", response.Content); err != nil {
			return Response{}, err
		}
	}

	response.ToolCalls = toolCalls

	// Update callback context with response
	callbackCtx.Response = &response

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", "error", err)
	}

	return response, nil
}

// buildPrompt builds a prompt for the model.
func (a *LLMAgent) buildPrompt(ctx context.Context, input string) (string, error) {
	var promptBuilder strings.Builder

	// Add instruction
	if a.instruction != "" {
		promptBuilder.WriteString("Instructions:\n")
		promptBuilder.WriteString(a.instruction)
		promptBuilder.WriteString("\n\n")
	}

	// Add tools
	if len(a.tools) > 0 {
		toolsJSON, err := FormatToolsAsJSON(a.tools)
		if err != nil {
			return "", err
		}

		promptBuilder.WriteString("Available tools:\n")
		promptBuilder.WriteString(toolsJSON)
		promptBuilder.WriteString("\n\n")
	}

	// Add memory/conversation history
	if a.memory != nil {
		messages, err := a.memory.Get()
		if err != nil {
			return "", err
		}

		if len(messages) > 0 {
			promptBuilder.WriteString("Conversation history:\n")
			for _, msg := range messages {
				promptBuilder.WriteString(fmt.Sprintf("%s: %s\n", msg.Role, msg.Content))
			}
			promptBuilder.WriteString("\n")
		}
	}

	// Add current input
	promptBuilder.WriteString("User: ")
	promptBuilder.WriteString(input)
	promptBuilder.WriteString("\n\nAssistant: ")

	return promptBuilder.String(), nil
}

// parseResponse parses the model's response for tool calls.
func (a *LLMAgent) parseResponse(result string) (Response, []ToolCall) {
	// Simple response, no tool calls
	return Response{Content: result}, nil

	// In a more complex implementation, we would parse the response to extract tool calls
	// This would typically involve looking for a specific format like JSON blocks indicating
	// tool usage and parsing those into ToolCall objects
}

// IsStreaming returns whether the agent supports streaming.
func (a *LLMAgent) IsStreaming() bool {
	return true
}

// WithModelTemperature sets the temperature for model generation.
func WithModelTemperature(temperature float64) ModelOption {
	return func(c *ModelConfig) {
		c.Temperature = temperature
	}
}

// WithModelMaxTokens sets the maximum tokens for model generation.
func WithModelMaxTokens(maxTokens int) ModelOption {
	return func(c *ModelConfig) {
		c.MaxTokens = maxTokens
	}
}
