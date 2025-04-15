// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"github.com/bytedance/sonic"

	"github.com/go-a2a/adk-go/message"
)

// ModelProvider represents the provider of a language model.
type ModelProvider string

const (
	// ModelProviderGoogle represents Google AI models.
	ModelProviderGoogle ModelProvider = "google"
	// ModelProviderOpenAI represents OpenAI models.
	ModelProviderOpenAI ModelProvider = "openai"
	// ModelProviderAnthropic represents Anthropic models.
	ModelProviderAnthropic ModelProvider = "anthropic"
	// ModelProviderMock represents mock models for testing.
	ModelProviderMock ModelProvider = "mock"
)

// ModelCapability represents a capability that a model may have.
type ModelCapability string

const (
	// ModelCapabilityToolCalling indicates the model supports tool calling.
	ModelCapabilityToolCalling ModelCapability = "tool_calling"
	// ModelCapabilityVision indicates the model can process images.
	ModelCapabilityVision ModelCapability = "vision"
	// ModelCapabilityJSON indicates the model can output JSON.
	ModelCapabilityJSON ModelCapability = "json"
	// ModelCapabilityStreaming indicates the model supports streaming responses.
	ModelCapabilityStreaming ModelCapability = "streaming"
	// ModelCapabilityFunctionCalling indicates the model supports function calling.
	ModelCapabilityFunctionCalling ModelCapability = "function_calling"
)

// GenerateOptions represents options for generating responses.
type GenerateOptions struct {
	// Temperature controls randomness in generations (0.0-1.0).
	Temperature float64
	// TopP controls nucleus sampling (0.0-1.0).
	TopP float64
	// MaxTokens controls the maximum length of the generated text.
	MaxTokens int
	// Stream indicates whether to stream the response.
	Stream bool
}

// DefaultGenerateOptions returns the default options for model generation.
func DefaultGenerateOptions() GenerateOptions {
	return GenerateOptions{
		Temperature: 0.7,
		TopP:        1.0,
		MaxTokens:   2048,
		Stream:      false,
	}
}

// ResponseHandler is called for each chunk of a streaming response.
type ResponseHandler func(chunk message.Message)

// Model represents an interface for interacting with language models.
type Model interface {
	// Generate generates a completion based on the provided messages.
	Generate(ctx context.Context, messages []message.Message) (message.Message, error)

	// GenerateWithOptions generates a completion with the specified options.
	GenerateWithOptions(ctx context.Context, messages []message.Message, opts GenerateOptions) (message.Message, error)

	// GenerateWithTools generates a response that can include tool calls.
	GenerateWithTools(ctx context.Context, messages []message.Message, tools []ToolDefinition) (message.Message, error)

	// GenerateStream generates a streaming response and invokes the handler for each chunk.
	GenerateStream(ctx context.Context, messages []message.Message, handler ResponseHandler) error

	// ModelID returns the identifier for this model.
	ModelID() string

	// Provider returns the provider of this model.
	Provider() ModelProvider

	// HasCapability returns whether the model has the specified capability.
	HasCapability(capability ModelCapability) bool
}

// ToolDefinition describes a tool that can be used by the model.
type ToolDefinition struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Parameters  ToolParameterSpec `json:"parameters"`
}

// ToolParameterSpec defines the JSON Schema for tool parameters.
type ToolParameterSpec map[string]any

// ToolDefinitionFromJSON parses a JSON string into a ToolDefinition.
func ToolDefinitionFromJSON(data []byte) (ToolDefinition, error) {
	var toolDef ToolDefinition
	err := sonic.Unmarshal(data, &toolDef)
	return toolDef, err
}

// ToJSON serializes the tool definition to JSON.
func (t ToolDefinition) ToJSON() ([]byte, error) {
	return sonic.Marshal(t)
}
