// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package models

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
)

// GeneratorFunc represents a function that generates a message based on the model ID, input messages, and generation options.
type GeneratorFunc func(ctx context.Context, modelID string, messages []message.Message, opts model.GenerateOptions) (message.Message, error)

// Model provides a common implementation for model functions.
type Model struct {
	modelID      string
	provider     model.ModelProvider
	capabilities map[model.ModelCapability]bool
	generator    GeneratorFunc
	mu           sync.RWMutex
}

// NewBaseModel creates a new BaseModel instance.
func NewBaseModel(modelID string, provider model.ModelProvider, capabilities []model.ModelCapability, generator GeneratorFunc) *Model {
	capMap := make(map[model.ModelCapability]bool)
	for _, c := range capabilities {
		capMap[c] = true
	}

	return &Model{
		modelID:      modelID,
		provider:     provider,
		capabilities: capMap,
		generator:    generator,
	}
}

// Generate implements the Model interface.
func (m *Model) Generate(ctx context.Context, messages []message.Message) (message.Message, error) {
	return m.GenerateWithOptions(ctx, messages, model.DefaultGenerateOptions())
}

// GenerateWithOptions implements the Model interface.
func (m *Model) GenerateWithOptions(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	// Basic validation
	if len(messages) == 0 {
		return message.Message{}, fmt.Errorf("no messages provided")
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return message.Message{}, ctx.Err()
	default:
		// Continue processing
	}

	// Clone messages to avoid modifying the original
	clonedMessages := make([]message.Message, len(messages))
	for i, msg := range messages {
		clonedMessages[i] = msg.Clone()
	}

	// If streaming is requested but not supported, return an error
	if opts.Stream && !m.HasCapability(model.ModelCapabilityStreaming) {
		return message.Message{}, fmt.Errorf("streaming not supported by model %s", m.modelID)
	}

	return m.generator(ctx, m.modelID, clonedMessages, opts)
}

// GenerateWithTools implements the Model interface.
func (m *Model) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	if !m.HasCapability(model.ModelCapabilityToolCalling) && !m.HasCapability(model.ModelCapabilityFunctionCalling) {
		return message.Message{}, fmt.Errorf("tool calling not supported by model %s", m.modelID)
	}

	// Implementation will be provided by specific model implementations
	return message.Message{}, fmt.Errorf("not implemented")
}

// GenerateStream implements the Model interface.
func (m *Model) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	if !m.HasCapability(model.ModelCapabilityStreaming) {
		return fmt.Errorf("streaming not supported by model %s", m.modelID)
	}

	// Implementation will be provided by specific model implementations
	return fmt.Errorf("not implemented")
}

// ModelID implements the Model interface.
func (m *Model) ModelID() string {
	return m.modelID
}

// Provider implements the Model interface.
func (m *Model) Provider() model.ModelProvider {
	return m.provider
}

// HasCapability implements the Model interface.
func (m *Model) HasCapability(capability model.ModelCapability) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.capabilities[capability]
}
