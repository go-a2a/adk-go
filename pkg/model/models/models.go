// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

// Package models provides implementations of various language models.
package models

import (
	"fmt"

	"github.com/go-a2a/adk-go/pkg/model"
)

// NewModelFromID creates a new model instance from a model ID.
func NewModelFromID(modelID string) (model.Model, error) {
	return GetModel(modelID)
}

// GetSupportedModelProviders returns a list of supported model providers.
func GetSupportedModelProviders() []model.ModelProvider {
	return []model.ModelProvider{
		model.ModelProviderGoogle,
		model.ModelProviderOpenAI,
		model.ModelProviderAnthropic,
		model.ModelProviderMock,
	}
}

// GetDefaultModelID returns the default model ID for a given provider.
func GetDefaultModelID(provider model.ModelProvider) (string, error) {
	switch provider {
	case model.ModelProviderGoogle:
		return DefaultGeminiModel, nil
	case model.ModelProviderOpenAI:
		return DefaultOpenAIModel, nil
	case model.ModelProviderAnthropic:
		return DefaultClaudeModel, nil
	case model.ModelProviderMock:
		return "mock-model", nil
	default:
		return "", fmt.Errorf("unsupported model provider: %s", provider)
	}
}

// NewModelFromProvider creates a new model instance for the given provider using the default model ID.
func NewModelFromProvider(provider model.ModelProvider) (model.Model, error) {
	modelID, err := GetDefaultModelID(provider)
	if err != nil {
		return nil, err
	}
	return NewModelFromID(modelID)
}
