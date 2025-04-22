// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"strings"
)

// ModelType represents a type of model.
type ModelType string

const (
	// ModelTypeGemini represents Gemini models.
	ModelTypeGemini ModelType = "gemini"
	// ModelTypeClaude represents Claude models.
	ModelTypeClaude ModelType = "claude"
)

// ModelFactory creates models.
type ModelFactory interface {
	// CreateModel creates a model with the specified name.
	CreateModel(ctx context.Context, modelName string) (Model, error)

	// CreateGenerativeModel creates a generative model with the specified name.
	CreateGenerativeModel(ctx context.Context, modelName string) (GenerativeModel, error)
}

// DefaultModelFactory is the default implementation of ModelFactory.
type DefaultModelFactory struct {
	apiKey string
}

// NewModelFactory creates a new model factory.
func NewModelFactory(apiKey string) ModelFactory {
	return &DefaultModelFactory{
		apiKey: apiKey,
	}
}

// CreateModel creates a model with the specified name.
func (f *DefaultModelFactory) CreateModel(ctx context.Context, modelName string) (Model, error) {
	// First try using the registry for more flexible pattern matching
	model, err := NewLLM(ctx, f.apiKey, modelName)
	if err == nil {
		return model, nil
	}

	// Fall back to legacy string prefix matching if registry fails
	modelType := getModelType(modelName)

	switch modelType {
	case ModelTypeGemini:
		return NewGeminiLLM(ctx, f.apiKey, modelName)
	case ModelTypeClaude:
		return NewClaudeLLM(ctx, f.apiKey, modelName)
	default:
		return nil, fmt.Errorf("unsupported model: %s", modelName)
	}
}

// CreateGenerativeModel creates a generative model with the specified name.
func (f *DefaultModelFactory) CreateGenerativeModel(ctx context.Context, modelName string) (GenerativeModel, error) {
	// First try using the registry for more flexible pattern matching
	model, err := NewLLM(ctx, f.apiKey, modelName)
	if err == nil {
		// Try to convert to GenerativeModel
		if genModel, ok := model.(GenerativeModel); ok {
			return genModel, nil
		}
		return nil, fmt.Errorf("model %s does not implement GenerativeModel", modelName)
	}

	// Fall back to legacy string prefix matching if registry fails
	modelType := getModelType(modelName)

	switch modelType {
	case ModelTypeGemini:
		return NewGeminiLLM(ctx, f.apiKey, modelName)
	case ModelTypeClaude:
		return NewClaudeLLM(ctx, f.apiKey, modelName)
	default:
		return nil, fmt.Errorf("unsupported model: %s", modelName)
	}
}

// getModelType returns the model type for the specified model name.
func getModelType(modelName string) ModelType {
	if strings.HasPrefix(modelName, "gemini") {
		return ModelTypeGemini
	}

	if strings.HasPrefix(modelName, "claude") {
		return ModelTypeClaude
	}

	return ""
}
