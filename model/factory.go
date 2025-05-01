// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"strings"
)

// ModelType represents a type of model.
type ModelType = string

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
}

// DefaultModelFactory is the default implementation of ModelFactory.
type DefaultModelFactory struct {
	apiKey string
}

var _ ModelFactory = (*DefaultModelFactory)(nil)

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
		return NewGemini(ctx, f.apiKey, modelName)
	case ModelTypeClaude:
		return NewClaude(ctx, f.apiKey, modelName)
	default:
		return nil, fmt.Errorf("unsupported model: %s", modelName)
	}
}

// getModelType returns the model type for the specified model name.
func getModelType(modelName string) ModelType {
	if strings.HasPrefix(modelName, ModelTypeGemini) {
		return ModelTypeGemini
	}

	if strings.HasPrefix(modelName, ModelTypeClaude) {
		return ModelTypeClaude
	}

	return ""
}
