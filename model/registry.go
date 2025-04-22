// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"regexp"
	"sync"
)

// init registers the built-in model types.
func init() {
	// Register Claude models
	RegisterLLMType(
		[]string{
			`claude-.*`, // General pattern for Claude models
		},
		func(ctx context.Context, apiKey string, modelName string) (Model, error) {
			return NewClaudeLLM(ctx, apiKey, modelName)
		},
	)

	// Register Google/Gemini models
	RegisterLLMType(
		[]string{
			`gemini-.*`,
			`projects\/.*\/locations\/.*\/endpoints\/.*`,
			`projects\/.*\/locations\/.*\/publishers\/google\/models\/gemini-.*`,
		},
		func(ctx context.Context, apiKey string, modelName string) (Model, error) {
			return NewGeminiLLM(ctx, apiKey, modelName)
		},
	)
}

// ModelCreatorFunc is a function type that creates a model instance.
type ModelCreatorFunc func(ctx context.Context, apiKey string, modelName string) (Model, error)

// modelEntry represents a registry entry with a regex pattern and model creator function.
type modelEntry struct {
	pattern *regexp.Regexp
	creator ModelCreatorFunc
}

// LLMRegistry provides a registry for LLM models.
// It allows registering and resolving model implementations based on regex patterns.
type LLMRegistry struct {
	mu         sync.RWMutex
	registry   []modelEntry
	cacheSize  int
	modelCache map[string]ModelCreatorFunc // Simple LRU-like cache
}

var (
	defaultRegistry *LLMRegistry
	once            sync.Once
)

// GetRegistry returns the singleton registry instance.
func GetRegistry() *LLMRegistry {
	once.Do(func() {
		defaultRegistry = NewLLMRegistry(32) // Cache size of 32
	})
	return defaultRegistry
}

// NewLLMRegistry creates a new LLM registry with the specified cache size.
func NewLLMRegistry(cacheSize int) *LLMRegistry {
	return &LLMRegistry{
		registry:   make([]modelEntry, 0),
		cacheSize:  cacheSize,
		modelCache: make(map[string]ModelCreatorFunc),
	}
}

// RegisterLLM registers a model pattern with a creator function.
// If the pattern already exists, it will be updated with the new creator.
func (r *LLMRegistry) RegisterLLM(modelPattern string, creator ModelCreatorFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	regex, err := regexp.Compile(modelPattern)
	if err != nil {
		// Log error and return
		fmt.Printf("Failed to compile regex pattern %s: %v\n", modelPattern, err)
		return
	}

	// Look for existing entry to update
	for i, entry := range r.registry {
		if entry.pattern.String() == modelPattern {
			r.registry[i].creator = creator
			return
		}
	}

	// Add new entry
	r.registry = append(r.registry, modelEntry{
		pattern: regex,
		creator: creator,
	})
}

// ResolveLLM finds the appropriate model creator for the given model name.
// Uses regex pattern matching and caching for performance.
func (r *LLMRegistry) ResolveLLM(modelName string) (ModelCreatorFunc, error) {
	// Check cache first (with read lock)
	r.mu.RLock()
	if creator, ok := r.modelCache[modelName]; ok {
		r.mu.RUnlock()
		return creator, nil
	}
	r.mu.RUnlock()

	// Not in cache, check registry (with read lock)
	r.mu.RLock()
	var matchedCreator ModelCreatorFunc
	for _, entry := range r.registry {
		if entry.pattern.MatchString(modelName) {
			matchedCreator = entry.creator
			break
		}
	}
	r.mu.RUnlock()

	if matchedCreator == nil {
		return nil, fmt.Errorf("model %s not found", modelName)
	}

	// Update cache (with write lock)
	r.mu.Lock()
	if len(r.modelCache) >= r.cacheSize {
		// Simple eviction strategy - clear cache when full
		r.modelCache = make(map[string]ModelCreatorFunc)
	}
	r.modelCache[modelName] = matchedCreator
	r.mu.Unlock()

	return matchedCreator, nil
}

// NewLLM creates a new LLM instance for the given model name.
// It resolves the appropriate model implementation and creates an instance.
func (r *LLMRegistry) NewLLM(ctx context.Context, apiKey string, modelName string) (Model, error) {
	creator, err := r.ResolveLLM(modelName)
	if err != nil {
		return nil, err
	}

	return creator(ctx, apiKey, modelName)
}

// RegisterLLM is a convenience function to register a model pattern.
func RegisterLLM(modelPattern string, creator ModelCreatorFunc) {
	GetRegistry().RegisterLLM(modelPattern, creator)
}

// RegisterLLMType registers multiple patterns for a single model creator.
func RegisterLLMType(patterns []string, creator ModelCreatorFunc) {
	registry := GetRegistry()
	for _, pattern := range patterns {
		registry.RegisterLLM(pattern, creator)
	}
}

// NewLLM is a convenience function to create a new LLM instance.
func NewLLM(ctx context.Context, apiKey string, modelName string) (Model, error) {
	return GetRegistry().NewLLM(ctx, apiKey, modelName)
}
