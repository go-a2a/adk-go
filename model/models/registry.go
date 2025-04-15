// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package models

import (
	"fmt"
	"regexp"
	"sync"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
)

// ModelFactory is a function that creates a new model instance.
type ModelFactory func(modelID string) (*genai.Model, error)

// modelRegEntry represents a model registry entry.
type modelRegEntry struct {
	pattern *regexp.Regexp
	factory ModelFactory
}

// Registry is a registry for language models.
type Registry struct {
	mu      sync.RWMutex
	entries []modelRegEntry
	cache   *sync.Map // modelID -> model.Model
}

// NewRegistry creates a new model registry.
func NewRegistry() *Registry {
	return &Registry{
		entries: make([]modelRegEntry, 0),
		cache:   new(sync.Map),
	}
}

// Register registers a model factory with the registry.
func (r *Registry) Register(pattern string, factory ModelFactory) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid model pattern %q: %w", pattern, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = append(r.entries, modelRegEntry{
		pattern: re,
		factory: factory,
	})

	return nil
}

// Resolve resolves a model ID to a ModelFactory.
func (r *Registry) Resolve(modelID string) (ModelFactory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, entry := range r.entries {
		if entry.pattern.MatchString(modelID) {
			return entry.factory, nil
		}
	}

	return nil, fmt.Errorf("no matching model found for %q", modelID)
}

// GetModel returns a model instance for the specified model ID.
func (r *Registry) GetModel(modelID string) (*genai.Model, error) {
	r.mu.RLock()
	if m, ok := r.cache.Load(modelID); ok {
		r.mu.RUnlock()
		return m.(*genai.Model), nil
	}
	r.mu.RUnlock()

	factory, err := r.Resolve(modelID)
	if err != nil {
		return nil, err
	}

	m, err := factory(modelID)
	if err != nil {
		return nil, fmt.Errorf("failed to create model instance for %q: %w", modelID, err)
	}

	r.mu.Lock()
	r.cache.Store(modelID, m)
	r.mu.Unlock()

	return m, nil
}

// DefaultRegistry is the default model registry.
var DefaultRegistry = NewRegistry()

// Register registers a model factory with the default registry.
func Register(pattern string, factory ModelFactory) error {
	return DefaultRegistry.Register(pattern, factory)
}

// GetModel returns a model instance from the default registry.
func GetModel(modelID string) (*genai.Model, error) {
	return DefaultRegistry.GetModel(modelID)
}

// RegisterWithCapabilities is a helper function to create a model factory with specific capabilities.
func RegisterWithCapabilities(pattern string, provider model.ModelProvider, capabilities []model.ModelCapability, generatorFunc GeneratorFunc) error {
	return Register(pattern, func(modelID string) (*genai.Model, error) {
		return NewBaseModel(modelID, provider, capabilities, generatorFunc), nil
	})
}
