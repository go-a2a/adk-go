// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"maps"
	"slices"
	"sync"
)

// Constants for state key prefixes
const (
	// AppPrefix is used for app-level state keys
	AppPrefix = "app:"

	// UserPrefix is used for user-level state keys
	UserPrefix = "user:"

	// TempPrefix is used for temporary state keys
	TempPrefix = "temp:"
)

// State manages session state with change tracking capabilities.
// It provides a dictionary-like interface with delta tracking.
type State struct {
	value map[string]any
	delta map[string]any
	mu    sync.RWMutex
}

// NewState creates a new [State] instance.
func NewState() *State {
	return &State{
		value: make(map[string]any),
		delta: make(map[string]any),
	}
}

// Get retrieves a value from the state, prioritizing delta values.
func (s *State) Get(key string, defualt any) (value any, exists bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check delta first
	if v, ok := s.delta[key]; ok {
		return v, true
	}

	// Then check current value
	if v, ok := s.value[key]; ok {
		return v, true
	}

	return defualt, false
}

// Set updates both current value and delta.
func (s *State) Set(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value[key] = value
	s.delta[key] = value
}

// Contains whether the state dict contains the given key.
func (s *State) Contains(key string) bool {
	return slices.Contains(slices.Sorted(maps.Keys(s.value)), key) || slices.Contains(slices.Sorted(maps.Keys(s.delta)), key)
}

// HasDelta checks if there are pending changes.
func (s *State) HasDelta() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.delta) > 0
}

// Update applies multiple changes to both current and delta states.
func (s *State) Update(updates map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range updates {
		s.value[k] = v
		s.delta[k] = v
	}
}

// ToMap merges current and delta states into a single map.
func (s *State) ToMap() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]any, len(s.value)+len(s.delta))
	// Copy all values
	maps.Copy(result, s.value)
	// Apply deltas (overwriting existing values)
	maps.Copy(result, s.delta)

	return result
}
