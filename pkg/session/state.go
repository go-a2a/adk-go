// Copyright 2025 The ADK Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
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
	mu    sync.RWMutex
	value map[string]any
	delta map[string]any
}

// NewState creates a new State instance.
func NewState() *State {
	return &State{
		value: make(map[string]any),
		delta: make(map[string]any),
	}
}

// Get retrieves a value from the state, prioritizing delta values.
func (s *State) Get(key string) (value any, exists bool) {
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

	return nil, false
}

// Set updates both current value and delta.
func (s *State) Set(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value[key] = value
	s.delta[key] = value
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
	for k, v := range s.value {
		result[k] = v
	}

	// Apply deltas (overwriting existing values)
	for k, v := range s.delta {
		result[k] = v
	}

	return result
}

// GetAppState returns all keys with AppPrefix.
func (s *State) GetAppState() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]any)

	// Add from value map
	for k, v := range s.value {
		if len(k) > len(AppPrefix) && k[:len(AppPrefix)] == AppPrefix {
			result[k[len(AppPrefix):]] = v
		}
	}

	// Override with delta map
	for k, v := range s.delta {
		if len(k) > len(AppPrefix) && k[:len(AppPrefix)] == AppPrefix {
			result[k[len(AppPrefix):]] = v
		}
	}

	return result
}

// GetUserState returns all keys with UserPrefix for the given app.
func (s *State) GetUserState() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]any)

	// Add from value map
	for k, v := range s.value {
		if len(k) > len(UserPrefix) && k[:len(UserPrefix)] == UserPrefix {
			result[k[len(UserPrefix):]] = v
		}
	}

	// Override with delta map
	for k, v := range s.delta {
		if len(k) > len(UserPrefix) && k[:len(UserPrefix)] == UserPrefix {
			result[k[len(UserPrefix):]] = v
		}
	}

	return result
}

// ClearDelta clears all pending changes.
func (s *State) ClearDelta() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta = make(map[string]any)
}

// CommitDelta applies all pending changes and clears the delta.
func (s *State) CommitDelta() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range s.delta {
		s.value[k] = v
	}

	s.delta = make(map[string]any)
}
