// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"maps"
	"sync"
)

// Constants for different state key prefixes
const (
	// AppPrefix is the prefix for application state keys
	AppPrefix = "app:"

	// UserPrefix is the prefix for user state keys
	UserPrefix = "user:"

	// TempPrefix is the prefix for temporary state keys
	TempPrefix = "temp:"
)

// State maintains the current value of a state dictionary and any pending deltas
// that haven't been committed yet.
type State struct {
	// mu protects concurrent access to fields
	mu sync.RWMutex

	// value is the current value of the state dict
	value map[string]any

	// delta is the pending change to the current value that hasn't been committed
	delta map[string]any
}

// NewState creates a new State with the given value and delta maps.
func NewState(value map[string]any, delta map[string]any) *State {
	if value == nil {
		value = make(map[string]any)
	}
	if delta == nil {
		delta = make(map[string]any)
	}

	return &State{
		value: value,
		delta: delta,
	}
}

// Get returns the value for the given key, prioritizing delta values
// over the base values.
func (s *State) Get(key string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check delta first
	if val, ok := s.delta[key]; ok {
		return val, true
	}

	// Then check value
	val, ok := s.value[key]
	return val, ok
}

// GetWithDefault returns the value for the given key, or the default value if
// the key doesn't exist.
func (s *State) GetWithDefault(key string, defaultVal any) any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check delta first
	if val, ok := s.delta[key]; ok {
		return val
	}

	// Then check value
	if val, ok := s.value[key]; ok {
		return val
	}

	return defaultVal
}

// Set sets the value for the given key, updating both value and delta.
// TODO: Consider updating only delta, with value updated at commit time.
func (s *State) Set(key string, val any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.value[key] = val
	s.delta[key] = val
}

// Has checks if the state contains the given key.
func (s *State) Has(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, inValue := s.value[key]
	_, inDelta := s.delta[key]

	return inValue || inDelta
}

// HasDelta checks if there are any pending changes.
func (s *State) HasDelta() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.delta) > 0
}

// Update updates the state with the given delta, affecting both value and delta.
func (s *State) Update(update map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range update {
		s.value[k] = v
		s.delta[k] = v
	}
}

// ToMap returns a map representation of the state, with delta values
// taking precedence over base values.
func (s *State) ToMap() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]any, len(s.value)+len(s.delta))

	// Copy value first
	maps.Copy(result, s.value)

	// Then overlay delta values
	maps.Copy(result, s.delta)

	return result
}

// ClearDelta clears any pending changes, usually called after committing changes
// to the persistent storage.
func (s *State) ClearDelta() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.delta = make(map[string]any)
}

// GetDelta returns just the pending changes.
func (s *State) GetDelta() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]any, len(s.delta))
	maps.Copy(result, s.delta)

	return result
}

// ApplyDelta applies all pending changes to the base state and clears the delta.
func (s *State) ApplyDelta() {
	s.mu.Lock()
	defer s.mu.Unlock()

	maps.Copy(s.value, s.delta)

	s.delta = make(map[string]any)
}

// GetApp retrieves a value with the app prefix.
func (s *State) GetApp(key string) (any, bool) {
	return s.Get(AppPrefix + key)
}

// SetApp sets a value with the app prefix.
func (s *State) SetApp(key string, val any) {
	s.Set(AppPrefix+key, val)
}

// GetUser retrieves a value with the user prefix.
func (s *State) GetUser(key string) (any, bool) {
	return s.Get(UserPrefix + key)
}

// SetUser sets a value with the user prefix.
func (s *State) SetUser(key string, val any) {
	s.Set(UserPrefix+key, val)
}

// GetTemp retrieves a value with the temp prefix.
func (s *State) GetTemp(key string) (any, bool) {
	return s.Get(TempPrefix + key)
}

// SetTemp sets a value with the temp prefix.
func (s *State) SetTemp(key string, val any) {
	s.Set(TempPrefix+key, val)
}
