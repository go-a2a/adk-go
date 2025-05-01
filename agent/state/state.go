// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package state provides state management for ADK agents.
package state

import (
	"context"
	"errors"
	"sync"

	"github.com/go-a2a/adk-go/agent/events"
)

var (
	// ErrStateKeyNotFound indicates that the requested state key was not found.
	ErrStateKeyNotFound = errors.New("state key not found")

	// ErrInvalidStateValue indicates that the state value could not be converted to the requested type.
	ErrInvalidStateValue = errors.New("invalid state value type")
)

// Scope defines the scope of state data.
type Scope string

const (
	// ScopeGlobal indicates that state is shared across all sessions.
	ScopeGlobal Scope = "global"

	// ScopeSession indicates that state is shared across agents within a session.
	ScopeSession Scope = "session"

	// ScopeAgent indicates that state is specific to an agent.
	ScopeAgent Scope = "agent"
)

// StateLayer provides an interface for accessing and updating state.
type StateLayer interface {
	// Get retrieves a value from the state layer.
	Get(ctx context.Context, scope Scope, id, key string) (any, error)

	// Set updates a value in the state layer.
	Set(ctx context.Context, scope Scope, id, key string, value any) error

	// Update atomically updates multiple keys in the state layer.
	Update(ctx context.Context, scope Scope, id string, updates map[string]any) error

	// Delete removes a key from the state layer.
	Delete(ctx context.Context, scope Scope, id, key string) error

	// Clear removes all keys for the given scope and ID.
	Clear(ctx context.Context, scope Scope, id string) error
}

// MemoryStateLayer is an in-memory implementation of StateLayer.
type MemoryStateLayer struct {
	globalState  map[string]any
	sessionState map[string]map[string]any
	agentState   map[string]map[string]any
	mu           sync.RWMutex
}

// NewMemoryStateLayer creates a new in-memory state layer.
func NewMemoryStateLayer() *MemoryStateLayer {
	return &MemoryStateLayer{
		globalState:  make(map[string]any),
		sessionState: make(map[string]map[string]any),
		agentState:   make(map[string]map[string]any),
	}
}

// Get retrieves a value from the in-memory state layer.
func (m *MemoryStateLayer) Get(ctx context.Context, scope Scope, id, key string) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var stateMap map[string]any
	var ok bool

	switch scope {
	case ScopeGlobal:
		stateMap = m.globalState
	case ScopeSession:
		stateMap, ok = m.sessionState[id]
		if !ok {
			return nil, ErrStateKeyNotFound
		}
	case ScopeAgent:
		stateMap, ok = m.agentState[id]
		if !ok {
			return nil, ErrStateKeyNotFound
		}
	default:
		return nil, errors.New("invalid scope")
	}

	value, ok := stateMap[key]
	if !ok {
		return nil, ErrStateKeyNotFound
	}

	return value, nil
}

// Set updates a value in the in-memory state layer.
func (m *MemoryStateLayer) Set(ctx context.Context, scope Scope, id, key string, value any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var stateMap map[string]any

	switch scope {
	case ScopeGlobal:
		stateMap = m.globalState
	case ScopeSession:
		stateMap, ok := m.sessionState[id]
		if !ok {
			stateMap = make(map[string]any)
			m.sessionState[id] = stateMap
		}
	case ScopeAgent:
		stateMap, ok := m.agentState[id]
		if !ok {
			stateMap = make(map[string]any)
			m.agentState[id] = stateMap
		}
	default:
		return errors.New("invalid scope")
	}

	stateMap[key] = value
	return nil
}

// Update atomically updates multiple keys in the in-memory state layer.
func (m *MemoryStateLayer) Update(ctx context.Context, scope Scope, id string, updates map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var stateMap map[string]any

	switch scope {
	case ScopeGlobal:
		stateMap = m.globalState
	case ScopeSession:
		stateMap, ok := m.sessionState[id]
		if !ok {
			stateMap = make(map[string]any)
			m.sessionState[id] = stateMap
		}
	case ScopeAgent:
		stateMap, ok := m.agentState[id]
		if !ok {
			stateMap = make(map[string]any)
			m.agentState[id] = stateMap
		}
	default:
		return errors.New("invalid scope")
	}

	for key, value := range updates {
		stateMap[key] = value
	}

	return nil
}

// Delete removes a key from the in-memory state layer.
func (m *MemoryStateLayer) Delete(ctx context.Context, scope Scope, id, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var stateMap map[string]any
	var ok bool

	switch scope {
	case ScopeGlobal:
		stateMap = m.globalState
	case ScopeSession:
		stateMap, ok = m.sessionState[id]
		if !ok {
			return nil // Already doesn't exist
		}
	case ScopeAgent:
		stateMap, ok = m.agentState[id]
		if !ok {
			return nil // Already doesn't exist
		}
	default:
		return errors.New("invalid scope")
	}

	delete(stateMap, key)
	return nil
}

// Clear removes all keys for the given scope and ID.
func (m *MemoryStateLayer) Clear(ctx context.Context, scope Scope, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch scope {
	case ScopeGlobal:
		m.globalState = make(map[string]any)
	case ScopeSession:
		delete(m.sessionState, id)
	case ScopeAgent:
		delete(m.agentState, id)
	default:
		return errors.New("invalid scope")
	}

	return nil
}

// StateManager handles state operations and events for an agent.
type StateManager struct {
	stateLayer StateLayer
	sessionID  string
	agentID    string

	// Function to emit state change events
	emitEvent func(*events.Event) error
}

// NewStateManager creates a new state manager.
func NewStateManager(stateLayer StateLayer, sessionID, agentID string, emitEvent func(*events.Event) error) *StateManager {
	return &StateManager{
		stateLayer: stateLayer,
		sessionID:  sessionID,
		agentID:    agentID,
		emitEvent:  emitEvent,
	}
}

// GetGlobal gets a value from global state.
func (m *StateManager) GetGlobal(ctx context.Context, key string) (any, error) {
	return m.stateLayer.Get(ctx, ScopeGlobal, "", key)
}

// GetSession gets a value from session state.
func (m *StateManager) GetSession(ctx context.Context, key string) (any, error) {
	return m.stateLayer.Get(ctx, ScopeSession, m.sessionID, key)
}

// GetAgent gets a value from agent state.
func (m *StateManager) GetAgent(ctx context.Context, key string) (any, error) {
	return m.stateLayer.Get(ctx, ScopeAgent, m.agentID, key)
}

// SetGlobal sets a value in global state.
func (m *StateManager) SetGlobal(ctx context.Context, key string, value any) error {
	if err := m.stateLayer.Set(ctx, ScopeGlobal, "", key, value); err != nil {
		return err
	}

	updates := map[string]any{key: value}
	event, err := events.NewStateChangeEvent(m.sessionID, m.agentID, updates)
	if err != nil {
		return err
	}

	return m.emitEvent(event)
}

// SetSession sets a value in session state.
func (m *StateManager) SetSession(ctx context.Context, key string, value any) error {
	if err := m.stateLayer.Set(ctx, ScopeSession, m.sessionID, key, value); err != nil {
		return err
	}

	updates := map[string]any{key: value}
	event, err := events.NewStateChangeEvent(m.sessionID, m.agentID, updates)
	if err != nil {
		return err
	}

	return m.emitEvent(event)
}

// SetAgent sets a value in agent state.
func (m *StateManager) SetAgent(ctx context.Context, key string, value any) error {
	if err := m.stateLayer.Set(ctx, ScopeAgent, m.agentID, key, value); err != nil {
		return err
	}

	updates := map[string]any{key: value}
	event, err := events.NewStateChangeEvent(m.sessionID, m.agentID, updates)
	if err != nil {
		return err
	}

	return m.emitEvent(event)
}

// UpdateGlobal updates multiple values in global state.
func (m *StateManager) UpdateGlobal(ctx context.Context, updates map[string]any) error {
	if err := m.stateLayer.Update(ctx, ScopeGlobal, "", updates); err != nil {
		return err
	}

	event, err := events.NewStateChangeEvent(m.sessionID, m.agentID, updates)
	if err != nil {
		return err
	}

	return m.emitEvent(event)
}

// UpdateSession updates multiple values in session state.
func (m *StateManager) UpdateSession(ctx context.Context, updates map[string]any) error {
	if err := m.stateLayer.Update(ctx, ScopeSession, m.sessionID, updates); err != nil {
		return err
	}

	event, err := events.NewStateChangeEvent(m.sessionID, m.agentID, updates)
	if err != nil {
		return err
	}

	return m.emitEvent(event)
}

// UpdateAgent updates multiple values in agent state.
func (m *StateManager) UpdateAgent(ctx context.Context, updates map[string]any) error {
	if err := m.stateLayer.Update(ctx, ScopeAgent, m.agentID, updates); err != nil {
		return err
	}

	event, err := events.NewStateChangeEvent(m.sessionID, m.agentID, updates)
	if err != nil {
		return err
	}

	return m.emitEvent(event)
}

// DeleteGlobal deletes a key from global state.
func (m *StateManager) DeleteGlobal(ctx context.Context, key string) error {
	return m.stateLayer.Delete(ctx, ScopeGlobal, "", key)
}

// DeleteSession deletes a key from session state.
func (m *StateManager) DeleteSession(ctx context.Context, key string) error {
	return m.stateLayer.Delete(ctx, ScopeSession, m.sessionID, key)
}

// DeleteAgent deletes a key from agent state.
func (m *StateManager) DeleteAgent(ctx context.Context, key string) error {
	return m.stateLayer.Delete(ctx, ScopeAgent, m.agentID, key)
}

// ClearGlobal clears all global state.
func (m *StateManager) ClearGlobal(ctx context.Context) error {
	return m.stateLayer.Clear(ctx, ScopeGlobal, "")
}

// ClearSession clears all session state.
func (m *StateManager) ClearSession(ctx context.Context) error {
	return m.stateLayer.Clear(ctx, ScopeSession, m.sessionID)
}

// ClearAgent clears all agent state.
func (m *StateManager) ClearAgent(ctx context.Context) error {
	return m.stateLayer.Clear(ctx, ScopeAgent, m.agentID)
}

