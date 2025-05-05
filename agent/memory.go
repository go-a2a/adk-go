// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"sync"
)

// SimpleMemory is a basic in-memory implementation of Memory.
type SimpleMemory struct {
	messages []Message
	mu       sync.RWMutex
	maxSize  int
}

// NewSimpleMemory creates a new SimpleMemory with optional maximum size.
func NewSimpleMemory(maxSize int) *SimpleMemory {
	if maxSize <= 0 {
		maxSize = 100 // Default max size
	}

	return &SimpleMemory{
		messages: make([]Message, 0),
		maxSize:  maxSize,
	}
}

// Add adds a message to memory.
func (m *SimpleMemory) Add(role string, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	message := Message{
		Role:    role,
		Content: content,
	}

	// If we're at capacity, remove the oldest message
	if len(m.messages) >= m.maxSize {
		m.messages = m.messages[1:]
	}

	m.messages = append(m.messages, message)
	return nil
}

// Get retrieves all messages in memory.
func (m *SimpleMemory) Get() ([]Message, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to avoid race conditions
	messages := make([]Message, len(m.messages))
	copy(messages, m.messages)

	return messages, nil
}

// Clear clears all messages from memory.
func (m *SimpleMemory) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.messages = make([]Message, 0)
	return nil
}

// PersistentMemory is a memory that can be saved and loaded.
type PersistentMemory interface {
	Memory

	// Save saves the memory to storage.
	Save() error

	// Load loads the memory from storage.
	Load() error
}
