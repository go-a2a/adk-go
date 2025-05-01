// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	// ErrInvalidEventType indicates that the event type is invalid for the requested operation.
	ErrInvalidEventType = errors.New("invalid event type")
)

// generateID generates a unique ID for an event.
func generateID() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		// This should never happen in practice
		panic("failed to generate random ID: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}

// EventHandler is a function that processes an event.
type EventHandler func(event *Event) error

// EventFilter is a function that filters events.
type EventFilter func(event *Event) bool

// FilterByType creates a filter that only passes events of the specified type.
func FilterByType(eventType EventType) EventFilter {
	return func(event *Event) bool {
		return event.Type == eventType
	}
}

// FilterByAgent creates a filter that only passes events from the specified agent.
func FilterByAgent(agentID string) EventFilter {
	return func(event *Event) bool {
		return event.AgentID == agentID
	}
}

// FilterByParent creates a filter that only passes events with the specified parent.
func FilterByParent(parentEventID string) EventFilter {
	return func(event *Event) bool {
		return event.ParentEventID == parentEventID
	}
}

// CombineFilters combines multiple filters with AND logic.
func CombineFilters(filters ...EventFilter) EventFilter {
	return func(event *Event) bool {
		for _, filter := range filters {
			if !filter(event) {
				return false
			}
		}
		return true
	}
}