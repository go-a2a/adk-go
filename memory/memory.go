// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package memory provides a memory service for storing and retrieving agent session data.
// It includes interfaces and implementations for different storage strategies,
// such as in-memory storage and cloud-based retrieval systems.
package memory

import (
	"context"
	"time"

	"github.com/go-a2a/adk-go/event"
)

// MemoryResult represents a single memory retrieval result.
type MemoryResult struct {
	// SessionID is the identifier for the session.
	SessionID string `json:"session_id"`

	// Events contains the events from the session.
	Events []*event.Event `json:"events"`
}

// SearchMemoryResponse represents the response from a memory search.
type SearchMemoryResponse struct {
	// Memories contains the results from the memory search.
	Memories []*MemoryResult `json:"memories"`
}

// Session represents a sequence of events in a conversation.
type Session struct {
	// ID is the unique identifier for the session.
	ID string `json:"id"`

	// AppName is the name of the application associated with the session.
	AppName string `json:"app_name"`

	// UserID is the identifier of the user associated with the session.
	UserID string `json:"user_id"`

	// StartTime is when the session began.
	StartTime time.Time `json:"start_time"`

	// EndTime is when the session ended (zero value if still active).
	EndTime time.Time `json:"end_time,omitempty"`

	// Events contains the events in the session.
	Events []*event.Event `json:"events"`
}

// MemoryService defines the interface for memory services.
type MemoryService interface {
	// AddSessionToMemory adds a session to the memory service.
	// A session can be added multiple times during its lifetime, e.g., after each turn.
	AddSessionToMemory(ctx context.Context, session *Session) error

	// SearchMemory searches for sessions that match the query.
	// Returns sessions that are relevant to the search terms, filtered by app and user.
	SearchMemory(ctx context.Context, appName, userID, query string) (*SearchMemoryResponse, error)
}
