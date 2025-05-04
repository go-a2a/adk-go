// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/session"
)

// MemoryService defines the interface for memory services.
type MemoryService interface {
	// AddSessionToMemory adds a session to the memory service.
	// A session can be added multiple times during its lifetime, e.g., after each turn.
	AddSessionToMemory(ctx context.Context, session *session.Session) error

	// SearchMemory searches for sessions that match the query.
	// Returns sessions that are relevant to the search terms, filtered by app and user.
	SearchMemory(ctx context.Context, appName, userID, query string) (*SearchMemoryResponse, error)
}

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
