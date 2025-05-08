// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
)

// MemoryService defines the interface for memory services.
//
// A session may be added multiple times during its lifetime.
type MemoryService interface {
	// AddSessionToMemory adds the contents of a session to memory.
	AddSessionToMemory(ctx context.Context, session Session) error

	// SearchMemory searches for sessions that match the query.
	SearchMemory(ctx context.Context, appName, userID, query string) (*MemorySearchResponse, error)
}

// MemoryResult represents a single search result from memory.
type MemoryResult struct {
	// SessionID is the ID of the session where this memory was stored.
	SessionID string `json:"session_id"`

	// Events are the events associated with this memory item.
	Events []*Event `json:"events"`
}

// MemorySearchResponse represents the response from a memory search.
type MemorySearchResponse struct {
	// Results are the memory items matching the search.
	Memories []*MemoryResult `json:"memories"`
}
