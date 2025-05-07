// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"time"
)

// MemoryService defines the interface for memory services.
type MemoryService interface {
	// AddSessionToMemory adds the contents of a session to memory.
	AddSessionToMemory(ctx context.Context, session Session) error

	// SearchMemory searches for relevant information in memory.
	// Returns a SearchResponse with matching results.
	SearchMemory(ctx context.Context, appName, userID, query string) (*MemorySearchResponse, error)
}

// MemoryResult represents a single search result from memory.
type MemoryResult struct {
	// SessionID is the ID of the session where this memory was stored.
	SessionID string `json:"session_id"`

	// UserID is the ID of the user associated with this memory.
	UserID string `json:"user_id"`

	// Timestamp is when this memory was created.
	Timestamp time.Time `json:"timestamp"`

	// Events are the events associated with this memory item.
	Events []*Event `json:"events"`

	// RelevanceScore indicates how relevant this result is to the search query.
	RelevanceScore float64 `json:"relevance_score"`
}

// MemorySearchResponse holds results from a memory search.
type MemorySearchResponse struct {
	// Results are the memory items matching the search.
	Results []*MemoryResult `json:"results"`
}
