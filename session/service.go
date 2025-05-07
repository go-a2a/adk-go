// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"time"

	"github.com/go-a2a/adk-go/types"
)

// Service defines the interface for session management.
type Service interface {
	// CreateSession creates a new session.
	CreateSession(ctx context.Context, appName, userID, sessionID string, state map[string]any) (types.Session, error)

	// GetSession retrieves a session by ID.
	GetSession(ctx context.Context, appName, userID, sessionID string, config *GetSessionConfig) (types.Session, error)

	// ListSessions lists all sessions for a user.
	ListSessions(ctx context.Context, appName, userID string) (*ListSessionsResponse, error)

	// DeleteSession deletes a session.
	DeleteSession(ctx context.Context, appName, userID, sessionID string) error

	// AppendEvent appends an event to a session.
	AppendEvent(ctx context.Context, session types.Session, event *types.Event) (*types.Event, error)

	// ListEvents lists events for a session.
	ListEvents(ctx context.Context, appName, userID, sessionID string) (*ListEventsResponse, error)
}

// GetSessionConfig contains options for retrieving a session.
type GetSessionConfig struct {
	// NumRecentEvents specifies the number of most recent events to include.
	NumRecentEvents int

	// AfterTimestamp specifies to only include events after this timestamp.
	AfterTimestamp time.Time
}

// ListSessionsResponse contains the response for listing sessions.
type ListSessionsResponse struct {
	// Sessions is the list of sessions.
	Sessions []*session
}

// ListEventsResponse contains the response for listing events.
type ListEventsResponse struct {
	// Events is the list of events.
	Events []*types.Event
}
