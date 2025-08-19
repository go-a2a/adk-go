// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"time"
)

// GetSessionConfig is the configuration of getting a session.
type GetSessionConfig struct {
	NumRecentEvents int
	AfterTimestamp  time.Time
}

// ListSessionsResponse is the response of listing sessions.
//
// The events and states are not set within each Session object.
type ListSessionsResponse struct {
	Sessions []Session
}

// ListEventsResponse is the response of listing events in a session.
type ListEventsResponse struct {
	Events        []*Event
	NextPageToken string
}

// SessionService is an interface for managing sessions and their events.
type SessionService interface {
	// CreateSession creates a new session with the given parameters.
	CreateSession(ctx context.Context, appName, userID, sessionID string, state map[string]any) (Session, error)

	// GetSession retrieves a specific session.
	// If maxEvents is > 0, only return the last maxEvents events.
	// If since is not nil, only return events after the given time.
	GetSession(ctx context.Context, appName, userID, sessionID string, config *GetSessionConfig) (Session, error)

	// ListSessions lists all sessions for a user/app.
	ListSessions(ctx context.Context, appName, userID string) ([]Session, error)

	// DeleteSession removes a specific session.
	DeleteSession(ctx context.Context, appName, userID, sessionID string) error

	// // CloseSession marks a session as closed.
	// CloseSession(ctx context.Context, appName, userID, sessionID string) error

	// // AppendEvent adds an event to a session and updates session state.
	AppendEvent(ctx context.Context, sess Session, event *Event) (*Event, error)

	// ListEvents retrieves events within a session.
	ListEvents(ctx context.Context, appName, userID, sessionID string, maxEvents int, since *time.Time) ([]Event, error)
}
