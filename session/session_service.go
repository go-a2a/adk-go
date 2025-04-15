// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"time"

	"github.com/go-a2a/adk-go/event"
)

// SessionService is an interface for managing sessions and their events.
type SessionService interface {
	// CreateSession creates a new session with the given parameters.
	CreateSession(ctx context.Context, appName, userID string, sessionID string) (*Session, error)

	// GetSession retrieves a specific session.
	// If maxEvents is > 0, only return the last maxEvents events.
	// If since is not nil, only return events after the given time.
	GetSession(ctx context.Context, appName, userID, sessionID string, maxEvents int, since *time.Time) (*Session, error)

	// ListSessions lists all sessions for a user/app.
	ListSessions(ctx context.Context, appName, userID string) ([]*Session, error)

	// DeleteSession removes a specific session.
	DeleteSession(ctx context.Context, appName, userID, sessionID string) error

	// CloseSession marks a session as closed.
	CloseSession(ctx context.Context, appName, userID, sessionID string) error

	// AppendEvent adds an event to a session and updates session state.
	AppendEvent(ctx context.Context, appName, userID, sessionID string, e event.Event) error

	// ListEvents retrieves events within a session.
	ListEvents(ctx context.Context, appName, userID, sessionID string, maxEvents int, since *time.Time) ([]event.Event, error)
}

// BaseSessionService provides a partial implementation of SessionService.
type BaseSessionService struct{}

// CloseSession is a default implementation that simply marks a session closed.
func (b *BaseSessionService) CloseSession(ctx context.Context, appName, userID, sessionID string) error {
	// Default implementation is a no-op
	return nil
}

// updateSessionState applies event state changes to the session state.
func updateSessionState(s *Session, e event.Event) {
	// Check if the event has state changes
	stateAction, ok := e.GetStateAction()
	if !ok {
		return
	}

	// Apply state changes from the event
	s.State.Update(stateAction.Changes)
}
