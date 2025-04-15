// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/go-a2a/adk-go/event"
)

// InMemorySessionService implements SessionService with in-memory storage.
type InMemorySessionService struct {
	BaseSessionService

	mu sync.RWMutex

	// sessions maps app -> user -> sessionID -> Session
	sessions map[string]map[string]map[string]*Session

	// userState maps app -> user -> stateKey -> value
	userState map[string]map[string]map[string]any

	// appState maps app -> stateKey -> value
	appState map[string]map[string]any
}

// NewInMemorySessionService creates a new InMemorySessionService.
func NewInMemorySessionService() *InMemorySessionService {
	return &InMemorySessionService{
		sessions:  make(map[string]map[string]map[string]*Session),
		userState: make(map[string]map[string]map[string]any),
		appState:  make(map[string]map[string]any),
	}
}

// CreateSession creates a new session with the given parameters.
func (s *InMemorySessionService) CreateSession(ctx context.Context, appName, userID, sessionID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate a session ID if not provided
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	// Create app entry if it doesn't exist
	if _, ok := s.sessions[appName]; !ok {
		s.sessions[appName] = make(map[string]map[string]*Session)
	}

	// Create user entry if it doesn't exist
	if _, ok := s.sessions[appName][userID]; !ok {
		s.sessions[appName][userID] = make(map[string]*Session)
	}

	// Check if session already exists
	if _, ok := s.sessions[appName][userID][sessionID]; ok {
		return nil, fmt.Errorf("session %s already exists", sessionID)
	}

	// Create a new session
	session := NewSession(sessionID, appName, userID)

	// Initialize app state
	if _, ok := s.appState[appName]; ok {
		for k, v := range s.appState[appName] {
			session.State.Set(AppPrefix+k, v)
		}
	} else {
		s.appState[appName] = make(map[string]any)
	}

	// Initialize user state
	if _, ok := s.userState[appName]; !ok {
		s.userState[appName] = make(map[string]map[string]any)
	}

	if _, ok := s.userState[appName][userID]; ok {
		for k, v := range s.userState[appName][userID] {
			session.State.Set(UserPrefix+k, v)
		}
	} else {
		s.userState[appName][userID] = make(map[string]any)
	}

	// Store the session
	s.sessions[appName][userID][sessionID] = session

	// Return a copy of the session
	return copySession(session), nil
}

// GetSession retrieves a specific session.
func (s *InMemorySessionService) GetSession(ctx context.Context, appName, userID, sessionID string, maxEvents int, since *time.Time) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if app exists
	appSessions, ok := s.sessions[appName]
	if !ok {
		return nil, fmt.Errorf("app %s not found", appName)
	}

	// Check if user exists
	userSessions, ok := appSessions[userID]
	if !ok {
		return nil, fmt.Errorf("user %s not found", userID)
	}

	// Check if session exists
	session, ok := userSessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	// Create a copy of the session
	result := copySession(session)

	// Filter events if needed
	if since != nil {
		result.Events = result.GetEventsAfterTime(*since)
	} else if maxEvents > 0 {
		result.Events = result.GetLastNEvents(maxEvents)
	}

	return result, nil
}

// ListSessions lists all sessions for a user/app.
func (s *InMemorySessionService) ListSessions(ctx context.Context, appName, userID string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if app exists
	appSessions, ok := s.sessions[appName]
	if !ok {
		return nil, nil
	}

	// Check if user exists
	userSessions, ok := appSessions[userID]
	if !ok {
		return nil, nil
	}

	// Collect all sessions
	sessions := make([]*Session, 0, len(userSessions))
	for _, session := range userSessions {
		sessions = append(sessions, copySession(session))
	}

	return sessions, nil
}

// DeleteSession removes a specific session.
func (s *InMemorySessionService) DeleteSession(ctx context.Context, appName, userID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if app exists
	appSessions, ok := s.sessions[appName]
	if !ok {
		return fmt.Errorf("app %s not found", appName)
	}

	// Check if user exists
	userSessions, ok := appSessions[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}

	// Check if session exists
	if _, ok := userSessions[sessionID]; !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Delete the session
	delete(userSessions, sessionID)

	return nil
}

// AppendEvent adds an event to a session and updates session state.
func (s *InMemorySessionService) AppendEvent(ctx context.Context, appName, userID, sessionID string, e event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if app exists
	appSessions, ok := s.sessions[appName]
	if !ok {
		return fmt.Errorf("app %s not found", appName)
	}

	// Check if user exists
	userSessions, ok := appSessions[userID]
	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}

	// Check if session exists
	session, ok := userSessions[sessionID]
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Add event to session
	session.AddEvent(e)

	// Update session state
	updateSessionState(session, e)

	// Store any app-level state changes
	stateAction, ok := e.GetStateAction()
	if ok {
		for k, v := range stateAction.Changes {
			if len(k) > len(AppPrefix) && k[:len(AppPrefix)] == AppPrefix {
				if _, ok := s.appState[appName]; !ok {
					s.appState[appName] = make(map[string]any)
				}
				s.appState[appName][k[len(AppPrefix):]] = v
			} else if len(k) > len(UserPrefix) && k[:len(UserPrefix)] == UserPrefix {
				if _, ok := s.userState[appName]; !ok {
					s.userState[appName] = make(map[string]map[string]any)
				}
				if _, ok := s.userState[appName][userID]; !ok {
					s.userState[appName][userID] = make(map[string]any)
				}
				s.userState[appName][userID][k[len(UserPrefix):]] = v
			}
		}
	}

	return nil
}

// ListEvents retrieves events within a session.
func (s *InMemorySessionService) ListEvents(ctx context.Context, appName, userID, sessionID string, maxEvents int, since *time.Time) ([]event.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if app exists
	appSessions, ok := s.sessions[appName]
	if !ok {
		return nil, fmt.Errorf("app %s not found", appName)
	}

	// Check if user exists
	userSessions, ok := appSessions[userID]
	if !ok {
		return nil, fmt.Errorf("user %s not found", userID)
	}

	// Check if session exists
	session, ok := userSessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	var events []event.Event

	// Filter events
	if since != nil {
		events = session.GetEventsAfterTime(*since)
	} else if maxEvents > 0 {
		events = session.GetLastNEvents(maxEvents)
	} else {
		events = make([]event.Event, len(session.Events))
		copy(events, session.Events)
	}

	return events, nil
}

// copySession creates a deep copy of a session.
func copySession(s *Session) *Session {
	copy := &Session{
		ID:             s.ID,
		AppName:        s.AppName,
		UserID:         s.UserID,
		LastUpdateTime: s.LastUpdateTime,
		State:          NewState(),
	}

	// Copy events
	copy.Events = make([]event.Event, len(s.Events))
	for i, e := range s.Events {
		copy.Events[i] = e
	}

	// Copy state
	if s.State != nil {
		for k, v := range s.State.ToMap() {
			copy.State.Set(k, v)
		}
	}

	return copy
}
