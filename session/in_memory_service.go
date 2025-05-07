// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/go-a2a/adk-go/types"
)

// InMemoryService is an in-memory implementation of the [SessionService].
type InMemoryService struct {
	// sessions is a map from app name to a map from user ID to a map from session ID to session.
	sessions map[string]map[string]map[string]*session

	// userState is a map from app name to a map from user ID to a map from key to value.
	userState map[string]map[string]map[string]any

	// appState is a map from app name to a map from key to value.
	appState map[string]map[string]any

	logger *slog.Logger
	mu     sync.RWMutex
}

var _ Service = (*InMemoryService)(nil)

// NewInMemoryService creates a new [InMemoryService].
func NewInMemoryService(opts ...InMemoryOption) *InMemoryService {
	s := &InMemoryService{
		sessions:  make(map[string]map[string]map[string]*session),
		userState: make(map[string]map[string]map[string]any),
		appState:  make(map[string]map[string]any),
		logger:    slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// CreateSession creates a new session.
func (s *InMemoryService) CreateSession(ctx context.Context, appName, userID, sessionID string, state map[string]any) (types.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.InfoContext(ctx, "Creating session",
		slog.String("app_name", appName),
		slog.String("user_id", userID),
		slog.String("session_id", sessionID),
	)

	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	if state == nil {
		state = make(map[string]any)
	}

	ses := NewSession(appName, userID, sessionID, state, time.Now())

	if _, ok := s.sessions[appName]; !ok {
		s.sessions[appName] = make(map[string]map[string]*session)
	}
	if _, ok := s.sessions[appName][userID]; !ok {
		s.sessions[appName][userID] = make(map[string]*session)
	}

	s.sessions[appName][userID][sessionID] = ses

	// Deep copy the session to avoid modifying the stored one
	copiedSession := s.copySession(ses)

	return s.mergeState(appName, userID, copiedSession), nil
}

// GetSession retrieves a session by ID.
func (s *InMemoryService) GetSession(ctx context.Context, appName, userID, sessionID string, config *GetSessionConfig) (types.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.logger.InfoContext(ctx, "Getting session",
		slog.String("app_name", appName),
		slog.String("user_id", userID),
		slog.String("session_id", sessionID),
	)

	if _, ok := s.sessions[appName]; !ok {
		return nil, fmt.Errorf("app %s not found", appName)
	}
	if _, ok := s.sessions[appName][userID]; !ok {
		return nil, fmt.Errorf("user %s not found for app %s", userID, appName)
	}
	if _, ok := s.sessions[appName][userID][sessionID]; !ok {
		return nil, fmt.Errorf("session %s not found for user %s in app %s", sessionID, userID, appName)
	}

	session := s.sessions[appName][userID][sessionID]
	copiedSession := s.copySession(session)

	if config != nil {
		// Filter events based on config
		if config.NumRecentEvents > 0 {
			copiedSession.events = copiedSession.GetRecentEvents(config.NumRecentEvents)
		}
		if !config.AfterTimestamp.IsZero() {
			copiedSession.events = copiedSession.GetEventsAfter(config.AfterTimestamp)
		}
	}

	return s.mergeState(appName, userID, copiedSession), nil
}

// ListSessions lists all sessions for a user.
func (s *InMemoryService) ListSessions(ctx context.Context, appName, userID string) (*ListSessionsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.logger.InfoContext(ctx, "Listing sessions",
		slog.String("app_name", appName),
		slog.String("user_id", userID),
	)

	emptyResponse := &ListSessionsResponse{Sessions: []*session{}}

	if _, ok := s.sessions[appName]; !ok {
		return emptyResponse, nil
	}
	if _, ok := s.sessions[appName][userID]; !ok {
		return emptyResponse, nil
	}

	sessionsWithoutEvents := make([]*session, 0, len(s.sessions[appName][userID]))
	for _, ses := range s.sessions[appName][userID] {
		copiedSession := NewSession(ses.appName, ses.userID, ses.id, make(map[string]any), ses.lastUpdateTime)
		sessionsWithoutEvents = append(sessionsWithoutEvents, copiedSession)
	}

	return &ListSessionsResponse{Sessions: sessionsWithoutEvents}, nil
}

// DeleteSession deletes a session.
func (s *InMemoryService) DeleteSession(ctx context.Context, appName, userID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.InfoContext(ctx, "Deleting session",
		slog.String("app_name", appName),
		slog.String("user_id", userID),
		slog.String("session_id", sessionID),
	)

	if _, ok := s.sessions[appName]; !ok {
		return nil
	}
	if _, ok := s.sessions[appName][userID]; !ok {
		return nil
	}
	if _, ok := s.sessions[appName][userID][sessionID]; !ok {
		return nil
	}

	delete(s.sessions[appName][userID], sessionID)
	return nil
}

// AppendEvent appends an event to a session.
func (s *InMemoryService) AppendEvent(ctx context.Context, ses types.Session, event *types.Event) (*types.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	appName := ses.AppName()
	userID := ses.UserID()
	sessionID := ses.ID()

	s.logger.InfoContext(ctx, "Appending event to session",
		slog.String("app_name", appName),
		slog.String("user_id", userID),
		slog.String("session_id", sessionID),
	)

	// Update the provided session
	ses.AddEvent(event)
	ses.SetLastUpdateTime(event.Timestamp)

	// Update the stored session if it exists
	if _, ok := s.sessions[appName]; !ok {
		return event, nil
	}
	if _, ok := s.sessions[appName][userID]; !ok {
		return event, nil
	}
	if storedSession, ok := s.sessions[appName][userID][sessionID]; ok {
		storedSession.AddEvent(event)
		storedSession.SetLastUpdateTime(event.Timestamp)

		// Update state if there's state delta in the event
		if event.Actions != nil && event.Actions.StateDelta != nil {
			for key, value := range event.Actions.StateDelta {
				if strings.HasPrefix(key, types.AppPrefix) {
					if _, ok := s.appState[appName]; !ok {
						s.appState[appName] = make(map[string]any)
					}
					s.appState[appName][strings.TrimPrefix(key, types.AppPrefix)] = value
				} else if strings.HasPrefix(key, types.UserPrefix) {
					if _, ok := s.userState[appName]; !ok {
						s.userState[appName] = make(map[string]map[string]any)
					}
					if _, ok := s.userState[appName][userID]; !ok {
						s.userState[appName][userID] = make(map[string]any)
					}
					s.userState[appName][userID][strings.TrimPrefix(key, types.UserPrefix)] = value
				}
			}
		}
	}

	return event, nil
}

// ListEvents lists events for a session.
func (s *InMemoryService) ListEvents(ctx context.Context, appName, userID, sessionID string) (*ListEventsResponse, error) {
	// This method is not implemented in the Python version
	return nil, fmt.Errorf("ListEvents is not implemented")
}

// copySession creates a deep copy of a session.
func (s *InMemoryService) copySession(ses *session) *session {
	// Create a new session with the same metadata
	copiedSession := NewSession(ses.appName, ses.userID, ses.id, make(map[string]any), ses.lastUpdateTime)

	// Copy events
	for _, event := range ses.events {
		copiedSession.AddEvent(event)
	}

	// Copy state
	maps.Copy(copiedSession.state, ses.state)

	return copiedSession
}

// mergeState merges app and user state into the session state.
func (s *InMemoryService) mergeState(appName, userID string, ses *session) types.Session {
	// Merge app state
	if appState, ok := s.appState[appName]; ok {
		for key, value := range appState {
			ses.state[types.AppPrefix+key] = value
		}
	}

	// Merge user state
	if userStateByApp, ok := s.userState[appName]; ok {
		if userState, ok := userStateByApp[userID]; ok {
			for key, value := range userState {
				ses.state[types.UserPrefix+key] = value
			}
		}
	}

	return ses
}
