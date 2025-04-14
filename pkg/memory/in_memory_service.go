// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/go-a2a/adk-go/pkg/event"
)

// InMemoryMemoryService provides an in-memory implementation of the MemoryService
// interface. It is designed for prototyping and testing purposes only.
// It uses keyword matching instead of semantic search.
type InMemoryMemoryService struct {
	// mu protects sessionEvents
	mu sync.RWMutex

	// sessionEvents maps session keys to events
	// The key format is "app_name/user_id/session_id"
	sessionEvents map[string][]*event.Event
}

// NewInMemoryMemoryService creates a new InMemoryMemoryService.
func NewInMemoryMemoryService() *InMemoryMemoryService {
	return &InMemoryMemoryService{
		sessionEvents: make(map[string][]*event.Event),
	}
}

// AddSessionToMemory adds a session to the memory service.
func (s *InMemoryMemoryService) AddSessionToMemory(ctx context.Context, session *Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}

	// Create key in the format "app_name/user_id/session_id"
	key := fmt.Sprintf("%s/%s/%s", session.AppName, session.UserID, session.ID)

	// Filter events to only include those with content
	var eventsWithContent []*event.Event
	for _, event := range session.Events {
		if event != nil && event.Content != "" {
			eventsWithContent = append(eventsWithContent, event)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Store the events
	s.sessionEvents[key] = eventsWithContent

	return nil
}

// SearchMemory searches for sessions that match the query.
func (s *InMemoryMemoryService) SearchMemory(ctx context.Context, appName string, userID string, query string) (*SearchMemoryResponse, error) {
	if appName == "" {
		return nil, fmt.Errorf("app name cannot be empty")
	}

	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	if query == "" {
		return nil, fmt.Errorf("query cannot be empty")
	}

	// Convert query to lowercase for case-insensitive matching
	queryLower := strings.ToLower(query)

	// Split query into keywords
	keywords := strings.Fields(queryLower)

	// Prepare response
	response := &SearchMemoryResponse{
		Memories: []*MemoryResult{},
	}

	// Create prefix for filtering sessions by app and user
	prefix := fmt.Sprintf("%s/%s/", appName, userID)

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Map to track which sessions have already been added to the response
	addedSessions := make(map[string]bool)

	// Search through all sessions
	for key, events := range s.sessionEvents {
		// Skip if the key doesn't start with the prefix
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		// Extract session ID from the key
		parts := strings.Split(key, "/")
		if len(parts) != 3 {
			continue
		}
		sessionID := parts[2]

		// Skip if we've already added this session
		if addedSessions[sessionID] {
			continue
		}

		// Search through events for keyword matches
		var matchedEvents []*event.Event
		for _, e := range events {
			if e == nil {
				continue
			}

			contentLower := strings.ToLower(e.Content)

			// Check if any keyword is in the content
			for _, keyword := range keywords {
				if strings.Contains(contentLower, keyword) {
					matchedEvents = append(matchedEvents, e)
					break
				}
			}
		}

		// Add to response if we found matches
		if len(matchedEvents) > 0 {
			response.Memories = append(response.Memories, &MemoryResult{
				SessionID: sessionID,
				Events:    matchedEvents,
			})

			addedSessions[sessionID] = true
		}
	}

	return response, nil
}
