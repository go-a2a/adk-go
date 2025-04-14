// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"time"

	"github.com/go-a2a/adk-go/pkg/event"
)

// Session represents a series of interactions between a user and agents.
// It captures the context and progression of a computational interaction.
type Session struct {
	// ID is the unique identifier for this session
	ID string `json:"id"`

	// AppName is the name of the application
	AppName string `json:"app_name"`

	// UserID is the identifier for the user
	UserID string `json:"user_id"`

	// State is a flexible dictionary to store session state
	State *State `json:"state"`

	// Events is the list of events that happened in this session
	Events []event.Event `json:"events"`

	// LastUpdateTime is the timestamp of the most recent session update
	LastUpdateTime time.Time `json:"last_update_time"`
}

// NewSession creates a new session with the given parameters.
func NewSession(id, appName, userID string) *Session {
	return &Session{
		ID:             id,
		AppName:        appName,
		UserID:         userID,
		State:          NewState(),
		Events:         make([]event.Event, 0),
		LastUpdateTime: time.Now(),
	}
}

// AddEvent appends an event to the session and updates the last update time.
func (s *Session) AddEvent(e event.Event) {
	s.Events = append(s.Events, e)
	s.LastUpdateTime = time.Now()
}

// GetEventsAfterTime returns all events that occurred after the given time.
func (s *Session) GetEventsAfterTime(t time.Time) []event.Event {
	var events []event.Event
	for _, e := range s.Events {
		if e.Timestamp.After(t) {
			events = append(events, e)
		}
	}
	return events
}

// GetLastNEvents returns the last n events from the session.
func (s *Session) GetLastNEvents(n int) []event.Event {
	if n <= 0 {
		return nil
	}

	if n >= len(s.Events) {
		return s.Events
	}

	return s.Events[len(s.Events)-n:]
}
