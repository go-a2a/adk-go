// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"time"

	"github.com/go-a2a/adk-go/types"
)

// sessions represents a session with user interaction history.
type session struct {
	id             string
	appName        string
	userID         string
	events         []*types.Event
	state          map[string]any
	lastUpdateTime time.Time
}

var _ types.Session = (*session)(nil)

// NewSession creates a new session with the given parameters.
func NewSession(appName, userID, id string, state map[string]any, lastUpdateTime time.Time) *session {
	if state == nil {
		state = make(map[string]any)
	}

	return &session{
		id:             id,
		appName:        appName,
		userID:         userID,
		events:         []*types.Event{},
		state:          state,
		lastUpdateTime: lastUpdateTime,
	}
}

// ID returns the session ID.
func (s *session) ID() string {
	return s.id
}

// AppName returns the application name.
func (s *session) AppName() string {
	return s.appName
}

// UserID returns the user ID.
func (s *session) UserID() string {
	return s.userID
}

// Events returns the events in this session.
func (s *session) Events() []*types.Event {
	return s.events
}

// State returns the state of this session.
func (s *session) State() map[string]any {
	return s.state
}

// LastUpdateTime returns the last time this session was updated.
func (s *session) LastUpdateTime() time.Time {
	return s.lastUpdateTime
}

// SetLastUpdateTime sets the last update time of this session.
func (s *session) SetLastUpdateTime(t time.Time) {
	s.lastUpdateTime = t
}

// AddEvent adds an event to this session.
func (s *session) AddEvent(event *types.Event) {
	s.events = append(s.events, event)
}

// GetRecentEvents returns the most recent n events.
func (s *session) GetRecentEvents(n int) []*types.Event {
	if n <= 0 || n > len(s.events) {
		return s.events
	}
	return s.events[len(s.events)-n:]
}

// GetEventsAfter returns events after the given timestamp.
func (s *session) GetEventsAfter(timestamp time.Time) []*types.Event {
	var result []*types.Event
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Timestamp.Before(timestamp) {
			break
		}
		result = append([]*types.Event{s.events[i]}, result...)
	}
	return result
}
