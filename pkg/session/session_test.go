// Copyright 2025 The ADK Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/go-a2a/adk-go/pkg/event"
)

func TestSession(t *testing.T) {
	id := uuid.NewString()
	s := NewSession(id, "test-app", "test-user")

	if s.ID != id {
		t.Errorf("Session ID = %s, want %s", s.ID, id)
	}

	if s.AppName != "test-app" {
		t.Errorf("Session AppName = %s, want %s", s.AppName, "test-app")
	}

	if s.UserID != "test-user" {
		t.Errorf("Session UserID = %s, want %s", s.UserID, "test-user")
	}

	if s.State == nil {
		t.Error("Session State is nil, want non-nil")
	}

	if len(s.Events) != 0 {
		t.Errorf("Session Events length = %d, want 0", len(s.Events))
	}
}

func TestSessionAddEvent(t *testing.T) {
	s := NewSession(uuid.NewString(), "test-app", "test-user")
	initialTime := s.LastUpdateTime

	// Sleep to ensure time difference
	time.Sleep(1 * time.Millisecond)

	// Create a mock event
	mockEvent := newMockEvent("test-event", map[string]any{})
	s.AddEvent(mockEvent)

	if len(s.Events) != 1 {
		t.Errorf("After AddEvent, Events length = %d, want 1", len(s.Events))
	}

	if !s.LastUpdateTime.After(initialTime) {
		t.Errorf("After AddEvent, LastUpdateTime not updated. Got %v, initial was %v", s.LastUpdateTime, initialTime)
	}
}

func TestSessionGetEventsAfterTime(t *testing.T) {
	s := NewSession(uuid.NewString(), "test-app", "test-user")

	mockEvent1 := newMockEvent("event1", map[string]any{})
	time.Sleep(10 * time.Millisecond)
	timePoint := time.Now()
	time.Sleep(10 * time.Millisecond)
	mockEvent2 := newMockEvent("event2", map[string]any{})
	mockEvent3 := newMockEvent("event3", map[string]any{})

	s.AddEvent(mockEvent1)
	s.AddEvent(mockEvent2)
	s.AddEvent(mockEvent3)

	events := s.GetEventsAfterTime(timePoint)
	if len(events) != 2 {
		t.Errorf("GetEventsAfterTime returned %d events, want 2", len(events))
	}
}

func TestSessionGetLastNEvents(t *testing.T) {
	s := NewSession(uuid.NewString(), "test-app", "test-user")

	mockEvent1 := newMockEvent("event1", map[string]any{})
	mockEvent2 := newMockEvent("event2", map[string]any{})
	mockEvent3 := newMockEvent("event3", map[string]any{})

	s.AddEvent(mockEvent1)
	s.AddEvent(mockEvent2)
	s.AddEvent(mockEvent3)

	events := s.GetLastNEvents(2)
	if len(events) != 2 {
		t.Errorf("GetLastNEvents returned %d events, want 2", len(events))
	}

	if events[0] != mockEvent2 || events[1] != mockEvent3 {
		t.Errorf("GetLastNEvents returned incorrect events")
	}

	// Test edge cases
	if len(s.GetLastNEvents(0)) != 0 {
		t.Errorf("GetLastNEvents(0) should return empty slice")
	}

	if len(s.GetLastNEvents(-1)) != 0 {
		t.Errorf("GetLastNEvents(-1) should return empty slice")
	}

	if len(s.GetLastNEvents(10)) != 3 {
		t.Errorf("GetLastNEvents(10) should return all 3 events")
	}
}

func TestState(t *testing.T) {
	s := NewState()

	// Test Set and Get
	s.Set("key1", "value1")
	val, exists := s.Get("key1")
	if !exists {
		t.Error("After Set, Get returns exists=false")
	}
	if val != "value1" {
		t.Errorf("After Set, Get returns val=%v, want 'value1'", val)
	}

	// Test HasDelta
	if !s.HasDelta() {
		t.Error("After Set, HasDelta returns false")
	}

	// Test Update
	s.Update(map[string]any{
		"key2": "value2",
		"key3": 123,
	})

	val, exists = s.Get("key2")
	if !exists || val != "value2" {
		t.Errorf("After Update, Get('key2') = (%v, %v), want ('value2', true)", val, exists)
	}

	val, exists = s.Get("key3")
	if !exists || val != 123 {
		t.Errorf("After Update, Get('key3') = (%v, %v), want (123, true)", val, exists)
	}

	// Test ToMap
	m := s.ToMap()
	if len(m) != 3 {
		t.Errorf("ToMap returned map with %d entries, want 3", len(m))
	}
	if m["key1"] != "value1" || m["key2"] != "value2" || m["key3"] != 123 {
		t.Errorf("ToMap returned incorrect map: %v", m)
	}

	// Test ClearDelta
	s.ClearDelta()
	if s.HasDelta() {
		t.Error("After ClearDelta, HasDelta returns true")
	}

	// After ClearDelta, values should still be accessible
	val, exists = s.Get("key1")
	if !exists || val != "value1" {
		t.Errorf("After ClearDelta, Get('key1') = (%v, %v), want ('value1', true)", val, exists)
	}
}

func TestStateWithPrefixes(t *testing.T) {
	s := NewState()

	// Add app state
	s.Set(AppPrefix+"app_key1", "app_value1")
	s.Set(AppPrefix+"app_key2", "app_value2")

	// Add user state
	s.Set(UserPrefix+"user_key1", "user_value1")
	s.Set(UserPrefix+"user_key2", "user_value2")

	// Add temporary state
	s.Set(TempPrefix+"temp_key", "temp_value")

	// Add regular state
	s.Set("regular_key", "regular_value")

	// Test GetAppState
	appState := s.GetAppState()
	if len(appState) != 2 {
		t.Errorf("GetAppState returned map with %d entries, want 2", len(appState))
	}
	if appState["app_key1"] != "app_value1" || appState["app_key2"] != "app_value2" {
		t.Errorf("GetAppState returned incorrect map: %v", appState)
	}

	// Test GetUserState
	userState := s.GetUserState()
	if len(userState) != 2 {
		t.Errorf("GetUserState returned map with %d entries, want 2", len(userState))
	}
	if userState["user_key1"] != "user_value1" || userState["user_key2"] != "user_value2" {
		t.Errorf("GetUserState returned incorrect map: %v", userState)
	}

	// Verify ToMap includes all values
	allState := s.ToMap()
	if len(allState) != 6 {
		t.Errorf("ToMap returned map with %d entries, want 6", len(allState))
	}
}

func TestInMemorySessionService(t *testing.T) {
	svc := NewInMemorySessionService()
	ctx := context.Background()

	// Test CreateSession
	session, err := svc.CreateSession(ctx, "test-app", "test-user", "")
	if err != nil {
		t.Fatalf("CreateSession error: %v", err)
	}
	if session.AppName != "test-app" || session.UserID != "test-user" {
		t.Errorf("CreateSession returned session with AppName=%s, UserID=%s, want 'test-app', 'test-user'",
			session.AppName, session.UserID)
	}

	sessionID := session.ID

	// Test GetSession
	retrieved, err := svc.GetSession(ctx, "test-app", "test-user", sessionID, 0, nil)
	if err != nil {
		t.Fatalf("GetSession error: %v", err)
	}
	if retrieved.ID != sessionID {
		t.Errorf("GetSession returned session with ID=%s, want %s", retrieved.ID, sessionID)
	}

	// Test ListSessions
	sessions, err := svc.ListSessions(ctx, "test-app", "test-user")
	if err != nil {
		t.Fatalf("ListSessions error: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("ListSessions returned %d sessions, want 1", len(sessions))
	}

	// Test AppendEvent
	mockEvent := newMockEvent("test-event", map[string]any{
		AppPrefix + "app_key": "app_value",
		UserPrefix + "user_key": "user_value",
	})

	err = svc.AppendEvent(ctx, "test-app", "test-user", sessionID, mockEvent)
	if err != nil {
		t.Fatalf("AppendEvent error: %v", err)
	}

	// Check event was added
	retrieved, err = svc.GetSession(ctx, "test-app", "test-user", sessionID, 0, nil)
	if err != nil {
		t.Fatalf("GetSession after AppendEvent error: %v", err)
	}
	if len(retrieved.Events) != 1 {
		t.Errorf("After AppendEvent, session has %d events, want 1", len(retrieved.Events))
	}

	// Test ListEvents
	events, err := svc.ListEvents(ctx, "test-app", "test-user", sessionID, 0, nil)
	if err != nil {
		t.Fatalf("ListEvents error: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("ListEvents returned %d events, want 1", len(events))
	}

	// Test state propagation
	if val, _ := retrieved.State.Get(AppPrefix + "app_key"); val != "app_value" {
		t.Errorf("After AppendEvent, session.State.Get(AppPrefix+'app_key') = %v, want 'app_value'", val)
	}
	if val, _ := retrieved.State.Get(UserPrefix + "user_key"); val != "user_value" {
		t.Errorf("After AppendEvent, session.State.Get(UserPrefix+'user_key') = %v, want 'user_value'", val)
	}

	// Test DeleteSession
	err = svc.DeleteSession(ctx, "test-app", "test-user", sessionID)
	if err != nil {
		t.Fatalf("DeleteSession error: %v", err)
	}

	// Verify session is deleted
	_, err = svc.GetSession(ctx, "test-app", "test-user", sessionID, 0, nil)
	if err == nil {
		t.Error("GetSession after DeleteSession should return error")
	}
}

// Mock event implementation for testing
type mockEvent struct {
	eventType string
	changes   map[string]any
	timestamp time.Time
}

func newMockEvent(eventType string, changes map[string]any) *mockEvent {
	return &mockEvent{
		eventType: eventType,
		changes:   changes,
		timestamp: time.Now(),
	}
}

func (e *mockEvent) Type() string {
	return e.eventType
}

func (e *mockEvent) Timestamp() time.Time {
	return e.timestamp
}

func (e *mockEvent) GetStateAction() (event.StateAction, bool) {
	if len(e.changes) == 0 {
		return event.StateAction{}, false
	}
	return event.StateAction{Changes: e.changes}, true
}