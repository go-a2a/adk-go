// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package memory

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/google/go-cmp/cmp"
)

// TestInMemoryMemoryService tests the InMemoryMemoryService implementation.
func TestInMemoryMemoryService(t *testing.T) {
	// Create service
	service := NewInMemoryMemoryService()
	
	// Create context
	ctx := context.Background()
	
	// Test session
	session := &Session{
		ID:        "test-session",
		AppName:   "test-app",
		UserID:    "test-user",
		StartTime: time.Now(),
		Events: []*event.Event{
			{
				InvocationID: "id1",
				Author:       "user",
				Content:      "Hello, I need help with Go programming.",
			},
			{
				InvocationID: "id2",
				Author:       "assistant",
				Content:      "I can help you with Go programming. What do you want to know?",
			},
			{
				InvocationID: "id3",
				Author:       "user",
				Content:      "How do I create a goroutine?",
			},
		},
	}
	
	// Add session to memory
	err := service.AddSessionToMemory(ctx, session)
	if err != nil {
		t.Fatalf("Failed to add session to memory: %v", err)
	}
	
	// Test search
	testCases := []struct {
		name        string
		query       string
		wantResults int
		wantContent string
	}{
		{
			name:        "Search for Go",
			query:       "Go programming",
			wantResults: 1,
			wantContent: "Go programming",
		},
		{
			name:        "Search for goroutine",
			query:       "goroutine",
			wantResults: 1,
			wantContent: "goroutine",
		},
		{
			name:        "Search for non-existent term",
			query:       "database",
			wantResults: 0,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Search memory
			res, err := service.SearchMemory(ctx, "test-app", "test-user", tc.query)
			if err != nil {
				t.Fatalf("Failed to search memory: %v", err)
			}
			
			// Check result count
			if len(res.Memories) != tc.wantResults {
				t.Errorf("Expected %d memory results, got %d", tc.wantResults, len(res.Memories))
			}
			
			// Check content if results expected
			if tc.wantResults > 0 && len(res.Memories) > 0 {
				foundMatch := false
				for _, memory := range res.Memories {
					for _, evt := range memory.Events {
						if strings.Contains(evt.Content, tc.wantContent) {
							foundMatch = true
							break
						}
					}
					if foundMatch {
						break
					}
				}
				
				if !foundMatch {
					t.Errorf("Expected to find content containing %q in results", tc.wantContent)
				}
			}
		})
	}
}

// TestVectorMemoryService tests the VectorMemoryService implementation.
func TestVectorMemoryService(t *testing.T) {
	// Create service
	service := NewVectorMemoryService(
		WithSimilarityTopK(3),
		WithDistanceThreshold(0.2),
	)
	
	// Create context
	ctx := context.Background()
	
	// Test session 1
	session1 := &Session{
		ID:        "session1",
		AppName:   "test-app",
		UserID:    "test-user",
		StartTime: time.Now(),
		Events: []*event.Event{
			{
				InvocationID: "id1",
				Author:       "user",
				Content:      "I want to learn about machine learning and AI.",
			},
		},
	}
	
	// Test session 2
	session2 := &Session{
		ID:        "session2",
		AppName:   "test-app",
		UserID:    "test-user",
		StartTime: time.Now(),
		Events: []*event.Event{
			{
				InvocationID: "id2",
				Author:       "user",
				Content:      "How do I create a web server in Go?",
			},
		},
	}
	
	// Add sessions to memory
	err := service.AddSessionToMemory(ctx, session1)
	if err != nil {
		t.Fatalf("Failed to add session1 to memory: %v", err)
	}
	
	err = service.AddSessionToMemory(ctx, session2)
	if err != nil {
		t.Fatalf("Failed to add session2 to memory: %v", err)
	}
	
	// Test search
	testCases := []struct {
		name          string
		query         string
		wantSessions  []string
		wantNotInSessions []string
	}{
		{
			name:          "Search for AI",
			query:         "AI and neural networks",
			wantSessions:  []string{"session1"},
			wantNotInSessions: []string{"session2"},
		},
		{
			name:          "Search for Go web",
			query:         "web development with Go",
			wantSessions:  []string{"session2"},
			wantNotInSessions: []string{"session1"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Search memory
			res, err := service.SearchMemory(ctx, "test-app", "test-user", tc.query)
			if err != nil {
				t.Fatalf("Failed to search memory: %v", err)
			}
			
			// Create map of found session IDs
			foundSessions := make(map[string]bool)
			for _, memory := range res.Memories {
				foundSessions[memory.SessionID] = true
			}
			
			// Check for expected sessions
			for _, sid := range tc.wantSessions {
				if !foundSessions[sid] {
					t.Errorf("Expected to find session %s in results", sid)
				}
			}
			
			// Check sessions that should not be present
			for _, sid := range tc.wantNotInSessions {
				if foundSessions[sid] {
					t.Errorf("Expected NOT to find session %s in results", sid)
				}
			}
		})
	}
}

// createTestEvent creates a test event.
func createTestEvent(id, author, content string) *event.Event {
	return &event.Event{
		InvocationID: id,
		Author:       author,
		Content:      content,
	}
}

// TestKnowledgeGraphMemoryService tests the KnowledgeGraphMemoryService implementation.
func TestKnowledgeGraphMemoryService(t *testing.T) {
	// Create service
	service := NewKnowledgeGraphMemoryService()
	
	// Create context
	ctx := context.Background()
	
	// Create test entities
	entityGo := &Entity{
		Type:       "entity",
		Name:       "Go",
		EntityType: "Language",
		Observations: []string{
			"Go is a statically typed, compiled programming language",
			"Go was designed at Google by Robert Griesemer, Rob Pike, and Ken Thompson",
			"Go has garbage collection, type safety, and CSP-style concurrency",
		},
	}
	
	entityRust := &Entity{
		Type:       "entity",
		Name:       "Rust",
		EntityType: "Language",
		Observations: []string{
			"Rust is a multi-paradigm, high-level, general-purpose programming language",
			"Rust emphasizes performance, type safety, and concurrency",
			"Rust enforces memory safety without using garbage collection",
		},
	}
	
	// Add entities to graph
	service.mu.Lock()
	service.graph.Entities[entityGo.Name] = entityGo
	service.graph.Entities[entityRust.Name] = entityRust
	service.mu.Unlock()
	
	// Test session
	session := &Session{
		ID:        "test-session",
		AppName:   "test-app",
		UserID:    "test-user",
		StartTime: time.Now(),
		Events: []*event.Event{
			createTestEvent("id1", "user", "I want to learn about memory management in programming languages"),
			createTestEvent("id2", "assistant", "Memory management varies across languages. Garbage collection is used in Go."),
		},
	}
	
	// Add session to memory
	err := service.AddSessionToMemory(ctx, session)
	if err != nil {
		t.Fatalf("Failed to add session to memory: %v", err)
	}
	
	// Test search
	testCases := []struct {
		name       string
		query      string
		wantEvents int
	}{
		{
			name:       "Search for garbage collection",
			query:      "garbage collection",
			wantEvents: 1, // From the session
		},
		{
			name:       "Search for memory",
			query:      "memory",
			wantEvents: 1, // From the session
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Search memory
			res, err := service.SearchMemory(ctx, "test-app", "test-user", tc.query)
			if err != nil {
				t.Fatalf("Failed to search memory: %v", err)
			}
			
			// Count total events
			totalEvents := 0
			for _, memory := range res.Memories {
				totalEvents += len(memory.Events)
			}
			
			if totalEvents != tc.wantEvents {
				t.Errorf("Expected %d total events, got %d", tc.wantEvents, totalEvents)
			}
		})
	}
}

// TestMemoryResult tests the MemoryResult struct.
func TestMemoryResult(t *testing.T) {
	// Create a memory result
	result := &MemoryResult{
		SessionID: "test-session",
		Events: []*event.Event{
			createTestEvent("id1", "user", "Hello"),
			createTestEvent("id2", "assistant", "Hi there"),
		},
	}
	
	// Test session ID
	if result.SessionID != "test-session" {
		t.Errorf("Expected session ID 'test-session', got '%s'", result.SessionID)
	}
	
	// Test events
	if len(result.Events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(result.Events))
	}
	
	// Test event content
	if result.Events[0].Content != "Hello" {
		t.Errorf("Expected first event content 'Hello', got '%s'", result.Events[0].Content)
	}
}

// TestSearchMemoryResponse tests the SearchMemoryResponse struct.
func TestSearchMemoryResponse(t *testing.T) {
	// Create a response
	response := &SearchMemoryResponse{
		Memories: []*MemoryResult{
			{
				SessionID: "session1",
				Events: []*event.Event{
					createTestEvent("id1", "user", "Hello"),
				},
			},
			{
				SessionID: "session2",
				Events: []*event.Event{
					createTestEvent("id2", "user", "Hi"),
				},
			},
		},
	}
	
	// Test memories count
	if len(response.Memories) != 2 {
		t.Errorf("Expected 2 memories, got %d", len(response.Memories))
	}
	
	// Test memory session IDs
	if response.Memories[0].SessionID != "session1" || response.Memories[1].SessionID != "session2" {
		t.Errorf("Session IDs don't match expected values")
	}
}