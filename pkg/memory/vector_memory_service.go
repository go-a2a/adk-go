// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-a2a/adk-go/pkg/event"
)

// VectorEntry represents a vector entry in the memory store
type VectorEntry struct {
	// Key uniquely identifies this entry
	Key string
	
	// SessionID is the session this entry belongs to
	SessionID string
	
	// AppName is the application name
	AppName string
	
	// UserID is the user identifier
	UserID string
	
	// Text is the content text
	Text string
	
	// Event is the original event
	Event *event.Event
	
	// Vector is a mock vector embedding - in a real implementation,
	// this would be a proper vector from an embedding model
	// Here we just use a simple mock based on word presence
	Vector map[string]float64
}

// VectorMemoryService provides a memory service that simulates
// vector-based retrieval. This is a simplified implementation
// for demonstration purposes, showing how a real vector-based
// system like Vertex AI RAG might be structured.
type VectorMemoryService struct {
	// mu protects vectors
	mu sync.RWMutex
	
	// vectors stores all vector entries
	vectors []*VectorEntry
	
	// similarityTopK is the number of results to return
	similarityTopK int
	
	// distanceThreshold is the maximum vector distance to consider
	distanceThreshold float64
}

// VectorMemoryServiceOption defines a functional option for configuring the service
type VectorMemoryServiceOption func(*VectorMemoryService)

// WithSimilarityTopK sets the number of results to return
func WithSimilarityTopK(k int) VectorMemoryServiceOption {
	return func(s *VectorMemoryService) {
		if k > 0 {
			s.similarityTopK = k
		}
	}
}

// WithDistanceThreshold sets the maximum vector distance threshold
func WithDistanceThreshold(threshold float64) VectorMemoryServiceOption {
	return func(s *VectorMemoryService) {
		if threshold > 0 {
			s.distanceThreshold = threshold
		}
	}
}

// NewVectorMemoryService creates a new VectorMemoryService
func NewVectorMemoryService(options ...VectorMemoryServiceOption) *VectorMemoryService {
	service := &VectorMemoryService{
		vectors:           []*VectorEntry{},
		similarityTopK:    5,        // Default to top 5 results
		distanceThreshold: 0.75,     // Default threshold
	}
	
	// Apply options
	for _, option := range options {
		option(service)
	}
	
	return service
}

// AddSessionToMemory adds a session to the memory service.
func (s *VectorMemoryService) AddSessionToMemory(ctx context.Context, session *Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	// Process each event with content
	var entries []*VectorEntry
	for _, evt := range session.Events {
		if evt == nil || evt.Content == "" {
			continue
		}
		
		// Create a vector entry
		entry := &VectorEntry{
			Key:       fmt.Sprintf("%s/%s/%s/%d", session.AppName, session.UserID, session.ID, time.Now().UnixNano()),
			SessionID: session.ID,
			AppName:   session.AppName,
			UserID:    session.UserID,
			Text:      evt.Content,
			Event:     evt,
			Vector:    generateMockVector(evt.Content),
		}
		
		entries = append(entries, entry)
	}
	
	// Add entries to the store
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.vectors = append(s.vectors, entries...)
	
	return nil
}

// SearchMemory searches for sessions that match the query.
func (s *VectorMemoryService) SearchMemory(ctx context.Context, appName string, userID string, query string) (*SearchMemoryResponse, error) {
	if appName == "" {
		return nil, fmt.Errorf("app name cannot be empty")
	}
	
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	
	if query == "" {
		return nil, fmt.Errorf("query cannot be empty")
	}
	
	// Generate query vector
	queryVector := generateMockVector(query)
	
	s.mu.RLock()
	
	// Score and filter vectors
	type scoredEntry struct {
		entry *VectorEntry
		score float64
	}
	
	var scoredEntries []scoredEntry
	
	for _, entry := range s.vectors {
		// Filter by app and user
		if entry.AppName != appName || entry.UserID != userID {
			continue
		}
		
		// Calculate similarity score
		score := calculateSimilarity(queryVector, entry.Vector)
		
		// Apply threshold
		if score >= s.distanceThreshold {
			scoredEntries = append(scoredEntries, scoredEntry{
				entry: entry,
				score: score,
			})
		}
	}
	
	s.mu.RUnlock()
	
	// Sort by score (highest first)
	sort.Slice(scoredEntries, func(i, j int) bool {
		return scoredEntries[i].score > scoredEntries[j].score
	})
	
	// Limit results
	if len(scoredEntries) > s.similarityTopK {
		scoredEntries = scoredEntries[:s.similarityTopK]
	}
	
	// Group by session and create response
	sessionEvents := make(map[string][]*event.Event)
	
	for _, scored := range scoredEntries {
		entry := scored.entry
		sessionEvents[entry.SessionID] = append(sessionEvents[entry.SessionID], entry.Event)
	}
	
	// Create memory results
	var memories []*MemoryResult
	
	for sessionID, events := range sessionEvents {
		memories = append(memories, &MemoryResult{
			SessionID: sessionID,
			Events:    mergeEventLists(events),
		})
	}
	
	return &SearchMemoryResponse{
		Memories: memories,
	}, nil
}

// generateMockVector creates a simple vector representation of text.
// This is a highly simplified mock of what an embedding model would do.
// In a real implementation, this would call an embedding model.
func generateMockVector(text string) map[string]float64 {
	vector := make(map[string]float64)
	
	// Normalize text
	text = strings.ToLower(text)
	
	// Split into words
	words := strings.Fields(text)
	
	// Count word occurrences
	wordCounts := make(map[string]int)
	for _, word := range words {
		wordCounts[word]++
	}
	
	// Convert to a simple vector
	totalWords := len(words)
	if totalWords > 0 {
		for word, count := range wordCounts {
			vector[word] = float64(count) / float64(totalWords)
		}
	}
	
	return vector
}

// calculateSimilarity calculates the cosine similarity between two vectors.
// This is a simplified implementation for our mock vectors.
func calculateSimilarity(v1, v2 map[string]float64) float64 {
	// For our mock implementation, we'll use a simple method:
	// Calculate the proportion of words that appear in both vectors
	
	// Count words in common
	commonWords := 0
	totalWords := 0
	
	// Check words from v1
	for word := range v1 {
		totalWords++
		if _, exists := v2[word]; exists {
			commonWords++
		}
	}
	
	// Add words only in v2
	for word := range v2 {
		if _, exists := v1[word]; !exists {
			totalWords++
		}
	}
	
	// Avoid division by zero
	if totalWords == 0 {
		return 0
	}
	
	return float64(commonWords) / float64(totalWords)
}

// mergeEventLists merges a list of events, potentially removing duplicates.
func mergeEventLists(events []*event.Event) []*event.Event {
	if len(events) <= 1 {
		return events
	}
	
	// Use a map to track unique events by ID
	uniqueEvents := make(map[string]*event.Event)
	
	for _, evt := range events {
		if evt == nil {
			continue
		}
		
		// Use invocation ID as the key
		uniqueEvents[evt.InvocationID] = evt
	}
	
	// Convert back to a slice
	result := make([]*event.Event, 0, len(uniqueEvents))
	for _, evt := range uniqueEvents {
		result = append(result, evt)
	}
	
	return result
}