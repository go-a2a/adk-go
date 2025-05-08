// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"

	"github.com/go-a2a/adk-go/types"
)

// MemoryItem represents a stored memory entry.
type MemoryItem struct {
	AppName   string
	UserID    string
	SessionID string
	Timestamp time.Time
	Events    []*types.Event
}

// InMemoryService implements Service with in-memory storage.
type InMemoryService struct {
	memory []*MemoryItem
	logger *slog.Logger
	mu     sync.RWMutex
}

// InMemoryOption is a functional option for [InMemoryService].
type InMemoryOption func(*InMemoryService)

// WithLogger sets the logger for the InMemoryService.
func WithLogger(logger *slog.Logger) InMemoryOption {
	return func(s *InMemoryService) {
		s.logger = logger
	}
}

// NewInMemoryService creates a new InMemoryService.
func NewInMemoryService(opts ...InMemoryOption) *InMemoryService {
	s := &InMemoryService{
		memory: []*MemoryItem{},
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// AddSessionToMemory implements [Service].
func (s *InMemoryService) AddSessionToMemory(ctx context.Context, session types.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create memory item from session
	item := &MemoryItem{
		AppName:   session.AppName(),
		UserID:    session.UserID(),
		SessionID: session.ID(),
		Timestamp: time.Now(),
		Events:    session.Events(),
	}

	s.logger.InfoContext(ctx, "Adding session to memory",
		slog.String("app_name", item.AppName),
		slog.String("user_id", item.UserID),
		slog.String("session_id", item.SessionID),
		slog.Int("events_count", len(item.Events)),
	)

	// Add to memory
	s.memory = append(s.memory, item)
	return nil
}

// extractTextContent extracts text content from an event.
func (s *InMemoryService) extractTextContent(e *types.Event) string {
	if e == nil || e.Content == nil {
		return ""
	}

	var content strings.Builder

	// Extract text from content parts
	for _, part := range e.Content.Parts {
		if part == nil {
			continue
		}

		// Try to extract text content
		if part.Text != "" {
			content.WriteString(" " + part.Text)
		}

		// Add function call names and arguments which might be relevant
		if part.FunctionCall != nil {
			content.WriteString(" " + part.FunctionCall.Name)
			// Could also potentially extract from arguments
		}

		// Add function responses which might contain relevant information
		if part.FunctionResponse != nil {
			content.WriteString(" " + part.FunctionResponse.Name)
			if part.FunctionResponse.Response != nil {
				data, err := sonic.ConfigFastest.Marshal(part.FunctionResponse.Response)
				if err != nil {
					continue
				}
				content.WriteString(" " + string(data))
			}
		}
	}

	return strings.ToLower(content.String())
}

// SearchMemory implements [Service].
func (s *InMemoryService) SearchMemory(ctx context.Context, appName, userID, query string) (*types.MemorySearchResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.logger.InfoContext(ctx, "Searching memory",
		slog.String("app_name", appName),
		slog.String("user_id", userID),
		slog.String("query", query),
	)

	// Simple keyword matching implementation
	queryTerms := strings.Fields(strings.ToLower(query))
	results := &types.MemorySearchResponse{
		Memories: make([]*types.MemoryResult, 0),
	}

	// Search through memory items
	for _, item := range s.memory {
		if item.AppName != appName || (userID != "" && item.UserID != userID) {
			continue
		}

		// Calculate relevance score based on event content matching query terms
		var relevanceScore float64
		for _, event := range item.Events {
			content := s.extractTextContent(event)

			// Score based on term frequency
			for _, term := range queryTerms {
				count := strings.Count(content, term)
				if count > 0 {
					relevanceScore += float64(count)
				}
			}
		}

		// Add to results if relevant
		if relevanceScore > 0 {
			results.Memories = append(results.Memories, &types.MemoryResult{
				SessionID: item.SessionID,
				Events:    item.Events,
			})
		}
	}

	// Sort results by relevance score (descending)
	for i := 0; i < len(results.Memories); i++ {
		for j := i + 1; j < len(results.Memories); j++ {
			if results.Memories[i].RelevanceScore < results.Memories[j].RelevanceScore {
				results.Memories[i], results.Memories[j] = results.Memories[j], results.Memories[i]
			}
		}
	}

	s.logger.InfoContext(ctx, "Memory search results",
		slog.Int("result_count", len(results.Memories)),
	)

	return results, nil
}
