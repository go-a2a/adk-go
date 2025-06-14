// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"google.golang.org/genai"

	ragclient "github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
	"github.com/go-a2a/adk-go/types"
)

// VertexAIRagService implements Service with Google Cloud Vertex AI RAG.
type VertexAIRagService struct {
	ragClient               *ragclient.Service
	ragCorpus               string
	similarityTopK          int
	vectorDistanceThreshold float64
	vertexRAGStore          *genai.VertexRAGStore
	logger                  *slog.Logger
}

var _ types.MemoryService = (*VertexAIRagService)(nil)

// VertexAIRagOption is a functional option for configuring [VertexAIRagService].
type VertexAIRagOption func(*VertexAIRagService)

// WithVertexAIRagLogger sets the logger for the [VertexAIRagService].
func WithVertexAIRagLogger(logger *slog.Logger) VertexAIRagOption {
	return func(s *VertexAIRagService) {
		s.logger = logger
	}
}

// WithSimilarityTopK sets the number of top results to return for the [VertexAIRagService].
func WithSimilarityTopK(topK int) VertexAIRagOption {
	return func(s *VertexAIRagService) {
		s.similarityTopK = topK
	}
}

// WithVectorDistanceThreshold sets the threshold for vector similarity for the [VertexAIRagService].
func WithVectorDistanceThreshold(threshold float64) VertexAIRagOption {
	return func(s *VertexAIRagService) {
		s.vectorDistanceThreshold = threshold
	}
}

// NewVertexAIRagService creates a new VertexAIRagService.
func NewVertexAIRagService(ctx context.Context, projectID, location, ragCorpus string, opts ...VertexAIRagOption) (*VertexAIRagService, error) {
	ragClient, err := ragclient.NewService(ctx, projectID, location)
	if err != nil {
		return nil, fmt.Errorf("failed to create RAG client: %w", err)
	}

	s := &VertexAIRagService{
		ragClient:               ragClient,
		ragCorpus:               ragCorpus,
		similarityTopK:          5,   // Default value
		vectorDistanceThreshold: 0.7, // Default value
		logger:                  slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	vertexGagStore := &genai.VertexRAGStore{
		RAGResources: []*genai.VertexRAGStoreRAGResource{
			{
				RAGCorpus: ragCorpus,
			},
		},
		SimilarityTopK:          genai.Ptr(int32(s.similarityTopK)),
		VectorDistanceThreshold: genai.Ptr(s.vectorDistanceThreshold),
	}
	s.vertexRAGStore = vertexGagStore

	return s, nil
}

// AddSessionToMemory implements [types.MemoryService].
func (s *VertexAIRagService) AddSessionToMemory(ctx context.Context, session types.Session) error {
	if len(s.vertexRAGStore.RAGResources) == 0 {
		return fmt.Errorf("rag resources must be set")
	}

	s.logger.InfoContext(ctx, "Adding session to Vertex AI RAG memory",
		slog.String("app_name", session.AppName()),
		slog.String("user_id", session.UserID()),
		slog.String("session_id", session.ID()),
		slog.String("rag_corpus", s.ragCorpus),
	)

	// Create temporary file with session content
	tempfile, err := os.CreateTemp(os.TempDir(), "session-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tempfile.Name())

	// Extract text content from session events
	var outputLines []string
	for _, event := range session.Events() {
		if event.Content == nil || len(event.Content.Parts) == 0 {
			continue
		}

		var textParts []string
		for _, part := range event.Content.Parts {
			if part.Text != "" {
				text := strings.ReplaceAll(part.Text, "\n", " ")
				textParts = append(textParts, text)
			}
		}

		if len(textParts) > 0 {
			eventData := map[string]any{
				"author":     event.Author,
				"timestamp":  event.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
				"text":       strings.Join(textParts, ". "),
				"app_name":   session.AppName(),
				"user_id":    session.UserID(),
				"session_id": session.ID(),
			}

			data, err := json.Marshal(eventData)
			if err != nil {
				return fmt.Errorf("failed to marshal event data: %w", err)
			}
			outputLines = append(outputLines, string(data))
		}
	}

	if len(outputLines) == 0 {
		s.logger.InfoContext(ctx, "No text content found in session, skipping upload")
		return nil
	}

	// Write session content to temporary file
	outputString := strings.Join(outputLines, "\n")
	if _, err := tempfile.WriteString(outputString); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	if err := tempfile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Upload file to RAG corpus using new internal client
	ragFile := &ragclient.RagFile{
		DisplayName: fmt.Sprintf("session-%s-%s-%s", session.AppName(), session.UserID(), session.ID()),
		Description: fmt.Sprintf("Session data for app %s, user %s, session %s", session.AppName(), session.UserID(), session.ID()),
		RagFileSource: &ragclient.RagFileSource{
			DirectUploadSource: &ragclient.DirectUploadSource{},
		},
	}

	uploadConfig := &ragclient.UploadRagFileConfig{
		ChunkSize:    1000, // Default chunk size
		ChunkOverlap: 100,  // Default overlap
	}

	uploadedFile, err := s.ragClient.UploadFile(ctx, s.ragCorpus, ragFile, uploadConfig)
	if err != nil {
		return fmt.Errorf("failed to upload session file to RAG corpus: %w", err)
	}

	s.logger.InfoContext(ctx, "Session added to Vertex AI RAG memory successfully",
		slog.String("file_name", uploadedFile.Name),
		slog.String("display_name", uploadedFile.DisplayName),
		slog.Int64("size_bytes", uploadedFile.SizeBytes),
	)

	return nil
}

// SearchMemory implements [types.MemoryService].
func (s *VertexAIRagService) SearchMemory(ctx context.Context, appName, userID, query string) (*types.SearchMemoryResponse, error) {
	s.logger.InfoContext(ctx, "Searching Vertex AI RAG memory",
		slog.String("app_name", appName),
		slog.String("user_id", userID),
		slog.String("query", query),
		slog.String("rag_corpus", s.ragCorpus),
	)

	// Perform semantic search using the new RAG client
	searchReq := &ragclient.SearchRequest{
		Query:                   query,
		CorporaNames:            []string{s.ragCorpus},
		TopK:                    int32(s.similarityTopK),
		VectorDistanceThreshold: s.vectorDistanceThreshold,
		Filters: map[string]any{
			"app_name": appName,
			"user_id":  userID,
		},
	}

	searchResp, err := s.ragClient.Search(ctx, searchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to search RAG corpus: %w", err)
	}

	// Convert search results to memory entries
	var memories []*types.MemoryEntry
	for _, doc := range searchResp.Documents {
		// Parse the document content back to extract event data
		var eventData map[string]any
		if err := json.Unmarshal([]byte(doc.Content), &eventData); err != nil {
			// If parsing fails, treat the content as plain text
			s.logger.WarnContext(ctx, "Failed to parse document as JSON, treating as plain text",
				slog.String("error", err.Error()),
			)

			memory := &types.MemoryEntry{
				Content: genai.NewContentFromText(doc.Content, genai.RoleUser),
				Author:  "unknown",
			}
			memories = append(memories, memory)
			continue
		}

		// Extract author and text from the parsed event data
		author := "unknown"
		if authorVal, ok := eventData["author"].(string); ok {
			author = authorVal
		}

		text := ""
		if textVal, ok := eventData["text"].(string); ok {
			text = textVal
		}

		memory := &types.MemoryEntry{
			Content: genai.NewContentFromText(text, genai.RoleUser),
			Author:  author,
		}

		// Parse timestamp if available
		if timestampStr, ok := eventData["timestamp"].(string); ok {
			if timestamp, err := time.Parse("2006-01-02T15:04:05Z07:00", timestampStr); err == nil {
				memory.Timestamp = timestamp
			}
		}

		memories = append(memories, memory)
	}

	response := &types.SearchMemoryResponse{
		Memories: memories,
	}

	s.logger.InfoContext(ctx, "Vertex AI RAG memory search completed",
		slog.Int("results_count", len(memories)),
	)

	return response, nil
}

// Close closes the underlying RAG client and releases resources.
func (s *VertexAIRagService) Close() error {
	if s.ragClient != nil {
		return s.ragClient.Close()
	}
	return nil
}
