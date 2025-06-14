// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
)

// SearchService handles search and retrieval operations for Example Stores.
type SearchService struct {
	client    *aiplatform.VertexRagDataClient
	projectID string
	location  string
	logger    *slog.Logger
}

// NewSearchService creates a new search service.
func NewSearchService(client *aiplatform.VertexRagDataClient, projectID, location string, logger *slog.Logger) *SearchService {
	return &SearchService{
		client:    client,
		projectID: projectID,
		location:  location,
		logger:    logger,
	}
}

// SearchExamples searches for relevant examples in an Example Store.
func (s *SearchService) SearchExamples(ctx context.Context, req *SearchExamplesRequest) (*SearchResponse, error) {
	s.logger.InfoContext(ctx, "Searching examples",
		slog.String("store", req.Parent),
		slog.String("query", req.Query.Text),
		slog.Int("top_k", int(req.Query.TopK)),
	)

	if err := req.Query.Validate(); err != nil {
		return nil, fmt.Errorf("invalid search query: %w", err)
	}

	// TODO: Replace with actual Vertex AI API call for semantic search
	// This would typically involve:
	// 1. Generate embedding for the query text using the store's embedding model
	// 2. Perform vector similarity search against stored example embeddings
	// 3. Apply any metadata filters
	// 4. Return top-k results ordered by similarity

	// For now, implement a mock search that demonstrates the expected behavior
	mockResults, err := s.performMockSearch(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	response := &SearchResponse{
		Results:        mockResults,
		QueryEmbedding: generateMockEmbedding(req.Query.Text),
	}

	s.logger.InfoContext(ctx, "Search completed",
		slog.String("store", req.Parent),
		slog.Int("result_count", len(response.Results)),
	)

	return response, nil
}

// performMockSearch performs a mock search for demonstration purposes.
// TODO: Replace with actual vector similarity search.
func (s *SearchService) performMockSearch(ctx context.Context, req *SearchExamplesRequest) ([]*SearchResult, error) {
	// For demonstration, create some mock examples and perform basic text similarity
	mockExamples := s.generateMockExamples(req.Parent)

	// Calculate similarity scores using simple text overlap
	var results []*SearchResult
	queryWords := strings.Fields(strings.ToLower(req.Query.Text))

	for _, example := range mockExamples {
		score := s.calculateTextSimilarity(queryWords, example)
		distance := 1.0 - score // Convert similarity to distance

		// Apply similarity threshold
		if score >= req.Query.SimilarityThreshold {
			result := &SearchResult{
				Example:         example,
				SimilarityScore: score,
				Distance:        distance,
			}
			results = append(results, result)
		}
	}

	// Sort by similarity score (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].SimilarityScore > results[j].SimilarityScore
	})

	// Limit to top-k results
	if len(results) > int(req.Query.TopK) {
		results = results[:req.Query.TopK]
	}

	return results, nil
}

// calculateTextSimilarity calculates a simple text similarity score.
// TODO: Replace with actual vector similarity calculation.
func (s *SearchService) calculateTextSimilarity(queryWords []string, example *StoredExample) float64 {
	if example.Input == nil {
		return 0.0
	}

	inputWords := strings.Fields(strings.ToLower(example.Input.Text))
	if len(inputWords) == 0 {
		return 0.0
	}

	// Calculate Jaccard similarity (intersection over union)
	querySet := make(map[string]bool)
	for _, word := range queryWords {
		querySet[word] = true
	}

	inputSet := make(map[string]bool)
	for _, word := range inputWords {
		inputSet[word] = true
	}

	intersection := 0
	for word := range querySet {
		if inputSet[word] {
			intersection++
		}
	}

	union := len(querySet) + len(inputSet) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// generateMockExamples generates mock examples for testing search functionality.
func (s *SearchService) generateMockExamples(storeName string) []*StoredExample {
	examples := []*StoredExample{
		{
			Name:        storeName + "/examples/example-1",
			DisplayName: "Geography Example 1",
			Input: &Content{
				Text:     "What is the capital of France?",
				Metadata: map[string]any{"category": "geography", "difficulty": "easy"},
			},
			Output: &Content{
				Text:     "The capital of France is Paris.",
				Metadata: map[string]any{"confidence": 0.95},
			},
			State:           ExampleStateActive,
			EmbeddingVector: generateMockEmbedding("What is the capital of France?"),
		},
		{
			Name:        storeName + "/examples/example-2",
			DisplayName: "Math Example 1",
			Input: &Content{
				Text:     "What is 2 + 2?",
				Metadata: map[string]any{"category": "math", "difficulty": "easy"},
			},
			Output: &Content{
				Text:     "2 + 2 equals 4.",
				Metadata: map[string]any{"confidence": 1.0},
			},
			State:           ExampleStateActive,
			EmbeddingVector: generateMockEmbedding("What is 2 + 2?"),
		},
		{
			Name:        storeName + "/examples/example-3",
			DisplayName: "Geography Example 2",
			Input: &Content{
				Text:     "What is the capital of Italy?",
				Metadata: map[string]any{"category": "geography", "difficulty": "easy"},
			},
			Output: &Content{
				Text:     "The capital of Italy is Rome.",
				Metadata: map[string]any{"confidence": 0.95},
			},
			State:           ExampleStateActive,
			EmbeddingVector: generateMockEmbedding("What is the capital of Italy?"),
		},
		{
			Name:        storeName + "/examples/example-4",
			DisplayName: "Science Example 1",
			Input: &Content{
				Text:     "What is photosynthesis?",
				Metadata: map[string]any{"category": "science", "difficulty": "medium"},
			},
			Output: &Content{
				Text:     "Photosynthesis is the process by which plants convert light energy into chemical energy.",
				Metadata: map[string]any{"confidence": 0.90},
			},
			State:           ExampleStateActive,
			EmbeddingVector: generateMockEmbedding("What is photosynthesis?"),
		},
		{
			Name:        storeName + "/examples/example-5",
			DisplayName: "Programming Example 1",
			Input: &Content{
				Text:     "How do you declare a variable in Go?",
				Metadata: map[string]any{"category": "programming", "language": "go", "difficulty": "easy"},
			},
			Output: &Content{
				Text:     "In Go, you can declare a variable using 'var name type' or 'name := value' for short declaration.",
				Metadata: map[string]any{"confidence": 0.98},
			},
			State:           ExampleStateActive,
			EmbeddingVector: generateMockEmbedding("How do you declare a variable in Go?"),
		},
	}

	return examples
}

// SearchSimilarExamples searches for examples similar to a given example.
func (s *SearchService) SearchSimilarExamples(ctx context.Context, storeName string, example *Example, topK int32) ([]*SearchResult, error) {
	s.logger.InfoContext(ctx, "Searching for similar examples",
		slog.String("store", storeName),
		slog.String("reference_input", example.Input.Text),
		slog.Int("top_k", int(topK)),
	)

	query := &SearchQuery{
		Text:                example.Input.Text,
		TopK:                topK,
		SimilarityThreshold: DefaultSimilarityThreshold,
	}

	req := &SearchExamplesRequest{
		Parent: storeName,
		Query:  query,
	}

	response, err := s.SearchExamples(ctx, req)
	if err != nil {
		return nil, err
	}

	return response.Results, nil
}

// SearchWithFilters searches for examples with metadata filters.
func (s *SearchService) SearchWithFilters(ctx context.Context, storeName, queryText string, topK int32, filters map[string]any) ([]*SearchResult, error) {
	s.logger.InfoContext(ctx, "Searching examples with filters",
		slog.String("store", storeName),
		slog.String("query", queryText),
		slog.Int("top_k", int(topK)),
		slog.Any("filters", filters),
	)

	query := &SearchQuery{
		Text:                queryText,
		TopK:                topK,
		SimilarityThreshold: DefaultSimilarityThreshold,
		MetadataFilters:     filters,
	}

	req := &SearchExamplesRequest{
		Parent: storeName,
		Query:  query,
	}

	// Get initial results
	response, err := s.SearchExamples(ctx, req)
	if err != nil {
		return nil, err
	}

	// Apply metadata filters (this would be done server-side in a real implementation)
	filteredResults := s.applyMetadataFilters(response.Results, filters)

	s.logger.InfoContext(ctx, "Search with filters completed",
		slog.String("store", storeName),
		slog.Int("initial_results", len(response.Results)),
		slog.Int("filtered_results", len(filteredResults)),
	)

	return filteredResults, nil
}

// applyMetadataFilters applies metadata filters to search results.
func (s *SearchService) applyMetadataFilters(results []*SearchResult, filters map[string]any) []*SearchResult {
	if len(filters) == 0 {
		return results
	}

	var filteredResults []*SearchResult

	for _, result := range results {
		if s.matchesFilters(result.Example, filters) {
			filteredResults = append(filteredResults, result)
		}
	}

	return filteredResults
}

// matchesFilters checks if an example matches the given metadata filters.
func (s *SearchService) matchesFilters(example *StoredExample, filters map[string]any) bool {
	for key, expectedValue := range filters {
		// Check example metadata
		if value, exists := example.Metadata[key]; exists {
			if !s.valuesMatch(value, expectedValue) {
				return false
			}
			continue
		}

		// Check input metadata
		if example.Input != nil {
			if value, exists := example.Input.Metadata[key]; exists {
				if !s.valuesMatch(value, expectedValue) {
					return false
				}
				continue
			}
		}

		// Check output metadata
		if example.Output != nil {
			if value, exists := example.Output.Metadata[key]; exists {
				if !s.valuesMatch(value, expectedValue) {
					return false
				}
				continue
			}
		}

		// If key not found in any metadata, filter doesn't match
		return false
	}

	return true
}

// valuesMatch checks if two values match (with type conversion).
func (s *SearchService) valuesMatch(actual, expected any) bool {
	// Simple equality check - in a real implementation, you might want
	// more sophisticated matching (e.g., range queries, regex, etc.)
	return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)
}

// GetRelevantExamples retrieves examples most relevant to a query with smart ranking.
func (s *SearchService) GetRelevantExamples(ctx context.Context, storeName, queryText string, topK int32, minSimilarity float64) ([]*SearchResult, error) {
	s.logger.InfoContext(ctx, "Getting relevant examples with smart ranking",
		slog.String("store", storeName),
		slog.String("query", queryText),
		slog.Int("top_k", int(topK)),
		slog.Float64("min_similarity", minSimilarity),
	)

	query := &SearchQuery{
		Text:                queryText,
		TopK:                topK * 2, // Get more results for better filtering
		SimilarityThreshold: minSimilarity,
	}

	req := &SearchExamplesRequest{
		Parent: storeName,
		Query:  query,
	}

	response, err := s.SearchExamples(ctx, req)
	if err != nil {
		return nil, err
	}

	// Apply smart ranking based on multiple factors
	rankedResults := s.applySmartRanking(response.Results, queryText)

	// Limit to requested top-k
	if len(rankedResults) > int(topK) {
		rankedResults = rankedResults[:topK]
	}

	s.logger.InfoContext(ctx, "Relevant examples retrieved",
		slog.String("store", storeName),
		slog.Int("result_count", len(rankedResults)),
	)

	return rankedResults, nil
}

// applySmartRanking applies smart ranking to search results.
func (s *SearchService) applySmartRanking(results []*SearchResult, queryText string) []*SearchResult {
	// Apply additional ranking factors beyond similarity score
	for _, result := range results {
		// Example quality score based on metadata
		qualityScore := s.calculateQualityScore(result.Example)

		// Recency score (newer examples get slight boost)
		recencyScore := s.calculateRecencyScore(result.Example)

		// Combined score: 70% similarity, 20% quality, 10% recency
		combinedScore := 0.7*result.SimilarityScore + 0.2*qualityScore + 0.1*recencyScore

		// Update the similarity score with the combined score
		result.SimilarityScore = combinedScore
	}

	// Re-sort by combined score
	sort.Slice(results, func(i, j int) bool {
		return results[i].SimilarityScore > results[j].SimilarityScore
	})

	return results
}

// calculateQualityScore calculates a quality score for an example.
func (s *SearchService) calculateQualityScore(example *StoredExample) float64 {
	score := 0.5 // Base score

	// Higher score for examples with metadata
	if len(example.Metadata) > 0 {
		score += 0.2
	}

	// Higher score for examples with confidence metadata
	if example.Output != nil {
		if confidence, exists := example.Output.Metadata["confidence"]; exists {
			if conf, ok := confidence.(float64); ok {
				score += 0.3 * conf
			}
		}
	}

	// Higher score for longer, more detailed outputs
	if example.Output != nil && len(example.Output.Text) > 50 {
		score += 0.2
	}

	return math.Min(score, 1.0)
}

// calculateRecencyScore calculates a recency score for an example.
func (s *SearchService) calculateRecencyScore(example *StoredExample) float64 {
	if example.CreateTime == nil {
		return 0.5 // Default score if no timestamp
	}

	// Examples created in the last 30 days get full recency score
	// Older examples get progressively lower scores
	// This is a simple linear decay - you might want more sophisticated aging

	// For now, return a constant score since we're using mock data
	return 0.8
}

// SearchByCategory searches for examples in specific categories.
func (s *SearchService) SearchByCategory(ctx context.Context, storeName, queryText, category string, topK int32) ([]*SearchResult, error) {
	filters := map[string]any{
		"category": category,
	}

	return s.SearchWithFilters(ctx, storeName, queryText, topK, filters)
}

// SearchByDifficulty searches for examples with specific difficulty levels.
func (s *SearchService) SearchByDifficulty(ctx context.Context, storeName, queryText, difficulty string, topK int32) ([]*SearchResult, error) {
	filters := map[string]any{
		"difficulty": difficulty,
	}

	return s.SearchWithFilters(ctx, storeName, queryText, topK, filters)
}
