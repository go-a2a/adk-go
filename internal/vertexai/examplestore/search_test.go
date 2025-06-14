// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"context"
	"fmt"
	"testing"
)

func TestSearchQuery_Validate(t *testing.T) {
	tests := []struct {
		name    string
		query   *SearchQuery
		wantErr bool
	}{
		{
			name: "valid query",
			query: &SearchQuery{
				Text:                "What is the capital of France?",
				TopK:                5,
				SimilarityThreshold: 0.8,
			},
			wantErr: false,
		},
		{
			name: "empty text",
			query: &SearchQuery{
				Text:                "",
				TopK:                5,
				SimilarityThreshold: 0.8,
			},
			wantErr: true,
		},
		{
			name: "zero topK defaults to default",
			query: &SearchQuery{
				Text:                "What is the capital of France?",
				TopK:                0,
				SimilarityThreshold: 0.8,
			},
			wantErr: false,
		},
		{
			name: "invalid similarity threshold defaults",
			query: &SearchQuery{
				Text:                "What is the capital of France?",
				TopK:                5,
				SimilarityThreshold: -0.5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SearchQuery.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				// Check that defaults were applied
				if tt.query.TopK <= 0 {
					t.Errorf("TopK should be set to default when <= 0")
				}
				if tt.query.SimilarityThreshold < 0 || tt.query.SimilarityThreshold > 1 {
					t.Errorf("SimilarityThreshold should be set to default when out of range")
				}
			}
		})
	}
}

func TestSearchService_SearchExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	tests := []struct {
		name    string
		req     *SearchExamplesRequest
		wantErr bool
	}{
		{
			name: "valid search request",
			req: &SearchExamplesRequest{
				Parent: "projects/test-project/locations/us-central1/exampleStores/test-store",
				Query: &SearchQuery{
					Text:                "capital of France",
					TopK:                3,
					SimilarityThreshold: 0.5,
				},
			},
			wantErr: false,
		},
		{
			name: "geography query",
			req: &SearchExamplesRequest{
				Parent: "projects/test-project/locations/us-central1/exampleStores/test-store",
				Query: &SearchQuery{
					Text:                "geography country capital",
					TopK:                5,
					SimilarityThreshold: 0.3,
				},
			},
			wantErr: false,
		},
		{
			name: "math query",
			req: &SearchExamplesRequest{
				Parent: "projects/test-project/locations/us-central1/exampleStores/test-store",
				Query: &SearchQuery{
					Text:                "mathematics addition numbers",
					TopK:                2,
					SimilarityThreshold: 0.4,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid query",
			req: &SearchExamplesRequest{
				Parent: "projects/test-project/locations/us-central1/exampleStores/test-store",
				Query: &SearchQuery{
					Text: "", // Empty text should fail validation
					TopK: 5,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := searchService.SearchExamples(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("SearchService.SearchExamples() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp == nil {
					t.Error("SearchService.SearchExamples() returned nil response")
					return
				}

				if resp.Results == nil {
					t.Error("SearchResponse.Results should not be nil")
					return
				}

				// Check that results don't exceed requested topK
				if len(resp.Results) > int(tt.req.Query.TopK) {
					t.Errorf("SearchExamples() returned %d results, max should be %d", len(resp.Results), tt.req.Query.TopK)
				}

				// Check that results are sorted by similarity score (descending)
				for i := 1; i < len(resp.Results); i++ {
					if resp.Results[i-1].SimilarityScore < resp.Results[i].SimilarityScore {
						t.Errorf("Results not sorted by similarity score: %f < %f at positions %d, %d",
							resp.Results[i-1].SimilarityScore, resp.Results[i].SimilarityScore, i-1, i)
					}
				}

				// Check that all results meet similarity threshold
				for i, result := range resp.Results {
					if result.SimilarityScore < tt.req.Query.SimilarityThreshold {
						t.Errorf("Result %d similarity score %f below threshold %f",
							i, result.SimilarityScore, tt.req.Query.SimilarityThreshold)
					}
				}

				// Check that query embedding was generated
				if len(resp.QueryEmbedding) == 0 {
					t.Error("SearchResponse.QueryEmbedding should not be empty")
				}
			}
		})
	}
}

func TestSearchService_SearchSimilarExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	referenceExample := &Example{
		Input: &Content{
			Text: "What is the capital of Italy?",
		},
		Output: &Content{
			Text: "The capital of Italy is Rome.",
		},
	}

	results, err := searchService.SearchSimilarExamples(ctx, storeName, referenceExample, 3)
	if err != nil {
		t.Errorf("SearchService.SearchSimilarExamples() error = %v", err)
		return
	}

	if len(results) > 3 {
		t.Errorf("SearchSimilarExamples() returned %d results, max should be 3", len(results))
	}

	// Results should be sorted by similarity
	for i := 1; i < len(results); i++ {
		if results[i-1].SimilarityScore < results[i].SimilarityScore {
			t.Errorf("Results not sorted by similarity score")
		}
	}
}

func TestSearchService_SearchWithFilters(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	tests := []struct {
		name    string
		query   string
		topK    int32
		filters map[string]any
	}{
		{
			name:  "filter by category",
			query: "capital city",
			topK:  5,
			filters: map[string]any{
				"category": "geography",
			},
		},
		{
			name:  "filter by difficulty",
			query: "simple question",
			topK:  3,
			filters: map[string]any{
				"difficulty": "easy",
			},
		},
		{
			name:  "multiple filters",
			query: "programming",
			topK:  2,
			filters: map[string]any{
				"category": "programming",
				"language": "go",
			},
		},
		{
			name:    "no filters",
			query:   "any question",
			topK:    5,
			filters: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := searchService.SearchWithFilters(ctx, storeName, tt.query, tt.topK, tt.filters)
			if err != nil {
				t.Errorf("SearchService.SearchWithFilters() error = %v", err)
				return
			}

			if len(results) > int(tt.topK) {
				t.Errorf("SearchWithFilters() returned %d results, max should be %d", len(results), tt.topK)
			}

			// Verify that results match filters
			for _, result := range results {
				if !matchesFilters(result.Example, tt.filters) {
					t.Errorf("Result does not match filters: %+v", tt.filters)
				}
			}
		})
	}
}

func TestSearchService_GetRelevantExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"
	queryText := "capital cities geography"
	topK := int32(3)
	minSimilarity := 0.5

	results, err := searchService.GetRelevantExamples(ctx, storeName, queryText, topK, minSimilarity)
	if err != nil {
		t.Errorf("SearchService.GetRelevantExamples() error = %v", err)
		return
	}

	if len(results) > int(topK) {
		t.Errorf("GetRelevantExamples() returned %d results, max should be %d", len(results), topK)
	}

	// All results should meet minimum similarity threshold
	for i, result := range results {
		if result.SimilarityScore < minSimilarity {
			t.Errorf("Result %d similarity score %f below minimum %f",
				i, result.SimilarityScore, minSimilarity)
		}
	}

	// Results should be sorted by smart ranking (similarity score after adjustments)
	for i := 1; i < len(results); i++ {
		if results[i-1].SimilarityScore < results[i].SimilarityScore {
			t.Errorf("Results not sorted by smart ranking score")
		}
	}
}

func TestSearchService_SearchByCategory(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	categories := []string{"geography", "math", "science", "programming"}

	for _, category := range categories {
		t.Run("category_"+category, func(t *testing.T) {
			results, err := searchService.SearchByCategory(ctx, storeName, "test query", category, 5)
			if err != nil {
				t.Errorf("SearchService.SearchByCategory() error = %v", err)
				return
			}

			// All results should have the requested category
			for _, result := range results {
				if !hasCategory(result.Example, category) {
					t.Errorf("Result does not have category %s", category)
				}
			}
		})
	}
}

func TestSearchService_SearchByDifficulty(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	difficulties := []string{"easy", "medium", "hard"}

	for _, difficulty := range difficulties {
		t.Run("difficulty_"+difficulty, func(t *testing.T) {
			results, err := searchService.SearchByDifficulty(ctx, storeName, "test query", difficulty, 5)
			if err != nil {
				t.Errorf("SearchService.SearchByDifficulty() error = %v", err)
				return
			}

			// All results should have the requested difficulty
			for _, result := range results {
				if !hasDifficulty(result.Example, difficulty) {
					t.Errorf("Result does not have difficulty %s", difficulty)
				}
			}
		})
	}
}

func TestCalculateTextSimilarity(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	tests := []struct {
		name        string
		queryWords  []string
		example     *StoredExample
		expectScore float64
	}{
		{
			name:       "exact match",
			queryWords: []string{"capital", "france"},
			example: &StoredExample{
				Input: &Content{
					Text: "capital france",
				},
			},
			expectScore: 1.0,
		},
		{
			name:       "partial match",
			queryWords: []string{"capital", "france"},
			example: &StoredExample{
				Input: &Content{
					Text: "capital",
				},
			},
			expectScore: 0.5, // 1 intersection, 2 union
		},
		{
			name:       "no match",
			queryWords: []string{"capital", "france"},
			example: &StoredExample{
				Input: &Content{
					Text: "math addition",
				},
			},
			expectScore: 0.0,
		},
		{
			name:       "nil input",
			queryWords: []string{"capital", "france"},
			example: &StoredExample{
				Input: nil,
			},
			expectScore: 0.0,
		},
		{
			name:       "empty input text",
			queryWords: []string{"capital", "france"},
			example: &StoredExample{
				Input: &Content{
					Text: "",
				},
			},
			expectScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := searchService.calculateTextSimilarity(tt.queryWords, tt.example)
			if score != tt.expectScore {
				t.Errorf("calculateTextSimilarity() = %f, want %f", score, tt.expectScore)
			}
		})
	}
}

func TestCalculateQualityScore(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	searchService := service.searchService

	tests := []struct {
		name     string
		example  *StoredExample
		minScore float64
		maxScore float64
	}{
		{
			name: "high quality example",
			example: &StoredExample{
				Metadata: map[string]any{"category": "test"},
				Output: &Content{
					Text:     "This is a long, detailed output that provides comprehensive information",
					Metadata: map[string]any{"confidence": 0.95},
				},
			},
			minScore: 0.8,
			maxScore: 1.0,
		},
		{
			name: "basic example",
			example: &StoredExample{
				Output: &Content{
					Text: "Short output",
				},
			},
			minScore: 0.4,
			maxScore: 0.8,
		},
		{
			name: "minimal example",
			example: &StoredExample{
				Output: &Content{
					Text: "No",
				},
			},
			minScore: 0.3,
			maxScore: 0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := searchService.calculateQualityScore(tt.example)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("calculateQualityScore() = %f, want between %f and %f", score, tt.minScore, tt.maxScore)
			}
		})
	}
}

// Helper functions for tests

func matchesFilters(example *StoredExample, filters map[string]any) bool {
	for key, expectedValue := range filters {
		found := false

		// Check example metadata
		if value, exists := example.Metadata[key]; exists {
			if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", expectedValue) {
				found = true
			}
		}

		// Check input metadata
		if !found && example.Input != nil {
			if value, exists := example.Input.Metadata[key]; exists {
				if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", expectedValue) {
					found = true
				}
			}
		}

		// Check output metadata
		if !found && example.Output != nil {
			if value, exists := example.Output.Metadata[key]; exists {
				if fmt.Sprintf("%v", value) == fmt.Sprintf("%v", expectedValue) {
					found = true
				}
			}
		}

		if !found {
			return false
		}
	}
	return true
}

func hasCategory(example *StoredExample, category string) bool {
	return matchesFilters(example, map[string]any{"category": category})
}

func hasDifficulty(example *StoredExample, difficulty string) bool {
	return matchesFilters(example, map[string]any{"difficulty": difficulty})
}
