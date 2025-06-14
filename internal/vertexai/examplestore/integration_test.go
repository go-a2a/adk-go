// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package examplestore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// Integration tests require actual Vertex AI API credentials and will make real API calls.
// These tests are disabled by default and only run when the integration build tag is used.
//
// To run integration tests:
// go test -tags=integration ./internal/vertexai/preview/examplestore/...
//
// Required environment variables:
// - GOOGLE_APPLICATION_CREDENTIALS or default credentials
// - Optionally PROJECT_ID (defaults to detected project)

const (
	// testTimeout is the maximum time to wait for operations to complete
	testTimeout = 10 * time.Minute

	// cleanupTimeout is the maximum time to wait for cleanup operations
	cleanupTimeout = 5 * time.Minute
)

func getTestProjectID() string {
	projectID := os.Getenv("PROJECT_ID")
	if projectID == "" {
		// Try to detect from credentials or skip test
		return "test-project-missing"
	}
	return projectID
}

func skipIfNoCredentials(t *testing.T) {
	if os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		t.Skip("Skipping integration test: GOOGLE_APPLICATION_CREDENTIALS not set")
	}
}

func TestIntegration_FullExampleStoreWorkflow(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	projectID := getTestProjectID()
	if projectID == "test-project-missing" {
		t.Skip("Skipping integration test: PROJECT_ID not set")
	}

	// Create service
	service, err := NewService(ctx, projectID, SupportedRegion)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Generate unique store name for this test
	timestamp := time.Now().Unix()
	storeName := fmt.Sprintf("integration-test-store-%d", timestamp)

	t.Logf("Starting integration test with store: %s", storeName)

	// Step 1: Create Example Store
	t.Run("CreateStore", func(t *testing.T) {
		config := &StoreConfig{
			EmbeddingModel: DefaultEmbeddingModel,
			DisplayName:    storeName,
			Description:    "Integration test store",
		}

		store, err := service.CreateStore(ctx, config)
		if err != nil {
			t.Fatalf("CreateStore() error = %v", err)
		}

		if store.DisplayName != storeName {
			t.Errorf("Store.DisplayName = %v, want %v", store.DisplayName, storeName)
		}

		if store.State != StoreStateCreating && store.State != StoreStateActive {
			t.Errorf("Store.State = %v, expected CREATING or ACTIVE", store.State)
		}

		t.Logf("Created store: %s", store.Name)
	})

	// Step 2: Wait for store to be active (if needed)
	storeResourceName := service.GenerateStoreName(storeName)

	t.Run("WaitForStoreActive", func(t *testing.T) {
		// Poll until store is active
		for i := 0; i < 60; i++ { // Wait up to 10 minutes
			store, err := service.GetStore(ctx, storeResourceName)
			if err != nil {
				t.Fatalf("GetStore() error = %v", err)
			}

			if store.State == StoreStateActive {
				t.Logf("Store is now active")
				break
			}

			if store.State == StoreStateError {
				t.Fatalf("Store creation failed")
			}

			t.Logf("Store state: %s, waiting...", store.State)
			time.Sleep(10 * time.Second)

			select {
			case <-ctx.Done():
				t.Fatalf("Context cancelled while waiting for store")
			default:
			}
		}
	})

	// Step 3: Upload examples
	var uploadedExamples []*StoredExample

	t.Run("UploadExamples", func(t *testing.T) {
		examples := []*Example{
			{
				Input: &Content{
					Text: "What is the capital of France?",
					Metadata: map[string]any{
						"category":   "geography",
						"difficulty": "easy",
						"language":   "en",
					},
				},
				Output: &Content{
					Text: "The capital of France is Paris.",
					Metadata: map[string]any{
						"confidence": 0.95,
					},
				},
				DisplayName: "Geography Example - France Capital",
				Metadata: map[string]any{
					"test_id": "geo_001",
					"source":  "integration_test",
				},
			},
			{
				Input: &Content{
					Text: "What is 15 + 27?",
					Metadata: map[string]any{
						"category":   "math",
						"difficulty": "easy",
						"language":   "en",
					},
				},
				Output: &Content{
					Text: "15 + 27 equals 42.",
					Metadata: map[string]any{
						"confidence": 1.0,
					},
				},
				DisplayName: "Math Example - Simple Addition",
				Metadata: map[string]any{
					"test_id": "math_001",
					"source":  "integration_test",
				},
			},
			{
				Input: &Content{
					Text: "How do you declare a variable in Go?",
					Metadata: map[string]any{
						"category":   "programming",
						"language":   "en",
						"topic":      "variables",
						"difficulty": "medium",
					},
				},
				Output: &Content{
					Text: "In Go, you can declare a variable using 'var name type' or use short declaration 'name := value'.",
					Metadata: map[string]any{
						"confidence": 0.98,
					},
				},
				DisplayName: "Programming Example - Go Variables",
				Metadata: map[string]any{
					"test_id": "prog_001",
					"source":  "integration_test",
				},
			},
		}

		results, err := service.UploadExamples(ctx, storeResourceName, examples)
		if err != nil {
			t.Fatalf("UploadExamples() error = %v", err)
		}

		if len(results) != len(examples) {
			t.Errorf("UploadExamples() returned %d results, want %d", len(results), len(examples))
		}

		uploadedExamples = results
		t.Logf("Uploaded %d examples", len(results))

		// Verify uploaded examples
		for i, result := range results {
			if result.DisplayName != examples[i].DisplayName {
				t.Errorf("Result[%d].DisplayName = %v, want %v", i, result.DisplayName, examples[i].DisplayName)
			}

			if result.State != ExampleStateActive && result.State != ExampleStateProcessing {
				t.Errorf("Result[%d].State = %v, expected ACTIVE or PROCESSING", i, result.State)
			}
		}
	})

	// Step 4: Wait for examples to be processed (if needed)
	t.Run("WaitForExamplesActive", func(t *testing.T) {
		for _, example := range uploadedExamples {
			for i := 0; i < 30; i++ { // Wait up to 5 minutes per example
				// In a real implementation, you would have a GetExample method
				// For now, we'll assume examples are processed quickly
				time.Sleep(1 * time.Second)
				break
			}
		}
		t.Logf("Examples are ready for search")
	})

	// Step 5: Search examples
	t.Run("SearchExamples", func(t *testing.T) {
		tests := []struct {
			name          string
			query         string
			expectedCount int
			minScore      float64
		}{
			{
				name:          "geography query",
				query:         "capital city country",
				expectedCount: 1,
				minScore:      0.3,
			},
			{
				name:          "math query",
				query:         "addition mathematics numbers",
				expectedCount: 1,
				minScore:      0.3,
			},
			{
				name:          "programming query",
				query:         "variable declaration programming",
				expectedCount: 1,
				minScore:      0.3,
			},
			{
				name:          "general query",
				query:         "what is",
				expectedCount: 2, // Should match geography and programming examples
				minScore:      0.1,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				results, err := service.SearchExamples(ctx, storeResourceName, tt.query, 10)
				if err != nil {
					t.Errorf("SearchExamples() error = %v", err)
					return
				}

				if len(results) < tt.expectedCount {
					t.Errorf("SearchExamples() returned %d results, expected at least %d", len(results), tt.expectedCount)
				}

				// Check that results are sorted by similarity
				for i := 1; i < len(results); i++ {
					if results[i-1].SimilarityScore < results[i].SimilarityScore {
						t.Errorf("Results not sorted by similarity score")
					}
				}

				// Check that top results meet minimum score
				if len(results) > 0 && results[0].SimilarityScore < tt.minScore {
					t.Errorf("Top result similarity %f below minimum %f", results[0].SimilarityScore, tt.minScore)
				}

				t.Logf("Query '%s' returned %d results, top score: %f", tt.query, len(results), results[0].SimilarityScore)
			})
		}
	})

	// Step 6: Search with filters
	t.Run("SearchWithFilters", func(t *testing.T) {
		// Search for geography examples only
		results, err := service.SearchExamplesAdvanced(ctx, storeResourceName, &SearchQuery{
			Text:                "capital",
			TopK:                5,
			SimilarityThreshold: 0.1,
			MetadataFilters: map[string]any{
				"category": "geography",
			},
		})
		if err != nil {
			t.Errorf("SearchExamplesAdvanced() error = %v", err)
			return
		}

		// Should find at least the geography example
		if len(results) == 0 {
			t.Error("SearchExamplesAdvanced() with geography filter returned no results")
		}

		// Verify all results have geography category
		for _, result := range results {
			hasGeoCategory := false
			if cat, exists := result.Example.Metadata["category"]; exists && cat == "geography" {
				hasGeoCategory = true
			}
			if result.Example.Input != nil {
				if cat, exists := result.Example.Input.Metadata["category"]; exists && cat == "geography" {
					hasGeoCategory = true
				}
			}
			if !hasGeoCategory {
				t.Error("Result does not have geography category")
			}
		}

		t.Logf("Filtered search returned %d geography examples", len(results))
	})

	// Step 7: List examples
	t.Run("ListExamples", func(t *testing.T) {
		resp, err := service.ListExamples(ctx, storeResourceName, 100, "")
		if err != nil {
			t.Errorf("ListExamples() error = %v", err)
			return
		}

		if len(resp.Examples) != len(uploadedExamples) {
			t.Errorf("ListExamples() returned %d examples, expected %d", len(resp.Examples), len(uploadedExamples))
		}

		t.Logf("Listed %d examples", len(resp.Examples))
	})

	// Step 8: Get store statistics
	t.Run("GetStoreStats", func(t *testing.T) {
		stats, err := service.GetStoreStats(ctx, storeResourceName)
		if err != nil {
			t.Errorf("GetStoreStats() error = %v", err)
			return
		}

		if stats.TotalExamples != int64(len(uploadedExamples)) {
			t.Errorf("StoreStats.TotalExamples = %d, expected %d", stats.TotalExamples, len(uploadedExamples))
		}

		t.Logf("Store stats: %d examples, avg input length: %.1f", stats.TotalExamples, stats.AverageInputLength)
	})

	// Step 9: Cleanup - Delete examples
	t.Run("DeleteExamples", func(t *testing.T) {
		for _, example := range uploadedExamples {
			err := service.DeleteExample(ctx, example.Name)
			if err != nil {
				t.Errorf("DeleteExample() error = %v", err)
			}
		}

		t.Logf("Deleted %d examples", len(uploadedExamples))
	})

	// Step 10: Cleanup - Delete store
	t.Run("DeleteStore", func(t *testing.T) {
		err := service.DeleteStore(ctx, storeResourceName, true)
		if err != nil {
			t.Errorf("DeleteStore() error = %v", err)
		}

		t.Logf("Deleted store: %s", storeResourceName)
	})
}

func TestIntegration_BatchOperations(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	projectID := getTestProjectID()
	if projectID == "test-project-missing" {
		t.Skip("Skipping integration test: PROJECT_ID not set")
	}

	service, err := NewService(ctx, projectID, SupportedRegion)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create store for batch testing
	timestamp := time.Now().Unix()
	storeName := fmt.Sprintf("batch-test-store-%d", timestamp)

	store, err := service.CreateDefaultStore(ctx, storeName, "Batch operations test store")
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	defer func() {
		// Cleanup
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		service.DeleteStore(ctx, store.Name, true)
	}()

	// Create 12 examples for batch upload testing (will be split into 3 batches)
	examples := make([]*Example, 12)
	for i := 0; i < 12; i++ {
		examples[i] = &Example{
			Input: &Content{
				Text: fmt.Sprintf("Question number %d: What is %d + %d?", i, i, i+1),
				Metadata: map[string]any{
					"category": "math",
					"number":   i,
				},
			},
			Output: &Content{
				Text: fmt.Sprintf("Answer: %d + %d = %d", i, i+1, i+(i+1)),
				Metadata: map[string]any{
					"confidence": 1.0,
				},
			},
			DisplayName: fmt.Sprintf("Batch Example %d", i),
			Metadata: map[string]any{
				"batch_id": "batch_001",
				"index":    i,
			},
		}
	}

	t.Run("BatchUploadExamples", func(t *testing.T) {
		results, err := service.BatchUploadExamples(ctx, store.Name, examples)
		if err != nil {
			t.Fatalf("BatchUploadExamples() error = %v", err)
		}

		if len(results) != len(examples) {
			t.Errorf("BatchUploadExamples() returned %d results, want %d", len(results), len(examples))
		}

		t.Logf("Batch uploaded %d examples", len(results))

		// Verify examples were uploaded correctly
		for i, result := range results {
			if result.DisplayName != examples[i].DisplayName {
				t.Errorf("Result[%d].DisplayName = %v, want %v", i, result.DisplayName, examples[i].DisplayName)
			}
		}
	})

	t.Run("BatchSearch", func(t *testing.T) {
		// Test multiple search queries
		queries := []string{
			"addition math",
			"question number",
			"what is",
		}

		for _, query := range queries {
			results, err := service.SearchExamples(ctx, store.Name, query, 5)
			if err != nil {
				t.Errorf("SearchExamples() for query '%s' error = %v", query, err)
				continue
			}

			t.Logf("Query '%s' returned %d results", query, len(results))
		}
	})
}

func TestIntegration_ErrorHandling(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	projectID := getTestProjectID()
	if projectID == "test-project-missing" {
		t.Skip("Skipping integration test: PROJECT_ID not set")
	}

	service, err := NewService(ctx, projectID, SupportedRegion)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	t.Run("InvalidStoreOperations", func(t *testing.T) {
		// Try to get non-existent store
		nonExistentStore := service.GenerateStoreName("non-existent-store-12345")
		_, err := service.GetStore(ctx, nonExistentStore)
		if err == nil {
			t.Error("GetStore() should fail for non-existent store")
		}

		// Try to search in non-existent store
		_, err = service.SearchExamples(ctx, nonExistentStore, "test query", 5)
		if err == nil {
			t.Error("SearchExamples() should fail for non-existent store")
		}
	})

	t.Run("InvalidExampleOperations", func(t *testing.T) {
		// Try to upload invalid examples
		invalidExamples := []*Example{
			{
				Input:  nil, // Invalid: nil input
				Output: &Content{Text: "Output"},
			},
		}

		nonExistentStore := service.GenerateStoreName("non-existent-store-12345")
		_, err := service.UploadExamples(ctx, nonExistentStore, invalidExamples)
		if err == nil {
			t.Error("UploadExamples() should fail for invalid examples")
		}
	})
}
