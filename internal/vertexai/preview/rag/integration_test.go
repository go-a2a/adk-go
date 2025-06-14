// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
)

// TestRAGWorkflowIntegration tests the complete RAG workflow from corpus creation to retrieval.
// This test requires Google Cloud credentials and creates real resources.
func TestRAGWorkflowIntegration(t *testing.T) {
	t.Skip("requires Google Cloud credentials and creates real resources")

	ctx := t.Context()
	client := setupTestClient(t)
	defer client.Close()

	// Generate unique names for test resources
	timestamp := time.Now().Unix()
	corpusDisplayName := fmt.Sprintf("Integration Test Corpus %d", timestamp)
	corpusDescription := fmt.Sprintf("Test corpus created at %d for integration testing", timestamp)

	// Step 1: Create a test corpus
	t.Log("Creating test corpus...")
	corpus, err := client.CreateDefaultCorpus(ctx, corpusDisplayName, corpusDescription)
	if err != nil {
		t.Fatalf("Failed to create test corpus: %v", err)
	}
	t.Logf("Created corpus: %s", corpus.Name)

	// Ensure cleanup even if test fails
	defer func() {
		t.Log("Cleaning up test corpus...")
		if err := client.DeleteCorpus(ctx, corpus.Name, true); err != nil {
			t.Logf("Failed to clean up corpus %s: %v", corpus.Name, err)
		} else {
			t.Logf("Successfully cleaned up corpus: %s", corpus.Name)
		}
	}()

	// Validate corpus creation
	if corpus.DisplayName != corpusDisplayName {
		t.Errorf("Corpus display name = %v, want %v", corpus.DisplayName, corpusDisplayName)
	}
	if corpus.Description != corpusDescription {
		t.Errorf("Corpus description = %v, want %v", corpus.Description, corpusDescription)
	}
	if corpus.State != rag.CorpusStateActive {
		t.Errorf("Corpus state = %v, want %v", corpus.State, rag.CorpusStateActive)
	}

	// Step 2: Test corpus retrieval
	t.Log("Testing corpus retrieval...")
	retrievedCorpus, err := client.GetCorpus(ctx, corpus.Name)
	if err != nil {
		t.Fatalf("Failed to retrieve corpus: %v", err)
	}

	if retrievedCorpus.Name != corpus.Name {
		t.Errorf("Retrieved corpus name = %v, want %v", retrievedCorpus.Name, corpus.Name)
	}

	// Step 3: List corpora and verify our corpus is included
	t.Log("Testing corpus listing...")
	listResp, err := client.ListCorpora(ctx, 50, "")
	if err != nil {
		t.Fatalf("Failed to list corpora: %v", err)
	}

	found := false
	for _, c := range listResp.RagCorpora {
		if c.Name == corpus.Name {
			found = true
			break
		}
	}
	if !found {
		t.Error("Created corpus not found in list response")
	}

	// Step 4: Test file operations (this will fail without real files, but tests the API)
	t.Log("Testing file operations...")

	// Try to list files (should be empty initially)
	filesResp, err := client.ListFiles(ctx, corpus.Name, 10, "")
	if err != nil {
		t.Fatalf("Failed to list files: %v", err)
	}
	if len(filesResp.RagFiles) != 0 {
		t.Errorf("Expected empty file list, got %d files", len(filesResp.RagFiles))
	}

	// Test import from GCS (expected to fail with non-existent bucket)
	t.Log("Testing GCS import (expected to fail)...")
	gcsUris := []string{"gs://non-existent-test-bucket/test-file.txt"}
	err = client.ImportFilesFromGCS(ctx, corpus.Name, gcsUris, 1000, 100)
	if err == nil {
		t.Log("GCS import unexpectedly succeeded (may indicate test bucket exists)")
	} else {
		t.Logf("GCS import failed as expected: %v", err)
	}

	// Step 5: Test retrieval operations (will return empty results)
	t.Log("Testing retrieval operations...")
	queryResp, err := client.QuickQuery(ctx, corpus.Name, "test query")
	if err != nil {
		t.Fatalf("Failed to query corpus: %v", err)
	}
	// Empty corpus should return empty results
	if len(queryResp.Documents) != 0 {
		t.Errorf("Expected empty query results, got %d documents", len(queryResp.Documents))
	}

	// Step 6: Test batch operations
	t.Log("Testing batch operations...")
	sources := []rag.ImportSource{
		{
			GcsUris:      []string{"gs://non-existent-bucket/file1.txt"},
			ChunkSize:    1000,
			ChunkOverlap: 100,
		},
	}
	err = client.BatchImportFiles(ctx, corpus.Name, sources)
	if err == nil {
		t.Log("Batch import unexpectedly succeeded")
	} else {
		t.Logf("Batch import failed as expected: %v", err)
	}

	t.Log("Integration test completed successfully")
}

// TestRAGErrorHandling tests error handling scenarios.
func TestRAGErrorHandling(t *testing.T) {
	t.Skip("requires Google Cloud credentials")

	ctx := t.Context()
	client := setupTestClient(t)
	defer client.Close()

	t.Run("get_nonexistent_corpus", func(t *testing.T) {
		nonexistentCorpus := client.GenerateCorpusName("nonexistent-corpus-12345")
		_, err := client.GetCorpus(ctx, nonexistentCorpus)
		if err == nil {
			t.Error("Expected error when getting nonexistent corpus")
		}
		t.Logf("Got expected error: %v", err)
	})

	t.Run("delete_nonexistent_corpus", func(t *testing.T) {
		nonexistentCorpus := client.GenerateCorpusName("nonexistent-corpus-12345")
		err := client.DeleteCorpus(ctx, nonexistentCorpus, false)
		if err == nil {
			t.Error("Expected error when deleting nonexistent corpus")
		}
		t.Logf("Got expected error: %v", err)
	})

	t.Run("list_files_nonexistent_corpus", func(t *testing.T) {
		nonexistentCorpus := client.GenerateCorpusName("nonexistent-corpus-12345")
		_, err := client.ListFiles(ctx, nonexistentCorpus, 10, "")
		if err == nil {
			t.Error("Expected error when listing files in nonexistent corpus")
		}
		t.Logf("Got expected error: %v", err)
	})

	t.Run("query_nonexistent_corpus", func(t *testing.T) {
		nonexistentCorpus := client.GenerateCorpusName("nonexistent-corpus-12345")
		_, err := client.QuickQuery(ctx, nonexistentCorpus, "test query")
		if err == nil {
			t.Error("Expected error when querying nonexistent corpus")
		}
		t.Logf("Got expected error: %v", err)
	})
}

// TestRAGConcurrency tests concurrent operations on RAG resources.
func TestRAGConcurrency(t *testing.T) {
	t.Skip("requires Google Cloud credentials and creates real resources")

	ctx := t.Context()
	client := setupTestClient(t)
	defer client.Close()

	// Create a test corpus
	timestamp := time.Now().Unix()
	corpus, err := client.CreateDefaultCorpus(ctx, fmt.Sprintf("Concurrency Test %d", timestamp), "Test corpus for concurrency testing")
	if err != nil {
		t.Fatalf("Failed to create test corpus: %v", err)
	}
	defer client.DeleteCorpus(ctx, corpus.Name, true)

	// Test concurrent queries
	t.Run("concurrent_queries", func(t *testing.T) {
		const numConcurrentQueries = 5
		queries := []string{
			"machine learning",
			"artificial intelligence",
			"data science",
			"neural networks",
			"deep learning",
		}

		results := make(chan error, numConcurrentQueries)

		for i := 0; i < numConcurrentQueries; i++ {
			go func(query string) {
				_, err := client.QuickQuery(ctx, corpus.Name, query)
				results <- err
			}(queries[i%len(queries)])
		}

		// Collect results
		for i := 0; i < numConcurrentQueries; i++ {
			if err := <-results; err != nil {
				t.Errorf("Concurrent query %d failed: %v", i, err)
			}
		}
	})

	// Test concurrent file listings
	t.Run("concurrent_file_listings", func(t *testing.T) {
		const numConcurrentLists = 3
		results := make(chan error, numConcurrentLists)

		for i := 0; i < numConcurrentLists; i++ {
			go func() {
				_, err := client.ListFiles(ctx, corpus.Name, 10, "")
				results <- err
			}()
		}

		// Collect results
		for i := 0; i < numConcurrentLists; i++ {
			if err := <-results; err != nil {
				t.Errorf("Concurrent file listing %d failed: %v", i, err)
			}
		}
	})
}

// TestRAGResourceNaming tests resource naming utilities.
func TestRAGResourceNaming(t *testing.T) {
	tests := []struct {
		name       string
		projectID  string
		location   string
		corpusID   string
		fileID     string
		wantCorpus string
		wantFile   string
	}{
		{
			name:       "simple_names",
			projectID:  "test-project",
			location:   "us-central1",
			corpusID:   "test-corpus",
			fileID:     "test-file",
			wantCorpus: "projects/test-project/locations/us-central1/ragCorpora/test-corpus",
			wantFile:   "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/test-file",
		},
		{
			name:       "hyphenated_names",
			projectID:  "my-test-project-123",
			location:   "europe-west4",
			corpusID:   "my-test-corpus-abc",
			fileID:     "my-test-file-xyz",
			wantCorpus: "projects/my-test-project-123/locations/europe-west4/ragCorpora/my-test-corpus-abc",
			wantFile:   "projects/my-test-project-123/locations/europe-west4/ragCorpora/my-test-corpus-abc/ragFiles/my-test-file-xyz",
		},
		{
			name:       "numeric_ids",
			projectID:  "project-12345",
			location:   "asia-southeast1",
			corpusID:   "corpus-67890",
			fileID:     "file-99999",
			wantCorpus: "projects/project-12345/locations/asia-southeast1/ragCorpora/corpus-67890",
			wantFile:   "projects/project-12345/locations/asia-southeast1/ragCorpora/corpus-67890/ragFiles/file-99999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Skip actual client creation for unit test
			if testing.Short() {
				t.Skip("skipping in short mode")
			}

			// For the naming test, we can create a client but don't need valid credentials
			// since we're only testing the helper methods
			client, err := rag.NewService(ctx, tt.projectID, tt.location)
			if err != nil {
				// Expected to fail without credentials, but we can still test if we have them
				t.Skipf("Cannot create client without credentials: %v", err)
			}
			defer client.Close()

			gotCorpus := client.GenerateCorpusName(tt.corpusID)
			if gotCorpus != tt.wantCorpus {
				t.Errorf("GenerateCorpusName() = %v, want %v", gotCorpus, tt.wantCorpus)
			}

			gotFile := client.GenerateFileName(tt.corpusID, tt.fileID)
			if gotFile != tt.wantFile {
				t.Errorf("GenerateFileName() = %v, want %v", gotFile, tt.wantFile)
			}
		})
	}
}

// TestRAGConfigurationPatterns tests different configuration patterns.
func TestRAGConfigurationPatterns(t *testing.T) {
	tests := []struct {
		name   string
		config *rag.VectorDbConfig
		valid  bool
	}{
		{
			name: "default_managed_config",
			config: &rag.VectorDbConfig{
				RagEmbeddingModelConfig: &rag.EmbeddingModelConfig{
					PublisherModel: "publishers/google/models/text-embedding-005",
				},
				RagManagedDb: &rag.RagManagedDbConfig{
					RetrievalConfig: &rag.RetrievalConfig{
						TopK:        10,
						MaxDistance: 0.7,
					},
				},
			},
			valid: true,
		},
		{
			name: "weaviate_config",
			config: &rag.VectorDbConfig{
				RagEmbeddingModelConfig: &rag.EmbeddingModelConfig{
					PublisherModel: "publishers/google/models/text-embedding-005",
				},
				WeaviateConfig: &rag.WeaviateConfig{
					HttpEndpoint:   "http://weaviate.example.com:8080",
					CollectionName: "my_documents",
				},
			},
			valid: true,
		},
		{
			name: "pinecone_config",
			config: &rag.VectorDbConfig{
				RagEmbeddingModelConfig: &rag.EmbeddingModelConfig{
					PublisherModel: "publishers/google/models/text-embedding-005",
				},
				PineconeConfig: &rag.PineconeConfig{
					IndexName: "my-pinecone-index",
				},
			},
			valid: true,
		},
		{
			name: "vertex_vector_search_config",
			config: &rag.VectorDbConfig{
				RagEmbeddingModelConfig: &rag.EmbeddingModelConfig{
					PublisherModel: "publishers/google/models/text-embedding-005",
				},
				VertexVectorSearch: &rag.VertexVectorSearchConfig{
					IndexEndpoint: "projects/test-project/locations/us-central1/indexEndpoints/12345",
					Index:         "my-vector-index",
				},
			},
			valid: true,
		},
		{
			name: "custom_embedding_endpoint",
			config: &rag.VectorDbConfig{
				RagEmbeddingModelConfig: &rag.EmbeddingModelConfig{
					Endpoint: "https://my-custom-embedding-service.com/v1/embeddings",
					Model:    "custom-embedding-model",
				},
				RagManagedDb: &rag.RagManagedDbConfig{
					RetrievalConfig: &rag.RetrievalConfig{
						TopK:        5,
						MaxDistance: 0.8,
					},
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate configuration structure
			if tt.config == nil && tt.valid {
				t.Error("Valid config should not be nil")
				return
			}

			if tt.config.RagEmbeddingModelConfig == nil && tt.valid {
				t.Error("Valid config should have embedding model config")
			}

			// Count backend configurations
			backendCount := 0
			if tt.config.RagManagedDb != nil {
				backendCount++
			}
			if tt.config.WeaviateConfig != nil {
				backendCount++
			}
			if tt.config.PineconeConfig != nil {
				backendCount++
			}
			if tt.config.VertexVectorSearch != nil {
				backendCount++
			}

			if backendCount != 1 && tt.valid {
				t.Errorf("Valid config should have exactly one backend, got %d", backendCount)
			}

			// Validate embedding config
			if tt.config.RagEmbeddingModelConfig != nil {
				embeddingConfig := tt.config.RagEmbeddingModelConfig
				hasPublisher := embeddingConfig.PublisherModel != ""
				hasCustom := embeddingConfig.Endpoint != "" && embeddingConfig.Model != ""

				if !hasPublisher && !hasCustom && tt.valid {
					t.Error("Valid embedding config should have either publisher model or custom endpoint")
				}

				if hasPublisher && hasCustom && tt.valid {
					t.Error("Embedding config should not have both publisher and custom endpoint")
				}
			}
		})
	}
}

// BenchmarkRAGOperations benchmarks various RAG operations.
func BenchmarkRAGOperations(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	b.Skip("requires Google Cloud credentials")

	ctx := context.Background()
	projectID := os.Getenv(envGoogleCloudProjectID)
	location := os.Getenv(envGoogleCloudLocation)

	if projectID == "" || location == "" {
		b.Skip("Benchmark requires GOOGLE_CLOUD_PROJECT_ID and GOOGLE_CLOUD_LOCATION")
	}

	client, err := rag.NewService(ctx, projectID, location)
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Create a test corpus for benchmarking
	corpus, err := client.CreateDefaultCorpus(ctx, "Benchmark Corpus", "Corpus for benchmarking")
	if err != nil {
		b.Fatalf("Failed to create benchmark corpus: %v", err)
	}
	defer client.DeleteCorpus(ctx, corpus.Name, true)

	b.Run("list_corpora", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.ListCorpora(ctx, 10, "")
			if err != nil {
				b.Fatalf("ListCorpora failed: %v", err)
			}
		}
	})

	b.Run("get_corpus", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.GetCorpus(ctx, corpus.Name)
			if err != nil {
				b.Fatalf("GetCorpus failed: %v", err)
			}
		}
	})

	b.Run("list_files", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.ListFiles(ctx, corpus.Name, 10, "")
			if err != nil {
				b.Fatalf("ListFiles failed: %v", err)
			}
		}
	})

	b.Run("query_corpus", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.QuickQuery(ctx, corpus.Name, "benchmark query")
			if err != nil {
				b.Fatalf("QuickQuery failed: %v", err)
			}
		}
	})
}
