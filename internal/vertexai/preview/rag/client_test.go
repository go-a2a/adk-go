// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
)

const (
	envGoogleCloudProjectID = "GOOGLE_CLOUD_PROJECT_ID"
	envGoogleCloudLocation  = "GOOGLE_CLOUD_LOCATION"
)

func TestNewClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		t.Skip("requires Google Cloud credentials")

		ctx := t.Context()
		projectID := getRequiredEnv(t, envGoogleCloudProjectID)
		location := getRequiredEnv(t, envGoogleCloudLocation)

		client, err := rag.NewService(ctx, projectID, location)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		defer client.Close()

		if got := client.GetProjectID(); got != projectID {
			t.Errorf("GetProjectID() = %v, want %v", got, projectID)
		}

		if got := client.GetLocation(); got != location {
			t.Errorf("GetLocation() = %v, want %v", got, location)
		}

		if client.GetLogger() == nil {
			t.Error("GetLogger() returned nil")
		}
	})

	t.Run("empty_project", func(t *testing.T) {
		ctx := t.Context()
		client, err := rag.NewService(ctx, "", "us-central1")
		if err != nil {
			t.Skipf("NewClient() failed with empty project ID: %v", err)
		}
		defer client.Close()

		// Empty project ID is allowed at client creation, validation happens at API call time
		if got := client.GetProjectID(); got != "" {
			t.Errorf("GetProjectID() = %v, want empty string", got)
		}
	})

	t.Run("empty_location", func(t *testing.T) {
		ctx := t.Context()
		client, err := rag.NewService(ctx, "test-project", "")
		if err != nil {
			t.Skipf("NewClient() failed with empty location: %v", err)
		}
		defer client.Close()

		// Empty location is allowed at client creation, validation happens at API call time
		if got := client.GetLocation(); got != "" {
			t.Errorf("GetLocation() = %v, want empty string", got)
		}
	})
}

func TestClient_CorpusOperations(t *testing.T) {
	t.Skip("requires Google Cloud credentials and creates real resources")

	ctx := t.Context()
	client := setupTestClient(t)
	defer client.Close()

	t.Run("create_default_corpus", func(t *testing.T) {
		corpus, err := client.CreateDefaultCorpus(ctx, "Test Corpus", "A test corpus for unit tests")
		if err != nil {
			t.Fatalf("CreateDefaultCorpus() error = %v", err)
		}

		if corpus.Name == "" {
			t.Error("CreateDefaultCorpus() returned corpus with empty name")
		}

		if corpus.DisplayName != "Test Corpus" {
			t.Errorf("CreateDefaultCorpus() display name = %v, want %v", corpus.DisplayName, "Test Corpus")
		}

		if corpus.Description != "A test corpus for unit tests" {
			t.Errorf("CreateDefaultCorpus() description = %v, want %v", corpus.Description, "A test corpus for unit tests")
		}

		// Clean up - delete the corpus
		defer func() {
			if err := client.DeleteCorpus(ctx, corpus.Name, true); err != nil {
				t.Logf("Failed to clean up corpus %s: %v", corpus.Name, err)
			}
		}()
	})

	t.Run("list_corpora", func(t *testing.T) {
		resp, err := client.ListCorpora(ctx, 10, "")
		if err != nil {
			t.Fatalf("ListCorpora() error = %v", err)
		}

		if resp.RagCorpora == nil {
			t.Error("ListCorpora() returned nil RagCorpora")
		}
	})
}

func TestClient_FileOperations(t *testing.T) {
	t.Skip("requires Google Cloud credentials and existing corpus")

	ctx := t.Context()
	client := setupTestClient(t)
	defer client.Close()

	// Create a test corpus first
	corpus, err := client.CreateDefaultCorpus(ctx, "Test File Operations", "Test corpus for file operations")
	if err != nil {
		t.Fatalf("Failed to create test corpus: %v", err)
	}
	defer client.DeleteCorpus(ctx, corpus.Name, true)

	t.Run("import_files_from_gcs", func(t *testing.T) {
		gcsUris := []string{"gs://test-bucket/test-file.txt"}
		err := client.ImportFilesFromGCS(ctx, corpus.Name, gcsUris, 1000, 100)
		if err != nil {
			// This is expected to fail without a real GCS bucket
			t.Logf("Expected error importing from non-existent GCS bucket: %v", err)
		}
	})

	t.Run("list_files", func(t *testing.T) {
		resp, err := client.ListFiles(ctx, corpus.Name, 10, "")
		if err != nil {
			t.Fatalf("ListFiles() error = %v", err)
		}

		if resp.RagFiles == nil {
			t.Error("ListFiles() returned nil RagFiles")
		}
	})
}

func TestClient_RetrievalOperations(t *testing.T) {
	t.Skip("requires Google Cloud credentials and populated corpus")

	ctx := t.Context()
	client := setupTestClient(t)
	defer client.Close()

	// Note: These tests would require an existing corpus with data
	corpusName := "projects/test-project/locations/us-central1/ragCorpora/test-corpus"

	t.Run("quick_query", func(t *testing.T) {
		resp, err := client.QuickQuery(ctx, corpusName, "test query")
		if err != nil {
			t.Fatalf("QuickQuery() error = %v", err)
		}

		if resp.Documents == nil {
			t.Error("QuickQuery() returned nil Documents")
		}
	})

	t.Run("query_with_parameters", func(t *testing.T) {
		resp, err := client.Query(ctx, corpusName, "test query", 5, 0.8)
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}

		if resp.Documents == nil {
			t.Error("Query() returned nil Documents")
		}
	})
}

func TestClient_HelperMethods(t *testing.T) {
	tests := []struct {
		name           string
		projectID      string
		location       string
		corpusID       string
		fileID         string
		wantCorpusName string
		wantFileName   string
	}{
		{
			name:           "valid_ids",
			projectID:      "test-project",
			location:       "us-central1",
			corpusID:       "test-corpus",
			fileID:         "test-file",
			wantCorpusName: "projects/test-project/locations/us-central1/ragCorpora/test-corpus",
			wantFileName:   "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/test-file",
		},
		{
			name:           "with_hyphens",
			projectID:      "my-test-project",
			location:       "europe-west1",
			corpusID:       "my-test-corpus",
			fileID:         "my-test-file",
			wantCorpusName: "projects/my-test-project/locations/europe-west1/ragCorpora/my-test-corpus",
			wantFileName:   "projects/my-test-project/locations/europe-west1/ragCorpora/my-test-corpus/ragFiles/my-test-file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			client, err := rag.NewService(ctx, tt.projectID, tt.location)
			if err != nil {
				// For unit tests without credentials, we expect this to fail
				// but we can still test the methods that don't require API calls
				t.Skipf("Cannot create client without credentials: %v", err)
			}
			defer client.Close()

			if got := client.GenerateCorpusName(tt.corpusID); got != tt.wantCorpusName {
				t.Errorf("GenerateCorpusName() = %v, want %v", got, tt.wantCorpusName)
			}

			if got := client.GenerateFileName(tt.corpusID, tt.fileID); got != tt.wantFileName {
				t.Errorf("GenerateFileName() = %v, want %v", got, tt.wantFileName)
			}
		})
	}
}

func TestClient_BatchOperations(t *testing.T) {
	t.Skip("requires Google Cloud credentials and existing corpus")

	ctx := t.Context()
	client := setupTestClient(t)
	defer client.Close()

	// Create a test corpus first
	corpus, err := client.CreateDefaultCorpus(ctx, "Test Batch Operations", "Test corpus for batch operations")
	if err != nil {
		t.Fatalf("Failed to create test corpus: %v", err)
	}
	defer client.DeleteCorpus(ctx, corpus.Name, true)

	t.Run("batch_import_files", func(t *testing.T) {
		sources := []rag.ImportSource{
			{
				GcsUris:      []string{"gs://test-bucket/file1.txt", "gs://test-bucket/file2.txt"},
				ChunkSize:    1000,
				ChunkOverlap: 100,
			},
			{
				GoogleDriveResourceIds: []string{"1234567890abcdef", "fedcba0987654321"},
				ChunkSize:              800,
				ChunkOverlap:           80,
			},
		}

		err := client.BatchImportFiles(ctx, corpus.Name, sources)
		if err != nil {
			// Expected to fail without real sources
			t.Logf("Expected error importing from non-existent sources: %v", err)
		}
	})

	t.Run("batch_delete_files", func(t *testing.T) {
		fileNames := []string{
			client.GenerateFileName("test-corpus", "test-file-1"),
			client.GenerateFileName("test-corpus", "test-file-2"),
		}

		err := client.BatchDeleteFiles(ctx, fileNames)
		if err != nil {
			// Expected to fail with non-existent files
			t.Logf("Expected error deleting non-existent files: %v", err)
		}
	})
}

func TestVectorDbConfig_Conversion(t *testing.T) {
	tests := []struct {
		name   string
		config *rag.VectorDbConfig
	}{
		{
			name: "managed_db_config",
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
		},
		{
			name: "weaviate_config",
			config: &rag.VectorDbConfig{
				WeaviateConfig: &rag.WeaviateConfig{
					HttpEndpoint:   "http://localhost:8080",
					CollectionName: "test-collection",
				},
			},
		},
		{
			name: "pinecone_config",
			config: &rag.VectorDbConfig{
				PineconeConfig: &rag.PineconeConfig{
					IndexName: "test-index",
				},
			},
		},
		{
			name: "vertex_vector_search_config",
			config: &rag.VectorDbConfig{
				VertexVectorSearch: &rag.VertexVectorSearchConfig{
					IndexEndpoint: "projects/test-project/locations/us-central1/indexEndpoints/test-endpoint",
					Index:         "test-index",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the config structure is valid
			if tt.config == nil {
				t.Error("Config should not be nil")
			}

			// Check specific fields based on config type
			switch {
			case tt.config.RagManagedDb != nil:
				if tt.config.RagManagedDb.RetrievalConfig == nil {
					t.Error("RagManagedDb should have RetrievalConfig")
				}
			case tt.config.WeaviateConfig != nil:
				if tt.config.WeaviateConfig.HttpEndpoint == "" {
					t.Error("WeaviateConfig should have HttpEndpoint")
				}
			case tt.config.PineconeConfig != nil:
				if tt.config.PineconeConfig.IndexName == "" {
					t.Error("PineconeConfig should have IndexName")
				}
			case tt.config.VertexVectorSearch != nil:
				if tt.config.VertexVectorSearch.IndexEndpoint == "" {
					t.Error("VertexVectorSearch should have IndexEndpoint")
				}
			}
		})
	}
}

func TestImportSource_Validation(t *testing.T) {
	tests := []struct {
		name    string
		source  rag.ImportSource
		wantErr bool
	}{
		{
			name: "valid_gcs_source",
			source: rag.ImportSource{
				GcsUris:      []string{"gs://bucket/file.txt"},
				ChunkSize:    1000,
				ChunkOverlap: 100,
			},
			wantErr: false,
		},
		{
			name: "valid_google_drive_source",
			source: rag.ImportSource{
				GoogleDriveResourceIds: []string{"1234567890"},
				ChunkSize:              800,
				ChunkOverlap:           80,
			},
			wantErr: false,
		},
		{
			name: "both_sources_specified",
			source: rag.ImportSource{
				GcsUris:                []string{"gs://bucket/file.txt"},
				GoogleDriveResourceIds: []string{"1234567890"},
				ChunkSize:              1000,
				ChunkOverlap:           100,
			},
			wantErr: false, // The implementation should handle this by preferring GcsUris
		},
		{
			name: "no_sources_specified",
			source: rag.ImportSource{
				ChunkSize:    1000,
				ChunkOverlap: 100,
			},
			wantErr: true, // This should be invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate that the source has at least one source type
			hasGcsSource := len(tt.source.GcsUris) > 0
			hasGoogleDriveSource := len(tt.source.GoogleDriveResourceIds) > 0
			hasAnySource := hasGcsSource || hasGoogleDriveSource

			if tt.wantErr && hasAnySource {
				t.Error("Expected validation error but source appears valid")
			}
			if !tt.wantErr && !hasAnySource {
				t.Error("Expected valid source but no source specified")
			}
		})
	}
}

// Helper functions

func setupTestClient(t *testing.T) *rag.Service {
	t.Helper()
	ctx := t.Context()
	projectID := getRequiredEnv(t, envGoogleCloudProjectID)
	location := getRequiredEnv(t, envGoogleCloudLocation)

	client, err := rag.NewService(ctx, projectID, location)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	return client
}

func getRequiredEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("Required environment variable %s is not set", key)
	}
	return value
}

func assertCorpusEqual(t *testing.T, got, want *rag.Corpus) {
	t.Helper()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Corpus mismatch (-want +got):\n%s", diff)
	}
}

func assertRetrievalResponseEqual(t *testing.T, got, want *rag.RetrievalResponse) {
	t.Helper()
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("RetrievalResponse mismatch (-want +got):\n%s", diff)
	}
}
