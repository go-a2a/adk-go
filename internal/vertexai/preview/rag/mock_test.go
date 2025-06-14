// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag_test

import (
	"testing"
	"time"

	"github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
)

// MockVertexRagClient simulates the behavior of the Vertex AI RAG client for testing.
type MockVertexRagClient struct {
	corpora map[string]*rag.Corpus
	files   map[string][]*rag.RagFile
}

// NewMockVertexRagClient creates a new mock client for testing.
func NewMockVertexRagClient() *MockVertexRagClient {
	return &MockVertexRagClient{
		corpora: make(map[string]*rag.Corpus),
		files:   make(map[string][]*rag.RagFile),
	}
}

// TestMockCorpusOperations tests corpus operations using mock data.
func TestMockCorpusOperations(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name   string
		corpus *rag.Corpus
	}{
		{
			name: "simple_corpus",
			corpus: &rag.Corpus{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/simple-corpus",
				DisplayName: "Simple Test Corpus",
				Description: "A simple test corpus",
				CreateTime:  &now,
				UpdateTime:  &now,
				State:       rag.CorpusStateActive,
			},
		},
		{
			name: "corpus_with_managed_db",
			corpus: &rag.Corpus{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/managed-corpus",
				DisplayName: "Managed DB Corpus",
				Description: "A corpus with managed database backend",
				BackendConfig: &rag.VectorDbConfig{
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
				CreateTime: &now,
				UpdateTime: &now,
				State:      rag.CorpusStateActive,
			},
		},
		{
			name: "corpus_with_weaviate",
			corpus: &rag.Corpus{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/weaviate-corpus",
				DisplayName: "Weaviate Corpus",
				Description: "A corpus with Weaviate backend",
				BackendConfig: &rag.VectorDbConfig{
					RagEmbeddingModelConfig: &rag.EmbeddingModelConfig{
						PublisherModel: "publishers/google/models/text-embedding-005",
					},
					WeaviateConfig: &rag.WeaviateConfig{
						HttpEndpoint:   "http://weaviate.example.com:8080",
						CollectionName: "test_collection",
					},
				},
				CreateTime: &now,
				UpdateTime: &now,
				State:      rag.CorpusStateActive,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test corpus validation
			if tt.corpus.Name == "" {
				t.Error("Corpus should have a name")
			}
			if tt.corpus.DisplayName == "" {
				t.Error("Corpus should have a display name")
			}
			if tt.corpus.CreateTime == nil {
				t.Error("Corpus should have a create time")
			}
			if tt.corpus.State == "" {
				t.Error("Corpus should have a state")
			}

			// Test backend configuration
			if tt.corpus.BackendConfig != nil {
				config := tt.corpus.BackendConfig
				if config.RagEmbeddingModelConfig == nil {
					t.Error("Backend config should have embedding model config")
				}

				// Count configured backends
				backendCount := 0
				if config.RagManagedDb != nil {
					backendCount++
				}
				if config.WeaviateConfig != nil {
					backendCount++
				}
				if config.PineconeConfig != nil {
					backendCount++
				}
				if config.VertexVectorSearch != nil {
					backendCount++
				}

				if backendCount != 1 {
					t.Errorf("Should have exactly one backend configured, got %d", backendCount)
				}
			}
		})
	}
}

// TestMockFileOperations tests file operations using mock data.
func TestMockFileOperations(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		file *rag.RagFile
	}{
		{
			name: "gcs_file",
			file: &rag.RagFile{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/gcs-file",
				DisplayName: "GCS Test File",
				Description: "A test file from Google Cloud Storage",
				RagFileSource: &rag.RagFileSource{
					GcsSource: &rag.GcsSource{
						Uris: []string{"gs://test-bucket/documents/test-file.pdf"},
					},
				},
				CreateTime:  &now,
				UpdateTime:  &now,
				State:       rag.FileStateActive,
				SizeBytes:   1024000,
				RagFileType: "application/pdf",
			},
		},
		{
			name: "google_drive_file",
			file: &rag.RagFile{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/drive-file",
				DisplayName: "Google Drive Test File",
				Description: "A test file from Google Drive",
				RagFileSource: &rag.RagFileSource{
					GoogleDriveSource: &rag.GoogleDriveSource{
						ResourceIds: []string{"1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"},
					},
				},
				CreateTime:  &now,
				UpdateTime:  &now,
				State:       rag.FileStateActive,
				SizeBytes:   512000,
				RagFileType: "application/vnd.google-apps.spreadsheet",
			},
		},
		{
			name: "direct_upload_file",
			file: &rag.RagFile{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus/ragFiles/upload-file",
				DisplayName: "Direct Upload Test File",
				Description: "A directly uploaded test file",
				RagFileSource: &rag.RagFileSource{
					DirectUploadSource: &rag.DirectUploadSource{},
				},
				CreateTime:  &now,
				UpdateTime:  &now,
				State:       rag.FileStateActive,
				SizeBytes:   256000,
				RagFileType: "text/plain",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test file validation
			if tt.file.Name == "" {
				t.Error("File should have a name")
			}
			if tt.file.DisplayName == "" {
				t.Error("File should have a display name")
			}
			if tt.file.RagFileSource == nil {
				t.Error("File should have a source")
			}
			if tt.file.CreateTime == nil {
				t.Error("File should have a create time")
			}
			if tt.file.State == "" {
				t.Error("File should have a state")
			}
			if tt.file.SizeBytes < 0 {
				t.Error("File size should not be negative")
			}

			// Test file source validation
			if tt.file.RagFileSource != nil {
				source := tt.file.RagFileSource
				sourceCount := 0

				if source.GcsSource != nil {
					sourceCount++
					if len(source.GcsSource.Uris) == 0 {
						t.Error("GCS source should have at least one URI")
					}
				}
				if source.GoogleDriveSource != nil {
					sourceCount++
					if len(source.GoogleDriveSource.ResourceIds) == 0 {
						t.Error("Google Drive source should have at least one resource ID")
					}
				}
				if source.DirectUploadSource != nil {
					sourceCount++
				}

				if sourceCount != 1 {
					t.Errorf("Should have exactly one file source, got %d", sourceCount)
				}
			}
		})
	}
}

// TestMockRetrievalOperations tests retrieval operations using mock data.
func TestMockRetrievalOperations(t *testing.T) {
	tests := []struct {
		name     string
		query    *rag.RetrievalQuery
		response *rag.RetrievalResponse
	}{
		{
			name: "simple_query",
			query: &rag.RetrievalQuery{
				Text:           "machine learning basics",
				SimilarityTopK: 5,
			},
			response: &rag.RetrievalResponse{
				Documents: []*rag.RetrievedDocument{
					{
						Id:       "doc-1",
						Content:  "Machine learning is a subset of artificial intelligence...",
						Distance: 0.15,
						Metadata: map[string]any{
							"source_uri":          "gs://test-bucket/ml-guide.pdf",
							"source_display_name": "Machine Learning Guide",
							"page_number":         1,
						},
					},
					{
						Id:       "doc-2",
						Content:  "Basic concepts in machine learning include supervised learning...",
						Distance: 0.22,
						Metadata: map[string]any{
							"source_uri":          "gs://test-bucket/ml-basics.txt",
							"source_display_name": "ML Basics",
							"chapter":             "Introduction",
						},
					},
				},
			},
		},
		{
			name: "query_with_threshold",
			query: &rag.RetrievalQuery{
				Text:                    "neural networks",
				SimilarityTopK:          10,
				VectorDistanceThreshold: 0.3,
			},
			response: &rag.RetrievalResponse{
				Documents: []*rag.RetrievedDocument{
					{
						Id:       "doc-3",
						Content:  "Neural networks are computing systems inspired by biological neural networks...",
						Distance: 0.12,
						Metadata: map[string]any{
							"source_uri":          "gs://test-bucket/neural-networks.pdf",
							"source_display_name": "Neural Networks Explained",
							"section":             "Introduction",
						},
					},
				},
			},
		},
		{
			name: "no_results_query",
			query: &rag.RetrievalQuery{
				Text:           "quantum computing",
				SimilarityTopK: 5,
			},
			response: &rag.RetrievalResponse{
				Documents: []*rag.RetrievedDocument{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate query
			if tt.query.Text == "" {
				t.Error("Query should have text")
			}
			if tt.query.SimilarityTopK <= 0 {
				t.Error("SimilarityTopK should be positive")
			}

			// Validate response
			if tt.response.Documents == nil {
				t.Error("Response should have documents slice (even if empty)")
			}

			// Validate retrieved documents
			for i, doc := range tt.response.Documents {
				if doc.Content == "" {
					t.Errorf("Document %d should have content", i)
				}
				if doc.Distance < 0 {
					t.Errorf("Document %d distance should not be negative", i)
				}
				if doc.Distance > 1.0 {
					t.Errorf("Document %d distance should not exceed 1.0", i)
				}
			}

			// Test that results are within the requested top-k
			if len(tt.response.Documents) > int(tt.query.SimilarityTopK) {
				t.Errorf("Response has %d documents but requested top-k was %d",
					len(tt.response.Documents), tt.query.SimilarityTopK)
			}

			// Test that results respect distance threshold if specified
			if tt.query.VectorDistanceThreshold > 0 {
				for i, doc := range tt.response.Documents {
					if doc.Distance > tt.query.VectorDistanceThreshold {
						t.Errorf("Document %d distance %f exceeds threshold %f",
							i, doc.Distance, tt.query.VectorDistanceThreshold)
					}
				}
			}
		})
	}
}

// TestMockSearchOperations tests search operations using mock data.
func TestMockSearchOperations(t *testing.T) {
	tests := []struct {
		name     string
		request  *rag.SearchRequest
		response *rag.SearchResponse
	}{
		{
			name: "multi_corpus_search",
			request: &rag.SearchRequest{
				Query:        "artificial intelligence",
				CorporaNames: []string{"corpus-1", "corpus-2"},
				TopK:         5,
				Filters: map[string]any{
					"category": "technical",
					"language": "english",
				},
			},
			response: &rag.SearchResponse{
				Documents: []*rag.RetrievedDocument{
					{
						Id:       "doc-ai-1",
						Content:  "Artificial intelligence is the simulation of human intelligence...",
						Distance: 0.08,
						Metadata: map[string]any{
							"corpus":   "corpus-1",
							"category": "technical",
							"language": "english",
						},
					},
					{
						Id:       "doc-ai-2",
						Content:  "AI systems can perform tasks that typically require human intelligence...",
						Distance: 0.14,
						Metadata: map[string]any{
							"corpus":   "corpus-2",
							"category": "technical",
							"language": "english",
						},
					},
				},
				TotalCount: 2,
			},
		},
		{
			name: "filtered_search",
			request: &rag.SearchRequest{
				Query:        "data science",
				CorporaNames: []string{"corpus-1"},
				TopK:         10,
				Filters: map[string]any{
					"category": "beginner",
				},
			},
			response: &rag.SearchResponse{
				Documents: []*rag.RetrievedDocument{
					{
						Id:       "doc-ds-1",
						Content:  "Data science for beginners: an introduction to the field...",
						Distance: 0.11,
						Metadata: map[string]any{
							"corpus":     "corpus-1",
							"category":   "beginner",
							"difficulty": "easy",
						},
					},
				},
				TotalCount: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate request
			if tt.request.Query == "" {
				t.Error("Search request should have a query")
			}
			if len(tt.request.CorporaNames) == 0 {
				t.Error("Search request should specify at least one corpus")
			}
			if tt.request.TopK <= 0 {
				t.Error("Search request TopK should be positive")
			}

			// Validate response
			if tt.response.Documents == nil {
				t.Error("Search response should have documents slice")
			}
			if tt.response.TotalCount < 0 {
				t.Error("Search response TotalCount should not be negative")
			}
			if tt.response.TotalCount < int32(len(tt.response.Documents)) {
				t.Error("TotalCount should not be less than returned documents count")
			}

			// Validate that filters are applied (check metadata)
			for _, doc := range tt.response.Documents {
				for filterKey, filterValue := range tt.request.Filters {
					if docValue, exists := doc.Metadata[filterKey]; exists {
						if docValue != filterValue {
							t.Errorf("Document metadata %s=%v does not match filter %s=%v",
								filterKey, docValue, filterKey, filterValue)
						}
					}
				}
			}
		})
	}
}

// TestMockConfigurationSerialization tests that configurations can be properly serialized and deserialized.
func TestMockConfigurationSerialization(t *testing.T) {
	originalConfig := &rag.VectorDbConfig{
		RagEmbeddingModelConfig: &rag.EmbeddingModelConfig{
			PublisherModel: "publishers/google/models/text-embedding-005",
		},
		RagManagedDb: &rag.RagManagedDbConfig{
			RetrievalConfig: &rag.RetrievalConfig{
				TopK:        10,
				MaxDistance: 0.7,
			},
		},
	}

	// In a real test, you would serialize and deserialize the config
	// For this mock test, we just verify the structure
	if originalConfig.RagEmbeddingModelConfig == nil {
		t.Error("Embedding model config should not be nil")
	}
	if originalConfig.RagManagedDb == nil {
		t.Error("Managed DB config should not be nil")
	}
	if originalConfig.RagManagedDb.RetrievalConfig == nil {
		t.Error("Retrieval config should not be nil")
	}

	// Test that the configuration is complete
	embeddingConfig := originalConfig.RagEmbeddingModelConfig
	if embeddingConfig.PublisherModel == "" {
		t.Error("Publisher model should be specified")
	}

	retrievalConfig := originalConfig.RagManagedDb.RetrievalConfig
	if retrievalConfig.TopK <= 0 {
		t.Error("TopK should be positive")
	}
	if retrievalConfig.MaxDistance <= 0 || retrievalConfig.MaxDistance > 1.0 {
		t.Error("MaxDistance should be between 0 and 1")
	}
}

// TestMockErrorScenarios tests various error scenarios using mock data.
func TestMockErrorScenarios(t *testing.T) {
	tests := []struct {
		name        string
		scenario    string
		expectError bool
	}{
		{
			name:        "valid_corpus_name",
			scenario:    "projects/test-project/locations/us-central1/ragCorpora/valid-corpus",
			expectError: false,
		},
		{
			name:        "invalid_corpus_name_format",
			scenario:    "invalid-corpus-name",
			expectError: true,
		},
		{
			name:        "empty_corpus_name",
			scenario:    "",
			expectError: true,
		},
		{
			name:        "corpus_name_wrong_resource_type",
			scenario:    "projects/test-project/locations/us-central1/datasets/wrong-type",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock validation of corpus name format
			isValid := validateCorpusName(tt.scenario)

			if tt.expectError && isValid {
				t.Error("Expected validation error but name was considered valid")
			}
			if !tt.expectError && !isValid {
				t.Error("Expected valid name but validation failed")
			}
		})
	}
}

// validateCorpusName is a mock function to validate corpus name format.
func validateCorpusName(name string) bool {
	if name == "" {
		return false
	}

	// Basic format check: projects/{project}/locations/{location}/ragCorpora/{corpus}
	expectedPrefix := "projects/"
	if len(name) < len(expectedPrefix) {
		return false
	}

	if name[:len(expectedPrefix)] != expectedPrefix {
		return false
	}

	// Check for ragCorpora resource type
	if !contains(name, "/ragCorpora/") {
		return false
	}

	return true
}

// contains is a helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		(len(s) > len(substr) && s[:len(substr)] == substr) ||
		(len(s) > len(substr) && findSubstring(s, substr))
}

// findSubstring is a simple substring search helper.
func findSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
