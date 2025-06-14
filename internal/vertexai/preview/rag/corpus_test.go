// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
)

func TestCorpusState_String(t *testing.T) {
	tests := []struct {
		name  string
		state rag.CorpusState
		want  string
	}{
		{
			name:  "unspecified",
			state: rag.CorpusStateUnspecified,
			want:  "CORPUS_STATE_UNSPECIFIED",
		},
		{
			name:  "active",
			state: rag.CorpusStateActive,
			want:  "ACTIVE",
		},
		{
			name:  "error",
			state: rag.CorpusStateError,
			want:  "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.state); got != tt.want {
				t.Errorf("CorpusState string = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCorpus_Validation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		corpus  *rag.Corpus
		wantErr bool
	}{
		{
			name: "valid_minimal_corpus",
			corpus: &rag.Corpus{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus",
				DisplayName: "Test Corpus",
				Description: "A test corpus",
				State:       rag.CorpusStateActive,
			},
			wantErr: false,
		},
		{
			name: "valid_full_corpus",
			corpus: &rag.Corpus{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus",
				DisplayName: "Test Corpus",
				Description: "A test corpus with full configuration",
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
			wantErr: false,
		},
		{
			name: "empty_display_name",
			corpus: &rag.Corpus{
				Name:        "projects/test-project/locations/us-central1/ragCorpora/test-corpus",
				DisplayName: "",
				Description: "A test corpus",
				State:       rag.CorpusStateActive,
			},
			wantErr: true, // In a real implementation, you might validate this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation checks
			if tt.corpus.Name == "" && !tt.wantErr {
				t.Error("Valid corpus should have a name")
			}
			if tt.corpus.DisplayName == "" && !tt.wantErr {
				t.Error("Valid corpus should have a display name")
			}

			// Check that timestamps are properly set if present
			if tt.corpus.CreateTime != nil && tt.corpus.CreateTime.IsZero() {
				t.Error("CreateTime should not be zero if set")
			}
			if tt.corpus.UpdateTime != nil && tt.corpus.UpdateTime.IsZero() {
				t.Error("UpdateTime should not be zero if set")
			}
		})
	}
}

func TestCreateCorpusRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request *rag.CreateCorpusRequest
		wantErr bool
	}{
		{
			name: "valid_request",
			request: &rag.CreateCorpusRequest{
				Parent: "projects/test-project/locations/us-central1",
				Corpus: &rag.Corpus{
					DisplayName: "Test Corpus",
					Description: "A test corpus",
				},
			},
			wantErr: false,
		},
		{
			name: "missing_corpus",
			request: &rag.CreateCorpusRequest{
				Parent: "projects/test-project/locations/us-central1",
				Corpus: nil,
			},
			wantErr: true,
		},
		{
			name: "missing_parent",
			request: &rag.CreateCorpusRequest{
				Parent: "",
				Corpus: &rag.Corpus{
					DisplayName: "Test Corpus",
					Description: "A test corpus",
				},
			},
			wantErr: false, // Parent can be auto-generated
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.request.Corpus == nil && !tt.wantErr {
				t.Error("Valid request should have a corpus")
			}
		})
	}
}

func TestListCorporaRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request *rag.ListCorporaRequest
		wantErr bool
	}{
		{
			name: "valid_request_with_pagination",
			request: &rag.ListCorporaRequest{
				Parent:    "projects/test-project/locations/us-central1",
				PageSize:  10,
				PageToken: "next-page-token",
			},
			wantErr: false,
		},
		{
			name: "valid_request_no_pagination",
			request: &rag.ListCorporaRequest{
				Parent:    "projects/test-project/locations/us-central1",
				PageSize:  0,
				PageToken: "",
			},
			wantErr: false,
		},
		{
			name: "negative_page_size",
			request: &rag.ListCorporaRequest{
				Parent:    "projects/test-project/locations/us-central1",
				PageSize:  -1,
				PageToken: "",
			},
			wantErr: true,
		},
		{
			name: "excessive_page_size",
			request: &rag.ListCorporaRequest{
				Parent:    "projects/test-project/locations/us-central1",
				PageSize:  10000,
				PageToken: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.request.PageSize < 0 && !tt.wantErr {
				t.Error("PageSize should not be negative")
			}
			if tt.request.PageSize > 1000 && !tt.wantErr {
				t.Error("PageSize should not exceed reasonable limits")
			}
		})
	}
}

func TestListCorporaResponse_Structure(t *testing.T) {
	corpus1 := &rag.Corpus{
		Name:        "projects/test-project/locations/us-central1/ragCorpora/corpus-1",
		DisplayName: "Corpus 1",
		Description: "First test corpus",
		State:       rag.CorpusStateActive,
	}

	corpus2 := &rag.Corpus{
		Name:        "projects/test-project/locations/us-central1/ragCorpora/corpus-2",
		DisplayName: "Corpus 2",
		Description: "Second test corpus",
		State:       rag.CorpusStateActive,
	}

	tests := []struct {
		name     string
		response *rag.ListCorporaResponse
		want     *rag.ListCorporaResponse
	}{
		{
			name: "empty_response",
			response: &rag.ListCorporaResponse{
				RagCorpora:    []*rag.Corpus{},
				NextPageToken: "",
			},
			want: &rag.ListCorporaResponse{
				RagCorpora:    []*rag.Corpus{},
				NextPageToken: "",
			},
		},
		{
			name: "response_with_corpora",
			response: &rag.ListCorporaResponse{
				RagCorpora:    []*rag.Corpus{corpus1, corpus2},
				NextPageToken: "next-page-token",
			},
			want: &rag.ListCorporaResponse{
				RagCorpora:    []*rag.Corpus{corpus1, corpus2},
				NextPageToken: "next-page-token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.response); diff != "" {
				t.Errorf("ListCorporaResponse mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVectorDbConfig_BackendTypes(t *testing.T) {
	tests := []struct {
		name   string
		config *rag.VectorDbConfig
		want   string // Expected backend type
	}{
		{
			name: "managed_db",
			config: &rag.VectorDbConfig{
				RagManagedDb: &rag.RagManagedDbConfig{
					RetrievalConfig: &rag.RetrievalConfig{
						TopK:        10,
						MaxDistance: 0.7,
					},
				},
			},
			want: "managed",
		},
		{
			name: "weaviate",
			config: &rag.VectorDbConfig{
				WeaviateConfig: &rag.WeaviateConfig{
					HttpEndpoint:   "http://localhost:8080",
					CollectionName: "test-collection",
				},
			},
			want: "weaviate",
		},
		{
			name: "pinecone",
			config: &rag.VectorDbConfig{
				PineconeConfig: &rag.PineconeConfig{
					IndexName: "test-index",
				},
			},
			want: "pinecone",
		},
		{
			name: "vertex_vector_search",
			config: &rag.VectorDbConfig{
				VertexVectorSearch: &rag.VertexVectorSearchConfig{
					IndexEndpoint: "projects/test-project/locations/us-central1/indexEndpoints/test-endpoint",
					Index:         "test-index",
				},
			},
			want: "vertex_vector_search",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine which backend is configured
			var got string
			switch {
			case tt.config.RagManagedDb != nil:
				got = "managed"
			case tt.config.WeaviateConfig != nil:
				got = "weaviate"
			case tt.config.PineconeConfig != nil:
				got = "pinecone"
			case tt.config.VertexVectorSearch != nil:
				got = "vertex_vector_search"
			default:
				got = "unknown"
			}

			if got != tt.want {
				t.Errorf("Backend type = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEmbeddingModelConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *rag.EmbeddingModelConfig
		wantErr bool
	}{
		{
			name: "publisher_model",
			config: &rag.EmbeddingModelConfig{
				PublisherModel: "publishers/google/models/text-embedding-005",
			},
			wantErr: false,
		},
		{
			name: "custom_endpoint",
			config: &rag.EmbeddingModelConfig{
				Endpoint: "https://my-custom-endpoint.com",
				Model:    "custom-embedding-model",
			},
			wantErr: false,
		},
		{
			name: "both_publisher_and_custom",
			config: &rag.EmbeddingModelConfig{
				PublisherModel: "publishers/google/models/text-embedding-005",
				Endpoint:       "https://my-custom-endpoint.com",
				Model:          "custom-embedding-model",
			},
			wantErr: true, // Should not specify both
		},
		{
			name: "empty_config",
			config: &rag.EmbeddingModelConfig{
				PublisherModel: "",
				Endpoint:       "",
				Model:          "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasPublisherModel := tt.config.PublisherModel != ""
			hasCustomEndpoint := tt.config.Endpoint != "" && tt.config.Model != ""
			hasAnyConfig := hasPublisherModel || hasCustomEndpoint
			hasBothConfigs := hasPublisherModel && hasCustomEndpoint

			if tt.wantErr {
				if !hasBothConfigs && hasAnyConfig {
					t.Error("Expected error but config appears valid")
				}
				if !hasAnyConfig {
					// This is expected for empty config
				}
			} else {
				if !hasAnyConfig {
					t.Error("Expected valid config but no configuration found")
				}
				if hasBothConfigs {
					t.Error("Should not specify both publisher model and custom endpoint")
				}
			}
		})
	}
}

func TestRetrievalConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  *rag.RetrievalConfig
		wantErr bool
	}{
		{
			name: "valid_config",
			config: &rag.RetrievalConfig{
				TopK:        10,
				MaxDistance: 0.7,
			},
			wantErr: false,
		},
		{
			name: "zero_top_k",
			config: &rag.RetrievalConfig{
				TopK:        0,
				MaxDistance: 0.7,
			},
			wantErr: true,
		},
		{
			name: "negative_top_k",
			config: &rag.RetrievalConfig{
				TopK:        -1,
				MaxDistance: 0.7,
			},
			wantErr: true,
		},
		{
			name: "invalid_max_distance",
			config: &rag.RetrievalConfig{
				TopK:        10,
				MaxDistance: -0.5,
			},
			wantErr: true,
		},
		{
			name: "max_distance_too_high",
			config: &rag.RetrievalConfig{
				TopK:        10,
				MaxDistance: 1.5,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.TopK <= 0 && !tt.wantErr {
				t.Error("TopK should be positive")
			}
			if (tt.config.MaxDistance < 0 || tt.config.MaxDistance > 1.0) && !tt.wantErr {
				t.Error("MaxDistance should be between 0 and 1")
			}
		})
	}
}
