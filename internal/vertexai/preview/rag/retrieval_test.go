// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
)

func TestRetrievalQuery_Validation(t *testing.T) {
	tests := []struct {
		name    string
		query   *rag.RetrievalQuery
		wantErr bool
	}{
		{
			name: "valid_query",
			query: &rag.RetrievalQuery{
				Text:                    "What is machine learning?",
				SimilarityTopK:          10,
				VectorDistanceThreshold: 0.7,
			},
			wantErr: false,
		},
		{
			name: "minimal_query",
			query: &rag.RetrievalQuery{
				Text:           "test query",
				SimilarityTopK: 1,
			},
			wantErr: false,
		},
		{
			name: "empty_text",
			query: &rag.RetrievalQuery{
				Text:           "",
				SimilarityTopK: 10,
			},
			wantErr: true,
		},
		{
			name: "zero_top_k",
			query: &rag.RetrievalQuery{
				Text:           "test query",
				SimilarityTopK: 0,
			},
			wantErr: true,
		},
		{
			name: "negative_top_k",
			query: &rag.RetrievalQuery{
				Text:           "test query",
				SimilarityTopK: -1,
			},
			wantErr: true,
		},
		{
			name: "invalid_distance_threshold",
			query: &rag.RetrievalQuery{
				Text:                    "test query",
				SimilarityTopK:          10,
				VectorDistanceThreshold: -0.5,
			},
			wantErr: true,
		},
		{
			name: "distance_threshold_too_high",
			query: &rag.RetrievalQuery{
				Text:                    "test query",
				SimilarityTopK:          10,
				VectorDistanceThreshold: 1.5,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.query.Text == "" && !tt.wantErr {
				t.Error("Valid query should have text")
			}
			if tt.query.SimilarityTopK <= 0 && !tt.wantErr {
				t.Error("SimilarityTopK should be positive")
			}
			if tt.query.VectorDistanceThreshold < 0 && !tt.wantErr {
				t.Error("VectorDistanceThreshold should not be negative")
			}
			if tt.query.VectorDistanceThreshold > 1.0 && !tt.wantErr {
				t.Error("VectorDistanceThreshold should not exceed 1.0")
			}
		})
	}
}

func TestRetrievedDocument_Structure(t *testing.T) {
	tests := []struct {
		name string
		doc  *rag.RetrievedDocument
		want *rag.RetrievedDocument
	}{
		{
			name: "complete_document",
			doc: &rag.RetrievedDocument{
				Id:       "doc-123",
				Content:  "This is a sample document about machine learning.",
				Distance: 0.15,
				Metadata: map[string]any{
					"source_uri":          "gs://bucket/ml-guide.pdf",
					"source_display_name": "Machine Learning Guide",
					"page_number":         1,
					"author":              "AI Expert",
				},
			},
			want: &rag.RetrievedDocument{
				Id:       "doc-123",
				Content:  "This is a sample document about machine learning.",
				Distance: 0.15,
				Metadata: map[string]any{
					"source_uri":          "gs://bucket/ml-guide.pdf",
					"source_display_name": "Machine Learning Guide",
					"page_number":         1,
					"author":              "AI Expert",
				},
			},
		},
		{
			name: "minimal_document",
			doc: &rag.RetrievedDocument{
				Content:  "Short content",
				Distance: 0.25,
			},
			want: &rag.RetrievedDocument{
				Content:  "Short content",
				Distance: 0.25,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.doc); diff != "" {
				t.Errorf("RetrievedDocument mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRetrievedDocument_Validation(t *testing.T) {
	tests := []struct {
		name    string
		doc     *rag.RetrievedDocument
		wantErr bool
	}{
		{
			name: "valid_document",
			doc: &rag.RetrievedDocument{
				Id:       "doc-123",
				Content:  "Valid document content",
				Distance: 0.25,
				Metadata: map[string]any{
					"source": "test-source",
				},
			},
			wantErr: false,
		},
		{
			name: "empty_content",
			doc: &rag.RetrievedDocument{
				Id:       "doc-123",
				Content:  "",
				Distance: 0.25,
			},
			wantErr: true,
		},
		{
			name: "negative_distance",
			doc: &rag.RetrievedDocument{
				Id:       "doc-123",
				Content:  "Valid content",
				Distance: -0.1,
			},
			wantErr: true,
		},
		{
			name: "distance_too_high",
			doc: &rag.RetrievedDocument{
				Id:       "doc-123",
				Content:  "Valid content",
				Distance: 1.5,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.doc.Content == "" && !tt.wantErr {
				t.Error("Valid document should have content")
			}
			if tt.doc.Distance < 0 && !tt.wantErr {
				t.Error("Distance should not be negative")
			}
			if tt.doc.Distance > 1.0 && !tt.wantErr {
				t.Error("Distance should not exceed 1.0")
			}
		})
	}
}

func TestRetrievalResponse_Structure(t *testing.T) {
	doc1 := &rag.RetrievedDocument{
		Id:       "doc-1",
		Content:  "First document content",
		Distance: 0.15,
		Metadata: map[string]any{"source": "source-1"},
	}

	doc2 := &rag.RetrievedDocument{
		Id:       "doc-2",
		Content:  "Second document content",
		Distance: 0.25,
		Metadata: map[string]any{"source": "source-2"},
	}

	tests := []struct {
		name     string
		response *rag.RetrievalResponse
		want     *rag.RetrievalResponse
	}{
		{
			name: "empty_response",
			response: &rag.RetrievalResponse{
				Documents: []*rag.RetrievedDocument{},
			},
			want: &rag.RetrievalResponse{
				Documents: []*rag.RetrievedDocument{},
			},
		},
		{
			name: "response_with_documents",
			response: &rag.RetrievalResponse{
				Documents: []*rag.RetrievedDocument{doc1, doc2},
			},
			want: &rag.RetrievalResponse{
				Documents: []*rag.RetrievedDocument{doc1, doc2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.response); diff != "" {
				t.Errorf("RetrievalResponse mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSearchRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request *rag.SearchRequest
		wantErr bool
	}{
		{
			name: "valid_request",
			request: &rag.SearchRequest{
				Query:                   "machine learning basics",
				CorporaNames:            []string{"corpus-1", "corpus-2"},
				TopK:                    10,
				VectorDistanceThreshold: 0.7,
				Filters: map[string]any{
					"category": "technical",
					"language": "english",
				},
			},
			wantErr: false,
		},
		{
			name: "minimal_request",
			request: &rag.SearchRequest{
				Query:        "test query",
				CorporaNames: []string{"corpus-1"},
				TopK:         5,
			},
			wantErr: false,
		},
		{
			name: "empty_query",
			request: &rag.SearchRequest{
				Query:        "",
				CorporaNames: []string{"corpus-1"},
				TopK:         10,
			},
			wantErr: true,
		},
		{
			name: "no_corpora",
			request: &rag.SearchRequest{
				Query:        "test query",
				CorporaNames: []string{},
				TopK:         10,
			},
			wantErr: true,
		},
		{
			name: "zero_top_k",
			request: &rag.SearchRequest{
				Query:        "test query",
				CorporaNames: []string{"corpus-1"},
				TopK:         0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.request.Query == "" && !tt.wantErr {
				t.Error("Valid request should have a query")
			}
			if len(tt.request.CorporaNames) == 0 && !tt.wantErr {
				t.Error("Valid request should have at least one corpus")
			}
			if tt.request.TopK <= 0 && !tt.wantErr {
				t.Error("TopK should be positive")
			}
			if tt.request.VectorDistanceThreshold < 0 {
				t.Error("VectorDistanceThreshold should not be negative")
			}
		})
	}
}

func TestSearchResponse_Structure(t *testing.T) {
	doc1 := &rag.RetrievedDocument{
		Id:       "doc-1",
		Content:  "First search result",
		Distance: 0.1,
	}

	doc2 := &rag.RetrievedDocument{
		Id:       "doc-2",
		Content:  "Second search result",
		Distance: 0.2,
	}

	tests := []struct {
		name     string
		response *rag.SearchResponse
		want     *rag.SearchResponse
	}{
		{
			name: "empty_response",
			response: &rag.SearchResponse{
				Documents:  []*rag.RetrievedDocument{},
				TotalCount: 0,
			},
			want: &rag.SearchResponse{
				Documents:  []*rag.RetrievedDocument{},
				TotalCount: 0,
			},
		},
		{
			name: "response_with_results",
			response: &rag.SearchResponse{
				Documents:  []*rag.RetrievedDocument{doc1, doc2},
				TotalCount: 2,
			},
			want: &rag.SearchResponse{
				Documents:  []*rag.RetrievedDocument{doc1, doc2},
				TotalCount: 2,
			},
		},
		{
			name: "response_with_more_total_than_returned",
			response: &rag.SearchResponse{
				Documents:  []*rag.RetrievedDocument{doc1, doc2},
				TotalCount: 100, // More results available than returned
			},
			want: &rag.SearchResponse{
				Documents:  []*rag.RetrievedDocument{doc1, doc2},
				TotalCount: 100,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.response); diff != "" {
				t.Errorf("SearchResponse mismatch (-want +got):\n%s", diff)
			}

			// Additional validation
			if tt.response.TotalCount < 0 {
				t.Error("TotalCount should not be negative")
			}
			if tt.response.TotalCount > 0 && len(tt.response.Documents) == 0 {
				t.Error("If TotalCount > 0, should have at least some documents")
			}
		})
	}
}

func TestSemanticSearchOptions_Validation(t *testing.T) {
	tests := []struct {
		name    string
		options *rag.SemanticSearchOptions
		wantErr bool
	}{
		{
			name: "valid_options",
			options: &rag.SemanticSearchOptions{
				TopK:                    10,
				VectorDistanceThreshold: 0.7,
				Filters: map[string]any{
					"category": "technical",
				},
			},
			wantErr: false,
		},
		{
			name: "minimal_options",
			options: &rag.SemanticSearchOptions{
				TopK: 5,
			},
			wantErr: false,
		},
		{
			name:    "nil_options",
			options: nil,
			wantErr: false, // Should use defaults
		},
		{
			name: "invalid_top_k",
			options: &rag.SemanticSearchOptions{
				TopK: 0,
			},
			wantErr: true,
		},
		{
			name: "invalid_distance_threshold",
			options: &rag.SemanticSearchOptions{
				TopK:                    10,
				VectorDistanceThreshold: -0.1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.options == nil {
				// Nil options should be handled with defaults
				return
			}

			if tt.options.TopK <= 0 && !tt.wantErr {
				t.Error("TopK should be positive")
			}
			if tt.options.VectorDistanceThreshold < 0 && !tt.wantErr {
				t.Error("VectorDistanceThreshold should not be negative")
			}
		})
	}
}

func TestHybridSearchOptions_Validation(t *testing.T) {
	tests := []struct {
		name    string
		options *rag.HybridSearchOptions
		wantErr bool
	}{
		{
			name: "valid_options",
			options: &rag.HybridSearchOptions{
				TopK:                    10,
				VectorDistanceThreshold: 0.7,
				KeywordWeight:           0.3,
				VectorWeight:            0.7,
				Filters: map[string]any{
					"category": "technical",
				},
			},
			wantErr: false,
		},
		{
			name: "equal_weights",
			options: &rag.HybridSearchOptions{
				TopK:          10,
				KeywordWeight: 0.5,
				VectorWeight:  0.5,
			},
			wantErr: false,
		},
		{
			name: "weights_sum_to_one",
			options: &rag.HybridSearchOptions{
				TopK:          10,
				KeywordWeight: 0.2,
				VectorWeight:  0.8,
			},
			wantErr: false,
		},
		{
			name: "weights_dont_sum_to_one",
			options: &rag.HybridSearchOptions{
				TopK:          10,
				KeywordWeight: 0.3,
				VectorWeight:  0.3, // Sum = 0.6
			},
			wantErr: true,
		},
		{
			name: "negative_keyword_weight",
			options: &rag.HybridSearchOptions{
				TopK:          10,
				KeywordWeight: -0.1,
				VectorWeight:  1.1,
			},
			wantErr: true,
		},
		{
			name: "negative_vector_weight",
			options: &rag.HybridSearchOptions{
				TopK:          10,
				KeywordWeight: 1.1,
				VectorWeight:  -0.1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.options == nil {
				return
			}

			if tt.options.TopK <= 0 && !tt.wantErr {
				t.Error("TopK should be positive")
			}
			if tt.options.KeywordWeight < 0 && !tt.wantErr {
				t.Error("KeywordWeight should not be negative")
			}
			if tt.options.VectorWeight < 0 && !tt.wantErr {
				t.Error("VectorWeight should not be negative")
			}

			// Check if weights are reasonable (sum close to 1.0)
			weightSum := tt.options.KeywordWeight + tt.options.VectorWeight
			tolerance := 0.01
			if (weightSum < 1.0-tolerance || weightSum > 1.0+tolerance) && !tt.wantErr {
				t.Errorf("Weights should sum to approximately 1.0, got %f", weightSum)
			}
		})
	}
}

func TestAugmentGenerationRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		request *rag.AugmentGenerationRequest
		wantErr bool
	}{
		{
			name: "valid_request",
			request: &rag.AugmentGenerationRequest{
				Model:        "gemini-2.0-flash",
				RagResources: []string{"corpus-1", "corpus-2"},
				RetrievalConfig: &rag.RetrievalConfig{
					TopK:        10,
					MaxDistance: 0.7,
				},
			},
			wantErr: false,
		},
		{
			name: "minimal_request",
			request: &rag.AugmentGenerationRequest{
				Model:        "gemini-2.0-flash",
				RagResources: []string{"corpus-1"},
			},
			wantErr: false,
		},
		{
			name: "empty_model",
			request: &rag.AugmentGenerationRequest{
				Model:        "",
				RagResources: []string{"corpus-1"},
			},
			wantErr: true,
		},
		{
			name: "no_rag_resources",
			request: &rag.AugmentGenerationRequest{
				Model:        "gemini-2.0-flash",
				RagResources: []string{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.request.Model == "" && !tt.wantErr {
				t.Error("Valid request should have a model")
			}
			if len(tt.request.RagResources) == 0 && !tt.wantErr {
				t.Error("Valid request should have at least one RAG resource")
			}
		})
	}
}

func TestAugmentGenerationResponse_Structure(t *testing.T) {
	doc1 := &rag.RetrievedDocument{
		Id:       "doc-1",
		Content:  "Context from document 1",
		Distance: 0.1,
	}

	doc2 := &rag.RetrievedDocument{
		Id:       "doc-2",
		Content:  "Context from document 2",
		Distance: 0.2,
	}

	tests := []struct {
		name     string
		response *rag.AugmentGenerationResponse
		want     *rag.AugmentGenerationResponse
	}{
		{
			name: "complete_response",
			response: &rag.AugmentGenerationResponse{
				Facts: []string{
					"Fact 1 extracted from documents",
					"Fact 2 extracted from documents",
				},
				RetrievedContexts: []*rag.RetrievedDocument{doc1, doc2},
			},
			want: &rag.AugmentGenerationResponse{
				Facts: []string{
					"Fact 1 extracted from documents",
					"Fact 2 extracted from documents",
				},
				RetrievedContexts: []*rag.RetrievedDocument{doc1, doc2},
			},
		},
		{
			name: "minimal_response",
			response: &rag.AugmentGenerationResponse{
				RetrievedContexts: []*rag.RetrievedDocument{doc1},
			},
			want: &rag.AugmentGenerationResponse{
				RetrievedContexts: []*rag.RetrievedDocument{doc1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.response); diff != "" {
				t.Errorf("AugmentGenerationResponse mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
