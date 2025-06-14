// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag

import (
	"context"
	"fmt"
	"log/slog"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/aiplatform/apiv1beta1/aiplatformpb"
)

// RetrievalService handles document retrieval operations from RAG corpora.
type RetrievalService struct {
	client    *aiplatform.VertexRagClient
	projectID string
	location  string
	logger    *slog.Logger
}

// NewRetrievalService creates a new RetrievalService.
func NewRetrievalService(client *aiplatform.VertexRagClient, projectID, location string, logger *slog.Logger) *RetrievalService {
	if logger == nil {
		logger = slog.Default()
	}
	return &RetrievalService{
		client:    client,
		projectID: projectID,
		location:  location,
		logger:    logger,
	}
}

// RetrieveContexts retrieves relevant contexts from RAG corpora for a given query.
func (s *RetrievalService) RetrieveContexts(ctx context.Context, query *RetrievalQuery, ragResources []string) (*RetrievalResponse, error) {
	s.logger.InfoContext(ctx, "Retrieving contexts from RAG corpora",
		slog.String("query", query.Text),
		slog.Int("similarity_top_k", int(query.SimilarityTopK)),
		slog.Float64("vector_distance_threshold", query.VectorDistanceThreshold),
		slog.Int("rag_resources_count", len(ragResources)),
	)

	parent := fmt.Sprintf("projects/%s/locations/%s", s.projectID, s.location)

	// Convert RAG resources to protobuf format
	var pbRagResources []*aiplatformpb.RetrieveContextsRequest_VertexRagStore_RagResource
	for _, resource := range ragResources {
		pbRagResources = append(pbRagResources, &aiplatformpb.RetrieveContextsRequest_VertexRagStore_RagResource{
			RagCorpus: resource,
		})
	}

	pbReq := &aiplatformpb.RetrieveContextsRequest{
		Parent: parent,
		Query: &aiplatformpb.RagQuery{
			Query: &aiplatformpb.RagQuery_Text{
				Text: query.Text,
			},
			SimilarityTopK: query.SimilarityTopK,
		},
		DataSource: &aiplatformpb.RetrieveContextsRequest_VertexRagStore_{
			VertexRagStore: &aiplatformpb.RetrieveContextsRequest_VertexRagStore{
				RagResources:            pbRagResources,
				VectorDistanceThreshold: &query.VectorDistanceThreshold,
			},
		},
	}

	resp, err := s.client.RetrieveContexts(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve contexts: %w", err)
	}

	// Convert response to our format
	ragContexts := resp.GetContexts()
	var documents []*RetrievedDocument

	if ragContexts != nil {
		for _, context := range ragContexts.GetContexts() {
			doc := &RetrievedDocument{
				Content:  context.GetText(),
				Distance: context.GetDistance(),
				Metadata: make(map[string]any),
			}

			// Add source information to metadata
			if context.GetSourceUri() != "" {
				doc.Metadata["source_uri"] = context.GetSourceUri()
			}
			if context.GetSourceDisplayName() != "" {
				doc.Metadata["source_display_name"] = context.GetSourceDisplayName()
			}

			documents = append(documents, doc)
		}
	}

	retrievalResp := &RetrievalResponse{
		Documents: documents,
	}

	s.logger.InfoContext(ctx, "Contexts retrieved successfully",
		slog.Int("documents_count", len(retrievalResp.Documents)),
	)

	return retrievalResp, nil
}

// QueryCorpus queries a specific corpus for relevant documents.
func (s *RetrievalService) QueryCorpus(ctx context.Context, corpusName string, query *RetrievalQuery) (*RetrievalResponse, error) {
	s.logger.InfoContext(ctx, "Querying RAG corpus",
		slog.String("corpus", corpusName),
		slog.String("query", query.Text),
		slog.Int("similarity_top_k", int(query.SimilarityTopK)),
	)

	return s.RetrieveContexts(ctx, query, []string{corpusName})
}

// QueryMultipleCorpora queries multiple corpora for relevant documents.
func (s *RetrievalService) QueryMultipleCorpora(ctx context.Context, corporaNames []string, query *RetrievalQuery) (*RetrievalResponse, error) {
	s.logger.InfoContext(ctx, "Querying multiple RAG corpora",
		slog.Int("corpora_count", len(corporaNames)),
		slog.String("query", query.Text),
		slog.Int("similarity_top_k", int(query.SimilarityTopK)),
	)

	return s.RetrieveContexts(ctx, query, corporaNames)
}

// AugmentGeneration augments generation with retrieval from RAG corpora.
// Note: This is a placeholder implementation. The actual AugmentPrompt API
// has a different structure that needs further investigation.
func (s *RetrievalService) AugmentGeneration(ctx context.Context, req *AugmentGenerationRequest) (*AugmentGenerationResponse, error) {
	s.logger.InfoContext(ctx, "AugmentGeneration is not yet fully implemented",
		slog.String("model", req.Model),
		slog.Int("rag_resources_count", len(req.RagResources)),
	)

	// For now, return a simple implementation that just retrieves contexts
	query := &RetrievalQuery{
		Text:           "query text", // This would need to be extracted from Contents
		SimilarityTopK: 10,
	}

	retrievalResp, err := s.RetrieveContexts(ctx, query, req.RagResources)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve contexts for augmentation: %w", err)
	}

	augmentResp := &AugmentGenerationResponse{
		RetrievedContexts: retrievalResp.Documents,
	}

	return augmentResp, nil
}

// AugmentGenerationRequest represents a request for augmented generation.
type AugmentGenerationRequest struct {
	// Model is the model to use for generation.
	Model string `json:"model,omitempty"`

	// Contents are the input contents for generation.
	Contents []*aiplatformpb.Content `json:"contents,omitempty"`

	// RagResources are the RAG corpus resources to use for retrieval.
	RagResources []string `json:"rag_resources,omitempty"`

	// RetrievalConfig is the configuration for retrieval.
	RetrievalConfig *RetrievalConfig `json:"retrieval_config,omitempty"`
}

// AugmentGenerationResponse represents the response from augmented generation.
type AugmentGenerationResponse struct {
	// AugmentedPrompt is the prompt augmented with retrieved contexts.
	AugmentedPrompt []*aiplatformpb.Content `json:"augmented_prompt,omitempty"`

	// Facts are the extracted facts from the retrieved contexts.
	Facts []string `json:"facts,omitempty"`

	// RetrievedContexts are the contexts retrieved from RAG corpora.
	RetrievedContexts []*RetrievedDocument `json:"retrieved_contexts,omitempty"`
}

// SearchRequest represents a search request for RAG documents.
type SearchRequest struct {
	// Query is the search query.
	Query string `json:"query,omitempty"`

	// CorporaNames are the names of the corpora to search in.
	CorporaNames []string `json:"corpora_names,omitempty"`

	// TopK is the number of top results to return.
	TopK int32 `json:"top_k,omitempty"`

	// VectorDistanceThreshold is the distance threshold for similarity.
	VectorDistanceThreshold float64 `json:"vector_distance_threshold,omitempty"`

	// Filters are additional filters to apply to the search.
	Filters map[string]any `json:"filters,omitempty"`
}

// SearchResponse represents the response from a search operation.
type SearchResponse struct {
	// Documents are the search results.
	Documents []*RetrievedDocument `json:"documents,omitempty"`

	// TotalCount is the total number of matching documents.
	TotalCount int32 `json:"total_count,omitempty"`
}

// Search performs a general search across RAG corpora.
func (s *RetrievalService) Search(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	s.logger.InfoContext(ctx, "Searching RAG corpora",
		slog.String("query", req.Query),
		slog.Int("corpora_count", len(req.CorporaNames)),
		slog.Int("top_k", int(req.TopK)),
	)

	query := &RetrievalQuery{
		Text:                    req.Query,
		SimilarityTopK:          req.TopK,
		VectorDistanceThreshold: req.VectorDistanceThreshold,
	}

	retrievalResp, err := s.RetrieveContexts(ctx, query, req.CorporaNames)
	if err != nil {
		return nil, fmt.Errorf("failed to search RAG corpora: %w", err)
	}

	searchResp := &SearchResponse{
		Documents:  retrievalResp.Documents,
		TotalCount: int32(len(retrievalResp.Documents)),
	}

	s.logger.InfoContext(ctx, "Search completed successfully",
		slog.Int("results_count", len(searchResp.Documents)),
	)

	return searchResp, nil
}

// SemanticSearch performs semantic search using vector similarity.
func (s *RetrievalService) SemanticSearch(ctx context.Context, query string, corporaNames []string, options *SemanticSearchOptions) (*SearchResponse, error) {
	if options == nil {
		options = &SemanticSearchOptions{
			TopK:                    10,
			VectorDistanceThreshold: 0.7,
		}
	}

	searchReq := &SearchRequest{
		Query:                   query,
		CorporaNames:            corporaNames,
		TopK:                    options.TopK,
		VectorDistanceThreshold: options.VectorDistanceThreshold,
		Filters:                 options.Filters,
	}

	return s.Search(ctx, searchReq)
}

// SemanticSearchOptions represents options for semantic search.
type SemanticSearchOptions struct {
	// TopK is the number of top results to return.
	TopK int32 `json:"top_k,omitempty"`

	// VectorDistanceThreshold is the distance threshold for similarity.
	VectorDistanceThreshold float64 `json:"vector_distance_threshold,omitempty"`

	// Filters are additional filters to apply to the search.
	Filters map[string]any `json:"filters,omitempty"`
}

// HybridSearch performs hybrid search combining vector and keyword search.
func (s *RetrievalService) HybridSearch(ctx context.Context, query string, corporaNames []string, options *HybridSearchOptions) (*SearchResponse, error) {
	if options == nil {
		options = &HybridSearchOptions{
			TopK:                    10,
			VectorDistanceThreshold: 0.7,
			KeywordWeight:           0.3,
			VectorWeight:            0.7,
		}
	}

	s.logger.InfoContext(ctx, "Performing hybrid search",
		slog.String("query", query),
		slog.Int("corpora_count", len(corporaNames)),
		slog.Float64("keyword_weight", options.KeywordWeight),
		slog.Float64("vector_weight", options.VectorWeight),
	)

	// For now, we'll implement this as semantic search
	// In a full implementation, you would combine vector and keyword search results
	searchReq := &SearchRequest{
		Query:                   query,
		CorporaNames:            corporaNames,
		TopK:                    options.TopK,
		VectorDistanceThreshold: options.VectorDistanceThreshold,
		Filters:                 options.Filters,
	}

	return s.Search(ctx, searchReq)
}

// HybridSearchOptions represents options for hybrid search.
type HybridSearchOptions struct {
	// TopK is the number of top results to return.
	TopK int32 `json:"top_k,omitempty"`

	// VectorDistanceThreshold is the distance threshold for similarity.
	VectorDistanceThreshold float64 `json:"vector_distance_threshold,omitempty"`

	// KeywordWeight is the weight for keyword search results.
	KeywordWeight float64 `json:"keyword_weight,omitempty"`

	// VectorWeight is the weight for vector search results.
	VectorWeight float64 `json:"vector_weight,omitempty"`

	// Filters are additional filters to apply to the search.
	Filters map[string]any `json:"filters,omitempty"`
}
