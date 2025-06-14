// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag

import (
	"context"
	"fmt"
	"log/slog"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/aiplatform/apiv1beta1/aiplatformpb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// CorpusService handles corpus management operations.
type CorpusService struct {
	client    *aiplatform.VertexRagDataClient
	projectID string
	location  string
	logger    *slog.Logger
}

// NewCorpusService creates a new CorpusService.
func NewCorpusService(client *aiplatform.VertexRagDataClient, projectID, location string, logger *slog.Logger) *CorpusService {
	if logger == nil {
		logger = slog.Default()
	}
	return &CorpusService{
		client:    client,
		projectID: projectID,
		location:  location,
		logger:    logger,
	}
}

// CreateCorpus creates a new RAG corpus.
func (s *CorpusService) CreateCorpus(ctx context.Context, req *CreateCorpusRequest) (*Corpus, error) {
	if req.Parent == "" {
		req.Parent = fmt.Sprintf("projects/%s/locations/%s", s.projectID, s.location)
	}

	s.logger.InfoContext(ctx, "Creating RAG corpus",
		slog.String("parent", req.Parent),
		slog.String("display_name", req.Corpus.DisplayName),
	)

	pbReq := &aiplatformpb.CreateRagCorpusRequest{
		Parent: req.Parent,
		RagCorpus: &aiplatformpb.RagCorpus{
			DisplayName: req.Corpus.DisplayName,
			Description: req.Corpus.Description,
		},
	}

	// Convert backend config if provided
	if req.Corpus.BackendConfig != nil {
		pbReq.RagCorpus.RagVectorDbConfig = convertVectorDbConfigToPb(req.Corpus.BackendConfig)
	}

	op, err := s.client.CreateRagCorpus(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create RAG corpus: %w", err)
	}

	pbCorpus, err := op.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for RAG corpus creation: %w", err)
	}

	corpus := convertPbToCorpus(pbCorpus)
	s.logger.InfoContext(ctx, "RAG corpus created successfully",
		slog.String("name", corpus.Name),
		slog.String("display_name", corpus.DisplayName),
	)

	return corpus, nil
}

// ListCorpora lists all RAG corpora in the project and location.
func (s *CorpusService) ListCorpora(ctx context.Context, req *ListCorporaRequest) (*ListCorporaResponse, error) {
	if req.Parent == "" {
		req.Parent = fmt.Sprintf("projects/%s/locations/%s", s.projectID, s.location)
	}

	s.logger.InfoContext(ctx, "Listing RAG corpora",
		slog.String("parent", req.Parent),
		slog.Int("page_size", int(req.PageSize)),
	)

	pbReq := &aiplatformpb.ListRagCorporaRequest{
		Parent:    req.Parent,
		PageSize:  req.PageSize,
		PageToken: req.PageToken,
	}

	it := s.client.ListRagCorpora(ctx, pbReq)
	var corpora []*Corpus
	var nextPageToken string

	for {
		pbCorpus, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list RAG corpora: %w", err)
		}

		corpus := convertPbToCorpus(pbCorpus)
		corpora = append(corpora, corpus)
	}

	// Get next page token if available
	resp := it.Response
	if resp != nil {
		if listResp, ok := resp.(*aiplatformpb.ListRagCorporaResponse); ok {
			nextPageToken = listResp.GetNextPageToken()
		}
	}

	s.logger.InfoContext(ctx, "Listed RAG corpora successfully",
		slog.Int("count", len(corpora)),
	)

	return &ListCorporaResponse{
		RagCorpora:    corpora,
		NextPageToken: nextPageToken,
	}, nil
}

// GetCorpus retrieves a specific RAG corpus.
func (s *CorpusService) GetCorpus(ctx context.Context, req *GetCorpusRequest) (*Corpus, error) {
	s.logger.InfoContext(ctx, "Getting RAG corpus",
		slog.String("name", req.Name),
	)

	pbReq := &aiplatformpb.GetRagCorpusRequest{
		Name: req.Name,
	}

	pbCorpus, err := s.client.GetRagCorpus(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get RAG corpus: %w", err)
	}

	corpus := convertPbToCorpus(pbCorpus)
	s.logger.InfoContext(ctx, "Got RAG corpus successfully",
		slog.String("name", corpus.Name),
		slog.String("display_name", corpus.DisplayName),
	)

	return corpus, nil
}

// DeleteCorpus deletes a RAG corpus.
func (s *CorpusService) DeleteCorpus(ctx context.Context, req *DeleteCorpusRequest) error {
	s.logger.InfoContext(ctx, "Deleting RAG corpus",
		slog.String("name", req.Name),
		slog.Bool("force", req.Force),
	)

	pbReq := &aiplatformpb.DeleteRagCorpusRequest{
		Name:  req.Name,
		Force: req.Force,
	}

	op, err := s.client.DeleteRagCorpus(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("failed to delete RAG corpus: %w", err)
	}

	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("failed to wait for RAG corpus deletion: %w", err)
	}

	s.logger.InfoContext(ctx, "RAG corpus deleted successfully",
		slog.String("name", req.Name),
	)

	return nil
}

// UpdateCorpus updates a RAG corpus.
func (s *CorpusService) UpdateCorpus(ctx context.Context, corpus *Corpus, updateMask *fieldmaskpb.FieldMask) (*Corpus, error) {
	s.logger.InfoContext(ctx, "Updating RAG corpus",
		slog.String("name", corpus.Name),
		slog.String("display_name", corpus.DisplayName),
	)

	pbReq := &aiplatformpb.UpdateRagCorpusRequest{
		RagCorpus: &aiplatformpb.RagCorpus{
			Name:        corpus.Name,
			DisplayName: corpus.DisplayName,
			Description: corpus.Description,
		},
	}

	// Convert backend config if provided
	if corpus.BackendConfig != nil {
		pbReq.RagCorpus.RagVectorDbConfig = convertVectorDbConfigToPb(corpus.BackendConfig)
	}

	op, err := s.client.UpdateRagCorpus(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("failed to update RAG corpus: %w", err)
	}

	pbCorpus, err := op.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for RAG corpus update: %w", err)
	}

	updatedCorpus := convertPbToCorpus(pbCorpus)
	s.logger.InfoContext(ctx, "RAG corpus updated successfully",
		slog.String("name", updatedCorpus.Name),
		slog.String("display_name", updatedCorpus.DisplayName),
	)

	return updatedCorpus, nil
}

// convertPbToCorpus converts a protobuf RagCorpus to our Corpus type.
func convertPbToCorpus(pb *aiplatformpb.RagCorpus) *Corpus {
	corpus := &Corpus{
		Name:        pb.GetName(),
		DisplayName: pb.GetDisplayName(),
		Description: pb.GetDescription(),
	}

	if pb.GetCreateTime() != nil {
		createTime := pb.GetCreateTime().AsTime()
		corpus.CreateTime = &createTime
	}

	if pb.GetUpdateTime() != nil {
		updateTime := pb.GetUpdateTime().AsTime()
		corpus.UpdateTime = &updateTime
	}

	// Convert state from corpus status
	if pb.GetCorpusStatus() != nil {
		switch pb.GetCorpusStatus().GetState() {
		case aiplatformpb.CorpusStatus_INITIALIZED:
			corpus.State = CorpusStateActive
		case aiplatformpb.CorpusStatus_ERROR:
			corpus.State = CorpusStateError
		default:
			corpus.State = CorpusStateUnspecified
		}
	}

	// Convert backend config if present
	if pb.GetRagVectorDbConfig() != nil {
		corpus.BackendConfig = convertPbToVectorDbConfig(pb.GetRagVectorDbConfig())
	}

	return corpus
}

// convertVectorDbConfigToPb converts our VectorDbConfig to protobuf.
func convertVectorDbConfigToPb(config *VectorDbConfig) *aiplatformpb.RagVectorDbConfig {
	if config == nil {
		return nil
	}

	pbConfig := &aiplatformpb.RagVectorDbConfig{}

	if config.RagManagedDb != nil {
		pbConfig.VectorDb = &aiplatformpb.RagVectorDbConfig_RagManagedDb_{
			RagManagedDb: &aiplatformpb.RagVectorDbConfig_RagManagedDb{},
		}
	}

	if config.WeaviateConfig != nil {
		pbConfig.VectorDb = &aiplatformpb.RagVectorDbConfig_Weaviate_{
			Weaviate: &aiplatformpb.RagVectorDbConfig_Weaviate{
				HttpEndpoint:   config.WeaviateConfig.HttpEndpoint,
				CollectionName: config.WeaviateConfig.CollectionName,
			},
		}
	}

	if config.PineconeConfig != nil {
		pbConfig.VectorDb = &aiplatformpb.RagVectorDbConfig_Pinecone_{
			Pinecone: &aiplatformpb.RagVectorDbConfig_Pinecone{
				IndexName: config.PineconeConfig.IndexName,
			},
		}
	}

	if config.VertexVectorSearch != nil {
		pbConfig.VectorDb = &aiplatformpb.RagVectorDbConfig_VertexVectorSearch_{
			VertexVectorSearch: &aiplatformpb.RagVectorDbConfig_VertexVectorSearch{
				IndexEndpoint: config.VertexVectorSearch.IndexEndpoint,
				Index:         config.VertexVectorSearch.Index,
			},
		}
	}

	return pbConfig
}

// convertPbToVectorDbConfig converts protobuf RagVectorDbConfig to our VectorDbConfig.
func convertPbToVectorDbConfig(pb *aiplatformpb.RagVectorDbConfig) *VectorDbConfig {
	if pb == nil {
		return nil
	}

	config := &VectorDbConfig{}

	switch vectorDb := pb.GetVectorDb().(type) {
	case *aiplatformpb.RagVectorDbConfig_RagManagedDb_:
		config.RagManagedDb = &RagManagedDbConfig{}
	case *aiplatformpb.RagVectorDbConfig_Weaviate_:
		config.WeaviateConfig = &WeaviateConfig{
			HttpEndpoint:   vectorDb.Weaviate.GetHttpEndpoint(),
			CollectionName: vectorDb.Weaviate.GetCollectionName(),
		}
	case *aiplatformpb.RagVectorDbConfig_Pinecone_:
		config.PineconeConfig = &PineconeConfig{
			IndexName: vectorDb.Pinecone.GetIndexName(),
		}
	case *aiplatformpb.RagVectorDbConfig_VertexVectorSearch_:
		config.VertexVectorSearch = &VertexVectorSearchConfig{
			IndexEndpoint: vectorDb.VertexVectorSearch.GetIndexEndpoint(),
			Index:         vectorDb.VertexVectorSearch.GetIndex(),
		}
	}

	return config
}

// generateCorpusName generates a corpus resource name.
func (s *CorpusService) generateCorpusName(corpusID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/ragCorpora/%s", s.projectID, s.location, corpusID)
}

// parseCorpusName parses a corpus resource name to extract the corpus ID.
func (s *CorpusService) parseCorpusName(name string) (string, error) {
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}
	// This is a simplified parser - you might want to use a more robust implementation
	// that handles the full resource name parsing
	return name, nil
}
