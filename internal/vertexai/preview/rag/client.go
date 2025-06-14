// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag

import (
	"context"
	"fmt"
	"log/slog"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/auth/credentials"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Service provides a unified interface for all Vertex AI RAG operations.
type Service struct {
	corpusService    *CorpusService
	fileService      *FileService
	retrievalService *RetrievalService
	projectID        string
	location         string
	logger           *slog.Logger
}

// ServiceOption is a functional option for configuring the RAG service.
type ServiceOption func(*Service)

// WithLogger sets the logger for the Client.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(c *Service) {
		c.logger = logger
	}
}

// NewService creates a new Vertex AI RAG client.
func NewService(ctx context.Context, projectID, location string, opts ...ServiceOption) (*Service, error) {
	client := &Service{
		projectID: projectID,
		location:  location,
		logger:    slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Create credentials
	creds, err := credentials.DetectDefault(&credentials.DetectOptions{
		Scopes: []string{
			"https://www.googleapis.com/auth/cloud-platform",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect default credentials: %w", err)
	}

	// Create RAG client
	ragClient, err := aiplatform.NewVertexRagClient(ctx, option.WithAuthCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create Vertex RAG client: %w", err)
	}

	// Create RAG data client
	ragDataClient, err := aiplatform.NewVertexRagDataClient(ctx, option.WithAuthCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create Vertex RAG data client: %w", err)
	}

	// Initialize services
	client.corpusService = NewCorpusService(ragDataClient, projectID, location, client.logger)
	client.fileService = NewFileService(ragClient, ragDataClient, projectID, location, client.logger)
	client.retrievalService = NewRetrievalService(ragClient, projectID, location, client.logger)

	client.logger.InfoContext(ctx, "Vertex AI RAG client initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return client, nil
}

// Close closes the RAG client and releases any resources.
func (c *Service) Close() error {
	// Note: In a full implementation, you would close the underlying clients
	// For now, we don't have explicit close methods on the underlying clients
	c.logger.Info("Vertex AI RAG client closed")
	return nil
}

// Corpus Management Methods

// CreateCorpus creates a new RAG corpus.
func (c *Service) CreateCorpus(ctx context.Context, displayName, description string, backendConfig *VectorDbConfig) (*Corpus, error) {
	req := &CreateCorpusRequest{
		Corpus: &Corpus{
			DisplayName:   displayName,
			Description:   description,
			BackendConfig: backendConfig,
		},
	}
	return c.corpusService.CreateCorpus(ctx, req)
}

// ListCorpora lists all RAG corpora in the project and location.
func (c *Service) ListCorpora(ctx context.Context, pageSize int32, pageToken string) (*ListCorporaResponse, error) {
	req := &ListCorporaRequest{
		PageSize:  pageSize,
		PageToken: pageToken,
	}
	return c.corpusService.ListCorpora(ctx, req)
}

// GetCorpus retrieves a specific RAG corpus.
func (c *Service) GetCorpus(ctx context.Context, corpusName string) (*Corpus, error) {
	req := &GetCorpusRequest{
		Name: corpusName,
	}
	return c.corpusService.GetCorpus(ctx, req)
}

// DeleteCorpus deletes a RAG corpus.
func (c *Service) DeleteCorpus(ctx context.Context, corpusName string, force bool) error {
	req := &DeleteCorpusRequest{
		Name:  corpusName,
		Force: force,
	}
	return c.corpusService.DeleteCorpus(ctx, req)
}

// UpdateCorpus updates a RAG corpus.
func (c *Service) UpdateCorpus(ctx context.Context, corpus *Corpus, updateMask *fieldmaskpb.FieldMask) (*Corpus, error) {
	return c.corpusService.UpdateCorpus(ctx, corpus, updateMask)
}

// File Management Methods

// ImportFiles imports files into a RAG corpus from various sources.
func (c *Service) ImportFiles(ctx context.Context, corpusName string, config *ImportFilesConfig) error {
	req := &ImportFilesRequest{
		Parent:            corpusName,
		ImportFilesConfig: config,
	}
	return c.fileService.ImportFiles(ctx, req)
}

// ImportFilesFromGCS imports files from Google Cloud Storage.
func (c *Service) ImportFilesFromGCS(ctx context.Context, corpusName string, gcsUris []string, chunkSize, chunkOverlap int32) error {
	config := &ImportFilesConfig{
		GcsSource: &GcsSource{
			Uris: gcsUris,
		},
		ChunkSize:    chunkSize,
		ChunkOverlap: chunkOverlap,
	}
	return c.ImportFiles(ctx, corpusName, config)
}

// ImportFilesFromGoogleDrive imports files from Google Drive.
func (c *Service) ImportFilesFromGoogleDrive(ctx context.Context, corpusName string, resourceIds []string, chunkSize, chunkOverlap int32) error {
	config := &ImportFilesConfig{
		GoogleDriveSource: &GoogleDriveSource{
			ResourceIds: resourceIds,
		},
		ChunkSize:    chunkSize,
		ChunkOverlap: chunkOverlap,
	}
	return c.ImportFiles(ctx, corpusName, config)
}

// UploadFile uploads a file directly to a RAG corpus.
func (c *Service) UploadFile(ctx context.Context, corpusName string, file *RagFile, config *UploadRagFileConfig) (*RagFile, error) {
	req := &UploadFileRequest{
		Parent:              corpusName,
		RagFile:             file,
		UploadRagFileConfig: config,
	}
	return c.fileService.UploadFile(ctx, req)
}

// ListFiles lists all files in a RAG corpus.
func (c *Service) ListFiles(ctx context.Context, corpusName string, pageSize int32, pageToken string) (*ListFilesResponse, error) {
	req := &ListFilesRequest{
		Parent:    corpusName,
		PageSize:  pageSize,
		PageToken: pageToken,
	}
	return c.fileService.ListFiles(ctx, req)
}

// GetFile retrieves a specific file from a RAG corpus.
func (c *Service) GetFile(ctx context.Context, fileName string) (*RagFile, error) {
	return c.fileService.GetFile(ctx, fileName)
}

// DeleteFile deletes a file from a RAG corpus.
func (c *Service) DeleteFile(ctx context.Context, fileName string) error {
	req := &DeleteFileRequest{
		Name: fileName,
	}
	return c.fileService.DeleteFile(ctx, req)
}

// Retrieval and Search Methods

// Query queries a specific corpus for relevant documents.
func (c *Service) Query(ctx context.Context, corpusName, queryText string, topK int32, distanceThreshold float64) (*RetrievalResponse, error) {
	query := &RetrievalQuery{
		Text:                    queryText,
		SimilarityTopK:          topK,
		VectorDistanceThreshold: distanceThreshold,
	}
	return c.retrievalService.QueryCorpus(ctx, corpusName, query)
}

// QueryMultiple queries multiple corpora for relevant documents.
func (c *Service) QueryMultiple(ctx context.Context, corporaNames []string, queryText string, topK int32, distanceThreshold float64) (*RetrievalResponse, error) {
	query := &RetrievalQuery{
		Text:                    queryText,
		SimilarityTopK:          topK,
		VectorDistanceThreshold: distanceThreshold,
	}
	return c.retrievalService.QueryMultipleCorpora(ctx, corporaNames, query)
}

// RetrieveContexts retrieves relevant contexts from RAG corpora for a given query.
func (c *Service) RetrieveContexts(ctx context.Context, query *RetrievalQuery, ragResources []string) (*RetrievalResponse, error) {
	return c.retrievalService.RetrieveContexts(ctx, query, ragResources)
}

// Search performs a general search across RAG corpora.
func (c *Service) Search(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	return c.retrievalService.Search(ctx, req)
}

// SemanticSearch performs semantic search using vector similarity.
func (c *Service) SemanticSearch(ctx context.Context, query string, corporaNames []string, options *SemanticSearchOptions) (*SearchResponse, error) {
	return c.retrievalService.SemanticSearch(ctx, query, corporaNames, options)
}

// HybridSearch performs hybrid search combining vector and keyword search.
func (c *Service) HybridSearch(ctx context.Context, query string, corporaNames []string, options *HybridSearchOptions) (*SearchResponse, error) {
	return c.retrievalService.HybridSearch(ctx, query, corporaNames, options)
}

// AugmentGeneration augments generation with retrieval from RAG corpora.
func (c *Service) AugmentGeneration(ctx context.Context, req *AugmentGenerationRequest) (*AugmentGenerationResponse, error) {
	return c.retrievalService.AugmentGeneration(ctx, req)
}

// Convenience Methods

// CreateDefaultCorpus creates a corpus with default managed database configuration.
func (c *Service) CreateDefaultCorpus(ctx context.Context, displayName, description string) (*Corpus, error) {
	backendConfig := &VectorDbConfig{
		RagEmbeddingModelConfig: &EmbeddingModelConfig{
			PublisherModel: "publishers/google/models/text-embedding-005",
		},
		RagManagedDb: &RagManagedDbConfig{
			RetrievalConfig: &RetrievalConfig{
				TopK:        10,
				MaxDistance: 0.7,
			},
		},
	}
	return c.CreateCorpus(ctx, displayName, description, backendConfig)
}

// QuickQuery performs a quick query with default parameters.
func (c *Service) QuickQuery(ctx context.Context, corpusName, queryText string) (*RetrievalResponse, error) {
	return c.Query(ctx, corpusName, queryText, 10, 0.7)
}

// QuickSearch performs a quick semantic search with default parameters.
func (c *Service) QuickSearch(ctx context.Context, query string, corporaNames []string) (*SearchResponse, error) {
	return c.SemanticSearch(ctx, query, corporaNames, nil)
}

// Helper Methods

// GenerateCorpusName generates a fully qualified corpus name.
func (c *Service) GenerateCorpusName(corpusID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/ragCorpora/%s", c.projectID, c.location, corpusID)
}

// GenerateFileName generates a fully qualified file name.
func (c *Service) GenerateFileName(corpusID, fileID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/ragCorpora/%s/ragFiles/%s", c.projectID, c.location, corpusID, fileID)
}

// GetProjectID returns the project ID.
func (c *Service) GetProjectID() string {
	return c.projectID
}

// GetLocation returns the location.
func (c *Service) GetLocation() string {
	return c.location
}

// GetLogger returns the logger.
func (c *Service) GetLogger() *slog.Logger {
	return c.logger
}

// Batch operations

// BatchDeleteFiles deletes multiple files from a corpus.
func (c *Service) BatchDeleteFiles(ctx context.Context, fileNames []string) error {
	c.logger.InfoContext(ctx, "Batch deleting RAG files",
		slog.Int("files_count", len(fileNames)),
	)

	for _, fileName := range fileNames {
		if err := c.DeleteFile(ctx, fileName); err != nil {
			c.logger.ErrorContext(ctx, "Failed to delete file",
				slog.String("file_name", fileName),
				slog.String("error", err.Error()),
			)
			return fmt.Errorf("failed to delete file %s: %w", fileName, err)
		}
	}

	c.logger.InfoContext(ctx, "Batch delete completed successfully",
		slog.Int("files_count", len(fileNames)),
	)

	return nil
}

// BatchImportFiles imports multiple files from different sources.
func (c *Service) BatchImportFiles(ctx context.Context, corpusName string, sources []ImportSource) error {
	c.logger.InfoContext(ctx, "Batch importing files from multiple sources",
		slog.String("corpus", corpusName),
		slog.Int("sources_count", len(sources)),
	)

	for i, source := range sources {
		var config *ImportFilesConfig

		switch {
		case source.GcsUris != nil:
			config = &ImportFilesConfig{
				GcsSource:    &GcsSource{Uris: source.GcsUris},
				ChunkSize:    source.ChunkSize,
				ChunkOverlap: source.ChunkOverlap,
			}
		case source.GoogleDriveResourceIds != nil:
			config = &ImportFilesConfig{
				GoogleDriveSource: &GoogleDriveSource{ResourceIds: source.GoogleDriveResourceIds},
				ChunkSize:         source.ChunkSize,
				ChunkOverlap:      source.ChunkOverlap,
			}
		default:
			return fmt.Errorf("invalid import source at index %d: must specify either GcsUris or GoogleDriveResourceIds", i)
		}

		if err := c.ImportFiles(ctx, corpusName, config); err != nil {
			return fmt.Errorf("failed to import files from source %d: %w", i, err)
		}
	}

	c.logger.InfoContext(ctx, "Batch import completed successfully",
		slog.Int("sources_count", len(sources)),
	)

	return nil
}

// ImportSource represents a source for importing files.
type ImportSource struct {
	// GcsUris are the Google Cloud Storage URIs.
	GcsUris []string `json:"gcs_uris,omitempty"`

	// GoogleDriveResourceIds are the Google Drive resource IDs.
	GoogleDriveResourceIds []string `json:"google_drive_resource_ids,omitempty"`

	// ChunkSize is the chunk size for processing files.
	ChunkSize int32 `json:"chunk_size,omitempty"`

	// ChunkOverlap is the overlap between chunks.
	ChunkOverlap int32 `json:"chunk_overlap,omitempty"`
}
