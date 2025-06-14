// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"context"
	"fmt"
	"log/slog"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/auth/credentials"
	"google.golang.org/api/option"
)

// Service provides a unified interface for all Vertex AI Example Store operations.
type Service struct {
	storeService   *StoreService
	exampleService *ExampleService
	searchService  *SearchService
	projectID      string
	location       string
	logger         *slog.Logger
	client         *aiplatform.VertexRagDataClient
}

// ServiceOption is a functional option for configuring the Example Store service.
type ServiceOption func(*Service)

// WithLogger sets the logger for the Service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// NewService creates a new Vertex AI Example Store service.
//
// The service provides comprehensive functionality for managing Example Stores,
// uploading examples, and performing similarity-based retrieval for few-shot learning.
//
// Parameters:
//   - ctx: Context for the initialization
//   - projectID: Google Cloud project ID
//   - location: Geographic location for Vertex AI services (only "us-central1" supported)
//   - opts: Optional configuration options
//
// Returns a fully initialized Example Store service or an error if initialization fails.
func NewService(ctx context.Context, projectID, location string, opts ...ServiceOption) (*Service, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if location != SupportedRegion {
		return nil, fmt.Errorf("location %s is not supported, only %s is supported", location, SupportedRegion)
	}

	service := &Service{
		projectID: projectID,
		location:  location,
		logger:    slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(service)
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

	// Create Vertex RAG Data client (used for Example Store operations)
	ragDataClient, err := aiplatform.NewVertexRagDataClient(ctx, option.WithAuthCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create Vertex RAG data client: %w", err)
	}
	service.client = ragDataClient

	// Initialize sub-services
	service.storeService = NewStoreService(ragDataClient, projectID, location, service.logger)
	service.exampleService = NewExampleService(ragDataClient, projectID, location, service.logger)
	service.searchService = NewSearchService(ragDataClient, projectID, location, service.logger)

	service.logger.InfoContext(ctx, "Vertex AI Example Store service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the Example Store service and releases any resources.
func (s *Service) Close() error {
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			s.logger.Error("Failed to close Vertex RAG data client", slog.String("error", err.Error()))
			return fmt.Errorf("failed to close Vertex RAG data client: %w", err)
		}
	}
	s.logger.Info("Vertex AI Example Store service closed")
	return nil
}

// Store Management Methods

// CreateStore creates a new Example Store with the specified configuration.
//
// Example Store creation takes a few minutes to complete. The store will be in
// CREATING state initially and transition to ACTIVE when ready.
//
// Parameters:
//   - ctx: Context for the operation
//   - config: Configuration for the new store
//
// Returns the created store or an error if creation fails.
func (s *Service) CreateStore(ctx context.Context, config *StoreConfig) (*Store, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid store config: %w", err)
	}

	req := &CreateStoreRequest{
		Parent: s.generateParentName(),
		Store: &Store{
			DisplayName: config.DisplayName,
			Description: config.Description,
			Config:      config,
		},
	}

	return s.storeService.CreateStore(ctx, req)
}

// ListStores lists all Example Stores in the project and location.
func (s *Service) ListStores(ctx context.Context, pageSize int32, pageToken string) (*ListStoresResponse, error) {
	req := &ListStoresRequest{
		Parent:    s.generateParentName(),
		PageSize:  pageSize,
		PageToken: pageToken,
	}
	return s.storeService.ListStores(ctx, req)
}

// GetStore retrieves a specific Example Store by name.
func (s *Service) GetStore(ctx context.Context, storeName string) (*Store, error) {
	req := &GetStoreRequest{
		Name: storeName,
	}
	return s.storeService.GetStore(ctx, req)
}

// GetStoreByID retrieves a specific Example Store by ID.
func (s *Service) GetStoreByID(ctx context.Context, storeID string) (*Store, error) {
	storeName := s.GenerateStoreName(storeID)
	return s.GetStore(ctx, storeName)
}

// DeleteStore deletes an Example Store and all its examples.
func (s *Service) DeleteStore(ctx context.Context, storeName string, force bool) error {
	req := &DeleteStoreRequest{
		Name:  storeName,
		Force: force,
	}
	return s.storeService.DeleteStore(ctx, req)
}

// DeleteStoreByID deletes an Example Store by ID.
func (s *Service) DeleteStoreByID(ctx context.Context, storeID string, force bool) error {
	storeName := s.GenerateStoreName(storeID)
	return s.DeleteStore(ctx, storeName, force)
}

// Example Management Methods

// UploadExamples uploads examples to an Example Store.
//
// Maximum of 5 examples per request. Examples become available immediately
// after upload. Use batch operations for uploading larger sets of examples.
//
// Parameters:
//   - ctx: Context for the operation
//   - storeName: Full resource name of the store
//   - examples: Examples to upload (max 5)
//
// Returns the uploaded examples or an error if upload fails.
func (s *Service) UploadExamples(ctx context.Context, storeName string, examples []*Example) ([]*StoredExample, error) {
	if err := ValidateExamples(examples); err != nil {
		return nil, fmt.Errorf("invalid examples: %w", err)
	}

	req := &UploadExamplesRequest{
		Parent:   storeName,
		Examples: examples,
	}

	response, err := s.exampleService.UploadExamples(ctx, req)
	if err != nil {
		return nil, err
	}

	return response.Examples, nil
}

// UploadExamplesByStoreID uploads examples to an Example Store by ID.
func (s *Service) UploadExamplesByStoreID(ctx context.Context, storeID string, examples []*Example) ([]*StoredExample, error) {
	storeName := s.GenerateStoreName(storeID)
	return s.UploadExamples(ctx, storeName, examples)
}

// BatchUploadExamples uploads multiple batches of examples to an Example Store.
//
// This method handles batching automatically, ensuring each request contains
// at most 5 examples as required by the API.
func (s *Service) BatchUploadExamples(ctx context.Context, storeName string, examples []*Example) ([]*StoredExample, error) {
	if len(examples) == 0 {
		return nil, fmt.Errorf("at least one example is required")
	}

	var allResults []*StoredExample
	batchSize := MaxExamplesPerUpload

	for i := 0; i < len(examples); i += batchSize {
		end := i + batchSize
		if end > len(examples) {
			end = len(examples)
		}

		batch := examples[i:end]
		results, err := s.UploadExamples(ctx, storeName, batch)
		if err != nil {
			return allResults, fmt.Errorf("failed to upload batch %d-%d: %w", i, end-1, err)
		}

		allResults = append(allResults, results...)

		s.logger.InfoContext(ctx, "Uploaded example batch",
			slog.String("store", storeName),
			slog.Int("batch_start", i),
			slog.Int("batch_end", end-1),
			slog.Int("batch_size", len(batch)),
		)
	}

	s.logger.InfoContext(ctx, "Batch upload completed",
		slog.String("store", storeName),
		slog.Int("total_examples", len(examples)),
		slog.Int("total_uploaded", len(allResults)),
	)

	return allResults, nil
}

// ListExamples lists all examples in an Example Store.
func (s *Service) ListExamples(ctx context.Context, storeName string, pageSize int32, pageToken string) (*ListExamplesResponse, error) {
	req := &ListExamplesRequest{
		Parent:    storeName,
		PageSize:  pageSize,
		PageToken: pageToken,
	}
	return s.exampleService.ListExamples(ctx, req)
}

// ListExamplesByStoreID lists examples by store ID.
func (s *Service) ListExamplesByStoreID(ctx context.Context, storeID string, pageSize int32, pageToken string) (*ListExamplesResponse, error) {
	storeName := s.GenerateStoreName(storeID)
	return s.ListExamples(ctx, storeName, pageSize, pageToken)
}

// DeleteExample deletes a specific example from an Example Store.
func (s *Service) DeleteExample(ctx context.Context, exampleName string) error {
	req := &DeleteExampleRequest{
		Name: exampleName,
	}
	return s.exampleService.DeleteExample(ctx, req)
}

// BatchDeleteExamples deletes multiple examples from an Example Store.
func (s *Service) BatchDeleteExamples(ctx context.Context, exampleNames []string) error {
	req := &BatchDeleteExamplesRequest{
		Names: exampleNames,
	}
	return s.exampleService.BatchDeleteExamples(ctx, req)
}

// Search and Retrieval Methods

// SearchExamples searches for relevant examples in an Example Store.
//
// Uses vector similarity to find examples most similar to the query text.
// This is the primary method for retrieving examples for few-shot learning.
//
// Parameters:
//   - ctx: Context for the operation
//   - storeName: Full resource name of the store
//   - queryText: Text to search for similar examples
//   - topK: Number of top results to return
//
// Returns search results ordered by similarity score.
func (s *Service) SearchExamples(ctx context.Context, storeName, queryText string, topK int32) ([]*SearchResult, error) {
	query := &SearchQuery{
		Text: queryText,
		TopK: topK,
	}

	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("invalid search query: %w", err)
	}

	req := &SearchExamplesRequest{
		Parent: storeName,
		Query:  query,
	}

	response, err := s.searchService.SearchExamples(ctx, req)
	if err != nil {
		return nil, err
	}

	return response.Results, nil
}

// SearchExamplesByStoreID searches examples by store ID.
func (s *Service) SearchExamplesByStoreID(ctx context.Context, storeID, queryText string, topK int32) ([]*SearchResult, error) {
	storeName := s.GenerateStoreName(storeID)
	return s.SearchExamples(ctx, storeName, queryText, topK)
}

// SearchExamplesAdvanced searches for examples with advanced filtering options.
func (s *Service) SearchExamplesAdvanced(ctx context.Context, storeName string, query *SearchQuery) ([]*SearchResult, error) {
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("invalid search query: %w", err)
	}

	req := &SearchExamplesRequest{
		Parent: storeName,
		Query:  query,
	}

	response, err := s.searchService.SearchExamples(ctx, req)
	if err != nil {
		return nil, err
	}

	return response.Results, nil
}

// Convenience Methods

// CreateDefaultStore creates an Example Store with default configuration.
func (s *Service) CreateDefaultStore(ctx context.Context, displayName, description string) (*Store, error) {
	config := &StoreConfig{
		EmbeddingModel: DefaultEmbeddingModel,
		DisplayName:    displayName,
		Description:    description,
	}
	return s.CreateStore(ctx, config)
}

// QuickSearch performs a search with default parameters.
func (s *Service) QuickSearch(ctx context.Context, storeName, queryText string) ([]*SearchResult, error) {
	return s.SearchExamples(ctx, storeName, queryText, DefaultTopK)
}

// QuickSearchByStoreID performs a search by store ID with default parameters.
func (s *Service) QuickSearchByStoreID(ctx context.Context, storeID, queryText string) ([]*SearchResult, error) {
	storeName := s.GenerateStoreName(storeID)
	return s.QuickSearch(ctx, storeName, queryText)
}

// Helper Methods

// GenerateStoreName generates a fully qualified store name.
func (s *Service) GenerateStoreName(storeID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/exampleStores/%s", s.projectID, s.location, storeID)
}

// GenerateExampleName generates a fully qualified example name.
func (s *Service) GenerateExampleName(storeID, exampleID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/exampleStores/%s/examples/%s", s.projectID, s.location, storeID, exampleID)
}

// generateParentName generates the parent resource name for stores.
func (s *Service) generateParentName() string {
	return fmt.Sprintf("projects/%s/locations/%s", s.projectID, s.location)
}

// GetProjectID returns the project ID.
func (s *Service) GetProjectID() string {
	return s.projectID
}

// GetLocation returns the location.
func (s *Service) GetLocation() string {
	return s.location
}

// GetLogger returns the logger.
func (s *Service) GetLogger() *slog.Logger {
	return s.logger
}

// Statistics and Monitoring Methods

// GetStoreStats retrieves statistics about an Example Store.
func (s *Service) GetStoreStats(ctx context.Context, storeName string) (*ExampleStoreStats, error) {
	return s.storeService.GetStoreStats(ctx, storeName)
}

// GetStoreStatsByID retrieves statistics by store ID.
func (s *Service) GetStoreStatsByID(ctx context.Context, storeID string) (*ExampleStoreStats, error) {
	storeName := s.GenerateStoreName(storeID)
	return s.GetStoreStats(ctx, storeName)
}

// HealthCheck performs a basic health check of the service.
func (s *Service) HealthCheck(ctx context.Context) error {
	s.logger.InfoContext(ctx, "Performing Example Store service health check")

	if s.client == nil {
		return fmt.Errorf("Vertex RAG data client not initialized")
	}

	if s.storeService == nil {
		return fmt.Errorf("store service not initialized")
	}

	if s.exampleService == nil {
		return fmt.Errorf("example service not initialized")
	}

	if s.searchService == nil {
		return fmt.Errorf("search service not initialized")
	}

	s.logger.InfoContext(ctx, "Example Store service health check passed")
	return nil
}

// GetServiceStatus returns the status of all sub-services.
func (s *Service) GetServiceStatus() map[string]string {
	status := make(map[string]string)

	if s.storeService != nil {
		status["store_service"] = "initialized"
	} else {
		status["store_service"] = "not_initialized"
	}

	if s.exampleService != nil {
		status["example_service"] = "initialized"
	} else {
		status["example_service"] = "not_initialized"
	}

	if s.searchService != nil {
		status["search_service"] = "initialized"
	} else {
		status["search_service"] = "not_initialized"
	}

	if s.client != nil {
		status["rag_data_client"] = "initialized"
	} else {
		status["rag_data_client"] = "not_initialized"
	}

	return status
}
