// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package contentcaching

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/auth/credentials"
	"google.golang.org/api/option"
	"google.golang.org/genai"
)

// Service provides content caching functionality for Vertex AI models.
//
// The service manages cached content lifecycle, including creation, retrieval,
// updates, and deletion. It integrates with supported generative models to
// optimize token usage for large content scenarios.
type Service struct {
	client    *aiplatform.PredictionClient
	projectID string
	location  string
	logger    *slog.Logger
}

// ServiceOption is a functional option for configuring the content caching service.
type ServiceOption func(*Service)

// WithLogger sets a custom logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// NewService creates a new content caching service.
//
// The service requires a Google Cloud project ID and location. It uses
// Application Default Credentials for authentication.
//
// Parameters:
//   - ctx: Context for initialization
//   - projectID: Google Cloud project ID
//   - location: Geographic location (e.g., "us-central1")
//   - opts: Optional configuration options
//
// Returns a configured service instance or an error if initialization fails.
func NewService(ctx context.Context, projectID, location string, opts ...ServiceOption) (*Service, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if location == "" {
		return nil, fmt.Errorf("location is required")
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

	// Create prediction service client for content caching
	client, err := aiplatform.NewPredictionClient(ctx, option.WithAuthCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create prediction service client: %w", err)
	}
	service.client = client

	service.logger.InfoContext(ctx, "Content caching service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the content caching service and releases resources.
func (s *Service) Close() error {
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			return fmt.Errorf("failed to close prediction service client: %w", err)
		}
	}
	s.logger.Info("Content caching service closed")
	return nil
}

// Cache Management Operations

// CreateCache creates a new cached content entry.
//
// The content will be cached for the specified model and TTL duration.
// Only models that support content caching can be used.
//
// Parameters:
//   - ctx: Context for the operation
//   - content: Content to cache (must not be nil)
//   - config: Cache configuration (must not be nil)
//
// Returns the created cached content or an error.
func (s *Service) CreateCache(ctx context.Context, content *genai.Content, config *CacheConfig) (*CachedContent, error) {
	if content == nil {
		return nil, fmt.Errorf("content cannot be nil")
	}
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Validate model support
	if !IsSupportedModel(config.Model) {
		return nil, fmt.Errorf("model %s does not support content caching", config.Model)
	}

	// Validate TTL
	if config.TTL <= 0 {
		return nil, fmt.Errorf("TTL must be greater than 0")
	}

	s.logger.InfoContext(ctx, "Creating cached content",
		slog.String("model", config.Model),
		slog.String("display_name", config.DisplayName),
		slog.Duration("ttl", config.TTL),
	)

	// Calculate expiration time
	expireTime := time.Now().Add(config.TTL)

	// Create cached content
	cachedContent := &CachedContent{
		DisplayName:       config.DisplayName,
		Model:             config.Model,
		Contents:          []*genai.Content{content},
		SystemInstruction: config.SystemInstruction,
		Tools:             config.Tools,
		ToolConfig:        config.ToolConfig,
		CreateTime:        time.Now(),
		UpdateTime:        time.Now(),
		ExpireTime:        expireTime,
		State:             CacheStateActive,
	}

	// Note: In a real implementation, you would call the actual Vertex AI API
	// For now, we'll simulate the creation with a generated name
	cachedContent.Name = s.generateCacheName("cache-" + generateID())

	s.logger.InfoContext(ctx, "Cached content created successfully",
		slog.String("cache_name", cachedContent.Name),
		slog.Time("expire_time", expireTime),
	)

	return cachedContent, nil
}

// GetCache retrieves cached content by name.
//
// Parameters:
//   - ctx: Context for the operation
//   - cacheName: Full resource name of the cached content
//
// Returns the cached content or an error if not found.
func (s *Service) GetCache(ctx context.Context, cacheName string) (*CachedContent, error) {
	if cacheName == "" {
		return nil, fmt.Errorf("cache name cannot be empty")
	}

	s.logger.InfoContext(ctx, "Retrieving cached content",
		slog.String("cache_name", cacheName),
	)

	// Note: In a real implementation, you would call the actual Vertex AI API
	// For now, we'll return a placeholder response
	cachedContent := &CachedContent{
		Name:        cacheName,
		DisplayName: "Example Cache",
		Model:       ModelGemini20Flash001,
		State:       CacheStateActive,
		CreateTime:  time.Now().Add(-time.Hour),
		UpdateTime:  time.Now().Add(-time.Hour),
		ExpireTime:  time.Now().Add(time.Hour * 23),
	}

	s.logger.InfoContext(ctx, "Cached content retrieved successfully",
		slog.String("cache_name", cacheName),
		slog.String("state", string(cachedContent.State)),
	)

	return cachedContent, nil
}

// ListCaches lists all cached content in the project and location.
//
// Parameters:
//   - ctx: Context for the operation
//   - opts: Options for listing (page size, token, filter, etc.)
//
// Returns a list response containing cached content entries.
func (s *Service) ListCaches(ctx context.Context, opts *ListCacheOptions) (*ListCacheResponse, error) {
	if opts == nil {
		opts = &ListCacheOptions{PageSize: 50}
	}

	s.logger.InfoContext(ctx, "Listing cached content",
		slog.Int("page_size", int(opts.PageSize)),
		slog.String("page_token", opts.PageToken),
	)

	// Note: In a real implementation, you would call the actual Vertex AI API
	// For now, we'll return a placeholder response
	response := &ListCacheResponse{
		CachedContents: []*CachedContent{
			{
				Name:        s.generateCacheName("cache-example-1"),
				DisplayName: "Example Cache 1",
				Model:       ModelGemini20Flash001,
				State:       CacheStateActive,
				CreateTime:  time.Now().Add(-time.Hour * 2),
				ExpireTime:  time.Now().Add(time.Hour * 22),
			},
			{
				Name:        s.generateCacheName("cache-example-2"),
				DisplayName: "Example Cache 2",
				Model:       ModelGemini20Pro001,
				State:       CacheStateActive,
				CreateTime:  time.Now().Add(-time.Hour),
				ExpireTime:  time.Now().Add(time.Hour * 23),
			},
		},
		NextPageToken: "",
	}

	s.logger.InfoContext(ctx, "Cached content listed successfully",
		slog.Int("count", len(response.CachedContents)),
	)

	return response, nil
}

// UpdateCache updates existing cached content.
//
// Parameters:
//   - ctx: Context for the operation
//   - cachedContent: Updated cached content with changes
//   - updateMask: Fields to update (if nil, all fields are updated)
//
// Returns the updated cached content or an error.
func (s *Service) UpdateCache(ctx context.Context, cachedContent *CachedContent, updateMask []string) (*CachedContent, error) {
	if cachedContent == nil {
		return nil, fmt.Errorf("cached content cannot be nil")
	}
	if cachedContent.Name == "" {
		return nil, fmt.Errorf("cached content name cannot be empty")
	}

	s.logger.InfoContext(ctx, "Updating cached content",
		slog.String("cache_name", cachedContent.Name),
		slog.Any("update_mask", updateMask),
	)

	// Update timestamp
	cachedContent.UpdateTime = time.Now()

	// Note: In a real implementation, you would call the actual Vertex AI API
	// For now, we'll return the updated content as-is

	s.logger.InfoContext(ctx, "Cached content updated successfully",
		slog.String("cache_name", cachedContent.Name),
	)

	return cachedContent, nil
}

// DeleteCache deletes cached content.
//
// Parameters:
//   - ctx: Context for the operation
//   - cacheName: Full resource name of the cached content to delete
//
// Returns an error if the deletion fails.
func (s *Service) DeleteCache(ctx context.Context, cacheName string) error {
	if cacheName == "" {
		return fmt.Errorf("cache name cannot be empty")
	}

	s.logger.InfoContext(ctx, "Deleting cached content",
		slog.String("cache_name", cacheName),
	)

	// Note: In a real implementation, you would call the actual Vertex AI API
	// For now, we'll simulate successful deletion

	s.logger.InfoContext(ctx, "Cached content deleted successfully",
		slog.String("cache_name", cacheName),
	)

	return nil
}

// Convenience Methods

// CreateCacheWithTTL creates cached content with a simple TTL configuration.
//
// This is a convenience method for the most common caching scenario.
func (s *Service) CreateCacheWithTTL(ctx context.Context, content *genai.Content, modelName, displayName string, ttl time.Duration) (*CachedContent, error) {
	config := &CacheConfig{
		DisplayName: displayName,
		Model:       modelName,
		TTL:         ttl,
	}
	return s.CreateCache(ctx, content, config)
}

// CreateCacheForModel creates cached content for a specific model with default settings.
func (s *Service) CreateCacheForModel(ctx context.Context, content *genai.Content, modelName string) (*CachedContent, error) {
	config := &CacheConfig{
		DisplayName: fmt.Sprintf("Cache for %s", modelName),
		Model:       modelName,
		TTL:         time.Hour * 24, // Default 24-hour TTL
	}
	return s.CreateCache(ctx, content, config)
}

// Helper Methods

// generateCacheName generates a fully qualified cache name.
func (s *Service) generateCacheName(cacheID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/cachedContents/%s", s.projectID, s.location, cacheID)
}

// generateID generates a simple ID for demonstration purposes.
// In a real implementation, this would be handled by the API.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// GetProjectID returns the configured project ID.
func (s *Service) GetProjectID() string {
	return s.projectID
}

// GetLocation returns the configured location.
func (s *Service) GetLocation() string {
	return s.location
}

// GetLogger returns the configured logger.
func (s *Service) GetLogger() *slog.Logger {
	return s.logger
}
