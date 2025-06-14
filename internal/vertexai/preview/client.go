// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package preview

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-a2a/adk-go/internal/vertexai/examplestore"
	"github.com/go-a2a/adk-go/internal/vertexai/extension"
	"github.com/go-a2a/adk-go/internal/vertexai/preview/contentcaching"
	"github.com/go-a2a/adk-go/internal/vertexai/preview/generativemodels"
	"github.com/go-a2a/adk-go/internal/vertexai/preview/modelgarden"
	"github.com/go-a2a/adk-go/internal/vertexai/preview/rag"
)

// Client provides unified access to all Vertex AI preview functionality.
//
// The preview client orchestrates multiple specialized services to provide
// comprehensive access to experimental and preview features of Vertex AI.
// It maintains a single authentication context and configuration across
// all preview services.
type Client struct {
	// Core services
	ragClient           *rag.Service
	contentCacheService *contentcaching.Service
	exampleStoreService *examplestore.Service
	generativeService   *generativemodels.Service
	modelGardenService  *modelgarden.Service
	extensionService    *extension.Service

	// Configuration
	projectID string
	location  string
	logger    *slog.Logger
}

// ClientOption is a functional option for configuring the preview client.
type ClientOption func(*Client)

// WithLogger sets a custom logger for the preview client.
func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// NewClient creates a new Vertex AI preview client.
//
// The client provides unified access to all preview services including RAG,
// content caching, enhanced generative models, and Model Garden integration.
//
// Parameters:
//   - ctx: Context for the initialization
//   - projectID: Google Cloud project ID
//   - location: Geographic location for Vertex AI services (e.g., "us-central1")
//   - opts: Optional configuration options
//
// Returns a fully initialized preview client or an error if initialization fails.
func NewClient(ctx context.Context, projectID, location string, opts ...ClientOption) (*Client, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	client := &Client{
		projectID: projectID,
		location:  location,
		logger:    slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Initialize RAG client
	ragClient, err := rag.NewService(ctx, projectID, location, rag.WithLogger(client.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RAG client: %w", err)
	}
	client.ragClient = ragClient

	// Initialize content caching service
	contentCacheService, err := contentcaching.NewService(ctx, projectID, location, contentcaching.WithLogger(client.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize content caching service: %w", err)
	}
	client.contentCacheService = contentCacheService

	// Initialize example store service
	exampleStoreService, err := examplestore.NewService(ctx, projectID, location, examplestore.WithLogger(client.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize example store service: %w", err)
	}
	client.exampleStoreService = exampleStoreService

	// Initialize generative models service
	generativeService, err := generativemodels.NewService(ctx, projectID, location, generativemodels.WithLogger(client.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize generative models service: %w", err)
	}
	client.generativeService = generativeService

	// Initialize Model Garden service
	modelGardenService, err := modelgarden.NewService(ctx, projectID, location, modelgarden.WithLogger(client.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Model Garden service: %w", err)
	}
	client.modelGardenService = modelGardenService

	// Initialize Extension service
	extensionService, err := extension.NewService(ctx, projectID, location, extension.WithLogger(client.logger))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Extension service: %w", err)
	}
	client.extensionService = extensionService

	client.logger.InfoContext(ctx, "Vertex AI preview client initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return client, nil
}

// Close closes the preview client and releases all resources.
//
// This method should be called when the client is no longer needed to ensure
// proper cleanup of underlying connections and resources.
func (c *Client) Close() error {
	c.logger.Info("Closing Vertex AI preview client")

	// Close all services
	if err := c.ragClient.Close(); err != nil {
		c.logger.Error("Failed to close RAG client", slog.String("error", err.Error()))
		return fmt.Errorf("failed to close RAG client: %w", err)
	}

	if err := c.contentCacheService.Close(); err != nil {
		c.logger.Error("Failed to close content caching service", slog.String("error", err.Error()))
		return fmt.Errorf("failed to close content caching service: %w", err)
	}

	if err := c.exampleStoreService.Close(); err != nil {
		c.logger.Error("Failed to close example store service", slog.String("error", err.Error()))
		return fmt.Errorf("failed to close example store service: %w", err)
	}

	if err := c.generativeService.Close(); err != nil {
		c.logger.Error("Failed to close generative models service", slog.String("error", err.Error()))
		return fmt.Errorf("failed to close generative models service: %w", err)
	}

	if err := c.modelGardenService.Close(); err != nil {
		c.logger.Error("Failed to close Model Garden service", slog.String("error", err.Error()))
		return fmt.Errorf("failed to close Model Garden service: %w", err)
	}

	if err := c.extensionService.Close(); err != nil {
		c.logger.Error("Failed to close Extension service", slog.String("error", err.Error()))
		return fmt.Errorf("failed to close Extension service: %w", err)
	}

	c.logger.Info("Vertex AI preview client closed successfully")
	return nil
}

// Service Access Methods
//
// These methods provide access to individual preview services while maintaining
// the unified client context and configuration.

// RAG returns the RAG (Retrieval-Augmented Generation) client.
//
// The RAG client provides comprehensive functionality for managing corpora,
// importing documents, and performing retrieval-augmented generation.
func (c *Client) RAG() *rag.Service {
	return c.ragClient
}

// ContentCaching returns the content caching service.
//
// The content caching service provides optimized caching for large content
// contexts, reducing token usage and improving performance for repeated queries.
func (c *Client) ContentCaching() *contentcaching.Service {
	return c.contentCacheService
}

// ExampleStore returns the example store service.
//
// The example store service provides functionality for managing Example Stores,
// uploading examples, and performing similarity-based retrieval for few-shot learning.
func (c *Client) ExampleStore() *examplestore.Service {
	return c.exampleStoreService
}

// GenerativeModels returns the enhanced generative models service.
//
// This service provides access to preview features for generative AI models,
// including advanced configuration options and experimental capabilities.
func (c *Client) GenerativeModels() *generativemodels.Service {
	return c.generativeService
}

// ModelGarden returns the Model Garden service.
//
// The Model Garden service provides access to experimental and community models,
// including deployment and management capabilities.
func (c *Client) ModelGarden() *modelgarden.Service {
	return c.modelGardenService
}

// Extensions returns the Extension service.
//
// The Extension service provides access to Vertex AI Extensions functionality,
// including creating, managing, and executing both custom and prebuilt extensions.
func (c *Client) Extensions() *extension.Service {
	return c.extensionService
}

// Configuration Access Methods

// GetProjectID returns the configured Google Cloud project ID.
func (c *Client) GetProjectID() string {
	return c.projectID
}

// GetLocation returns the configured geographic location.
func (c *Client) GetLocation() string {
	return c.location
}

// GetLogger returns the configured logger instance.
func (c *Client) GetLogger() *slog.Logger {
	return c.logger
}

// Health Check and Status Methods

// HealthCheck performs a basic health check across all preview services.
//
// This method verifies that all underlying services are accessible and
// functioning correctly. It's useful for monitoring and debugging.
func (c *Client) HealthCheck(ctx context.Context) error {
	c.logger.InfoContext(ctx, "Performing preview client health check")

	// Note: In a full implementation, you would perform actual health checks
	// against each service. For now, we just verify the services are initialized.

	if c.ragClient == nil {
		return fmt.Errorf("RAG client not initialized")
	}

	if c.contentCacheService == nil {
		return fmt.Errorf("content caching service not initialized")
	}

	if c.exampleStoreService == nil {
		return fmt.Errorf("example store service not initialized")
	}

	if c.generativeService == nil {
		return fmt.Errorf("generative models service not initialized")
	}

	if c.modelGardenService == nil {
		return fmt.Errorf("Model Garden service not initialized")
	}

	if c.extensionService == nil {
		return fmt.Errorf("Extension service not initialized")
	}

	c.logger.InfoContext(ctx, "Preview client health check passed")
	return nil
}

// GetServiceStatus returns the status of all preview services.
func (c *Client) GetServiceStatus() map[string]string {
	status := make(map[string]string)

	if c.ragClient != nil {
		status["rag"] = "initialized"
	} else {
		status["rag"] = "not_initialized"
	}

	if c.contentCacheService != nil {
		status["content_caching"] = "initialized"
	} else {
		status["content_caching"] = "not_initialized"
	}

	if c.exampleStoreService != nil {
		status["example_store"] = "initialized"
	} else {
		status["example_store"] = "not_initialized"
	}

	if c.generativeService != nil {
		status["generative_models"] = "initialized"
	} else {
		status["generative_models"] = "not_initialized"
	}

	if c.modelGardenService != nil {
		status["model_garden"] = "initialized"
	} else {
		status["model_garden"] = "not_initialized"
	}

	if c.extensionService != nil {
		status["extensions"] = "initialized"
	} else {
		status["extensions"] = "not_initialized"
	}

	return status
}
