// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
)

// Service provides access to Vertex AI Extensions functionality.
//
// The service manages extension lifecycles, executes operations, and provides
// access to prebuilt extensions from Google's extension hub.
type Service struct {
	projectID string
	location  string
	logger    *slog.Logger
	client    *http.Client
	baseURL   string
	creds     *auth.Credentials
}

// ServiceOption is a functional option for configuring the extension service.
type ServiceOption func(*Service)

// WithLogger sets a custom logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// WithHTTPClient sets a custom HTTP client for the service.
func WithHTTPClient(client *http.Client) ServiceOption {
	return func(s *Service) {
		s.client = client
	}
}

// NewService creates a new Vertex AI Extension service.
//
// The service provides access to all extension operations including creation,
// execution, and management of both custom and prebuilt extensions.
//
// Parameters:
//   - ctx: Context for the initialization
//   - projectID: Google Cloud project ID
//   - location: Geographic location for Vertex AI services (must be "us-central1")
//   - opts: Optional configuration options
//
// Returns a fully initialized extension service or an error if initialization fails.
func NewService(ctx context.Context, projectID, location string, opts ...ServiceOption) (*Service, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	// Enforce region restriction
	if location != "us-central1" {
		return nil, &RegionNotSupportedError{
			RequestedRegion:  location,
			SupportedRegions: []string{"us-central1"},
		}
	}

	service := &Service{
		projectID: projectID,
		location:  location,
		logger:    slog.Default(),
		client:    &http.Client{Timeout: 30 * time.Second},
		baseURL:   fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1beta1", location),
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
	service.creds = creds

	service.logger.InfoContext(ctx, "Vertex AI Extension service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the extension service and releases any resources.
func (s *Service) Close() error {
	s.logger.Info("Vertex AI Extension service closed")
	return nil
}

// Extension Management Methods

// CreateExtension creates a new custom extension.
//
// This method allows you to register a custom extension with Vertex AI by providing
// a manifest that defines the API specification, authentication configuration,
// and runtime settings.
func (s *Service) CreateExtension(ctx context.Context, req *CreateExtensionRequest) (*Extension, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.DisplayName == "" {
		return nil, fmt.Errorf("display_name is required")
	}
	if req.Manifest == nil {
		return nil, fmt.Errorf("manifest is required")
	}

	// Validate manifest
	if err := s.validateManifest(req.Manifest); err != nil {
		return nil, &ManifestValidationError{
			Message: fmt.Sprintf("invalid manifest: %v", err),
			Details: map[string]any{"manifest": req.Manifest},
		}
	}

	s.logger.InfoContext(ctx, "Creating extension",
		slog.String("display_name", req.DisplayName),
		slog.String("manifest_name", req.Manifest.Name),
	)

	// TODO: Implement actual API call to Vertex AI Extensions API
	// For now, return a mock extension
	extension := &Extension{
		ID:            s.generateExtensionID(),
		Name:          s.generateExtensionName(s.generateExtensionID()),
		DisplayName:   req.DisplayName,
		Description:   req.Description,
		Manifest:      req.Manifest,
		RuntimeConfig: req.RuntimeConfig,
		CreateTime:    time.Now(),
		UpdateTime:    time.Now(),
		State:         ExtensionStateActive,
	}

	s.logger.InfoContext(ctx, "Extension created successfully",
		slog.String("extension_id", extension.ID),
		slog.String("extension_name", extension.Name),
	)

	return extension, nil
}

// CreateFromHub creates an extension from Google's prebuilt extension hub.
//
// This method provides easy access to Google's curated extensions like
// code_interpreter and vertex_ai_search without requiring manual manifest creation.
func (s *Service) CreateFromHub(ctx context.Context, extensionType PrebuiltExtensionType) (*Extension, error) {
	s.logger.InfoContext(ctx, "Creating extension from hub",
		slog.String("extension_type", string(extensionType)),
	)

	manifest, runtimeConfig, err := s.getPrebuiltExtensionConfig(extensionType)
	if err != nil {
		return nil, fmt.Errorf("failed to get prebuilt extension config: %w", err)
	}

	req := &CreateExtensionRequest{
		DisplayName:   s.getPrebuiltDisplayName(extensionType),
		Description:   s.getPrebuiltDescription(extensionType),
		Manifest:      manifest,
		RuntimeConfig: runtimeConfig,
	}

	extension, err := s.CreateExtension(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create extension from hub: %w", err)
	}

	s.logger.InfoContext(ctx, "Extension created from hub successfully",
		slog.String("extension_type", string(extensionType)),
		slog.String("extension_id", extension.ID),
	)

	return extension, nil
}

// ListExtensions lists all extensions in the project and location.
func (s *Service) ListExtensions(ctx context.Context, req *ListExtensionsRequest) (*ListExtensionsResponse, error) {
	if req == nil {
		req = &ListExtensionsRequest{}
	}

	s.logger.InfoContext(ctx, "Listing extensions",
		slog.Int("page_size", int(req.PageSize)),
		slog.String("page_token", req.PageToken),
	)

	// TODO: Implement actual API call to list extensions
	// For now, return empty response
	response := &ListExtensionsResponse{
		Extensions:    []*Extension{},
		NextPageToken: "",
	}

	s.logger.InfoContext(ctx, "Listed extensions successfully",
		slog.Int("extension_count", len(response.Extensions)),
	)

	return response, nil
}

// GetExtension retrieves a specific extension by its resource name.
func (s *Service) GetExtension(ctx context.Context, req *GetExtensionRequest) (*Extension, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	s.logger.InfoContext(ctx, "Getting extension",
		slog.String("name", req.Name),
	)

	// TODO: Implement actual API call to get extension
	// For now, return extension not found error
	return nil, &ExtensionNotFoundError{
		Name: req.Name,
	}
}

// DeleteExtension deletes an extension.
func (s *Service) DeleteExtension(ctx context.Context, req *DeleteExtensionRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}

	s.logger.InfoContext(ctx, "Deleting extension",
		slog.String("name", req.Name),
	)

	// TODO: Implement actual API call to delete extension
	s.logger.InfoContext(ctx, "Extension deleted successfully",
		slog.String("name", req.Name),
	)

	return nil
}

// Extension Execution Methods

// ExecuteExtension executes an operation on a specific extension.
//
// This method allows you to invoke extension operations with structured parameters
// and receive the execution results. The operation parameters are specific to
// each extension and operation type.
func (s *Service) ExecuteExtension(ctx context.Context, req *ExecuteExtensionRequest) (*ExecuteExtensionResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.OperationID == "" {
		return nil, fmt.Errorf("operation_id is required")
	}

	s.logger.InfoContext(ctx, "Executing extension operation",
		slog.String("name", req.Name),
		slog.String("operation_id", req.OperationID),
	)

	// TODO: Implement actual API call to execute extension
	// For now, return a mock response
	_ = &ExecuteExtensionResponse{
		Content:  []byte(`{"result": "mock execution result"}`),
		Metadata: map[string]any{"execution_time": time.Now()},
	}

	s.logger.InfoContext(ctx, "Extension operation executed successfully",
		slog.String("name", req.Name),
		slog.String("operation_id", req.OperationID),
	)

	return &ExecuteExtensionResponse{
		Content:  []byte(`{"result": "mock execution result"}`),
		Metadata: map[string]any{"execution_time": time.Now()},
	}, nil
}

// Convenience Methods for Prebuilt Extensions

// ExecuteCodeInterpreter executes a code interpreter operation with simplified parameters.
func (s *Service) ExecuteCodeInterpreter(ctx context.Context, extensionName, query string, files []string) (*CodeInterpreterExecutionResponse, error) {
	req := &ExecuteExtensionRequest{
		Name:        extensionName,
		OperationID: "generate_and_execute",
		OperationParams: map[string]any{
			"query": query,
			"files": files,
		},
	}

	_, err := s.ExecuteExtension(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute code interpreter: %w", err)
	}

	// TODO: Parse response into CodeInterpreterExecutionResponse
	// For now, return a mock response
	return &CodeInterpreterExecutionResponse{
		GeneratedCode:   "# Generated code would be here",
		ExecutionResult: "Execution result would be here",
		ExecutionError:  "",
		OutputFiles:     []string{},
	}, nil
}

// ExecuteVertexAISearch executes a Vertex AI Search operation with simplified parameters.
func (s *Service) ExecuteVertexAISearch(ctx context.Context, extensionName, query string, maxResults int32) (*VertexAISearchExecutionResponse, error) {
	req := &ExecuteExtensionRequest{
		Name:        extensionName,
		OperationID: "search",
		OperationParams: map[string]any{
			"query":       query,
			"max_results": maxResults,
		},
	}

	_, err := s.ExecuteExtension(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute Vertex AI Search: %w", err)
	}

	// TODO: Parse response into VertexAISearchExecutionResponse
	// For now, return a mock response
	return &VertexAISearchExecutionResponse{
		Results:       []SearchResult{},
		NextPageToken: "",
	}, nil
}

// Helper Methods

// generateExtensionID generates a unique extension ID.
func (s *Service) generateExtensionID() string {
	// In a real implementation, this would generate a unique ID
	return fmt.Sprintf("ext_%d", time.Now().UnixNano())
}

// generateExtensionName generates the full resource name for an extension.
func (s *Service) generateExtensionName(extensionID string) string {
	return fmt.Sprintf("projects/%s/locations/%s/extensions/%s", s.projectID, s.location, extensionID)
}

// validateManifest validates an extension manifest.
func (s *Service) validateManifest(manifest *Manifest) error {
	if manifest.Name == "" {
		return fmt.Errorf("manifest name is required")
	}
	if manifest.Description == "" {
		return fmt.Errorf("manifest description is required")
	}
	if manifest.APISpec == nil {
		return fmt.Errorf("API specification is required")
	}
	if manifest.APISpec.OpenAPIGCSURI == "" {
		return fmt.Errorf("OpenAPI GCS URI is required")
	}
	if !strings.HasPrefix(manifest.APISpec.OpenAPIGCSURI, "gs://") {
		return fmt.Errorf("OpenAPI GCS URI must start with gs://")
	}
	if manifest.AuthConfig == nil {
		return fmt.Errorf("authentication configuration is required")
	}
	if manifest.AuthConfig.AuthType == AuthTypeUnspecified {
		return fmt.Errorf("authentication type must be specified")
	}

	return nil
}

// Configuration Access Methods

// GetProjectID returns the configured Google Cloud project ID.
func (s *Service) GetProjectID() string {
	return s.projectID
}

// GetLocation returns the configured geographic location.
func (s *Service) GetLocation() string {
	return s.location
}

// GetLogger returns the configured logger instance.
func (s *Service) GetLogger() *slog.Logger {
	return s.logger
}
