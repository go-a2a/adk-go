// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/aiplatform/apiv1beta1/aiplatformpb"
	"cloud.google.com/go/storage"
	"github.com/go-json-experiment/json"
	yaml "go.yaml.in/yaml/v4"
	"google.golang.org/api/option"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/pkg/logging"
	"github.com/go-a2a/adk-go/types/aiconv"
)

var VertexExtensionHub = map[PrebuiltExtensionType]*aiplatformpb.ImportExtensionRequest{
	PrebuiltExtensionCodeInterpreter: {
		Extension: &aiplatformpb.Extension{
			DisplayName: "Code Interpreter",
			Description: "This extension generates and executes code in the specified language",
			Manifest: &aiplatformpb.ExtensionManifest{
				Name:        "code_interpreter_tool",
				Description: "Google Code Interpreter Extension",
				ApiSpec: &aiplatformpb.ExtensionManifest_ApiSpec{
					ApiSpec: &aiplatformpb.ExtensionManifest_ApiSpec_OpenApiGcsUri{
						OpenApiGcsUri: "gs://vertex-extension-public/code_interpreter.yaml",
					},
				},
				AuthConfig: NewGoogleServiceAccountConfig(""),
			},
		},
	},
	PrebuiltExtensionVertexAISearch: {
		Extension: &aiplatformpb.Extension{
			DisplayName: "Vertex AI Search",
			Description: "This extension generates and executes search queries",
			Manifest: &aiplatformpb.ExtensionManifest{
				Name:        "vertex_ai_search",
				Description: "Vertex AI Search Extension",
				ApiSpec: &aiplatformpb.ExtensionManifest_ApiSpec{
					ApiSpec: &aiplatformpb.ExtensionManifest_ApiSpec_OpenApiGcsUri{
						OpenApiGcsUri: "gs://vertex-extension-public/vertex_ai_search.yaml",
					},
				},
				AuthConfig: NewGoogleServiceAccountConfig(""),
			},
		},
	},
	PrebuiltExtensionWebpageBrowser: {
		Extension: &aiplatformpb.Extension{
			DisplayName: "Webpage Browser",
			Description: "This extension fetches the content of a webpage",
			Manifest: &aiplatformpb.ExtensionManifest{
				Name:        "webpage_browser",
				Description: "Vertex Webpage Browser Extension",
				ApiSpec: &aiplatformpb.ExtensionManifest_ApiSpec{
					ApiSpec: &aiplatformpb.ExtensionManifest_ApiSpec_OpenApiGcsUri{
						OpenApiGcsUri: "gs://vertex-extension-public/webpage_browser.yaml",
					},
				},
				AuthConfig: NewGoogleServiceAccountConfig(""),
			},
		},
	},
}

// Service provides access to Vertex AI Extensions functionality.
//
// The service manages extension lifecycles, executes operations, and provides
// access to prebuilt extensions from Google's extension hub.
type Service interface {
	// CreateExtension creates a new custom extension.
	CreateExtension(ctx context.Context, req *aiplatformpb.ImportExtensionRequest) (*Extension, error)

	// ResourceName returns the full qualified resource name for the extension.
	ResourceName() string

	// APISpec returns the (Open)API Spec of the extension.
	APISpec(ctx context.Context) map[string]any

	// OperationSchemas returns the (Open)API schemas for each operation of the extension.
	OperationSchemas(ctx context.Context) map[string]any

	// ExecuteExtension executes an operation of the extension with the specified params.
	ExecuteExtension(ctx context.Context, req *aiplatformpb.ExecuteExtensionRequest) (*aiplatformpb.ExecuteExtensionResponse, error)

	// QueryExtension queries an extension with the specified contents.
	QueryExtension(ctx context.Context, contents any) (*aiplatformpb.QueryExtensionResponse, error)

	// CreateFromHub creates a new Extension from the set of first party extensions.
	CreateFromHub(ctx context.Context, extensionType PrebuiltExtensionType, runtimeConfig *aiplatformpb.RuntimeConfig) (*Extension, error)

	// Close closes the Extension Execution service and releases any resources.
	Close() error
}

type service struct {
	// AI Platform clients
	extensionExecutionClient *aiplatform.ExtensionExecutionClient
	extensionRegistryClient  *aiplatform.ExtensionRegistryClient

	// Configuration
	projectID string
	location  string
	logger    *slog.Logger

	resourceName string

	// Cached API specs
	apiSpec          map[string]any
	operationSchemas map[string]any
	specMu           sync.RWMutex

	// Service state
	initialized bool
	mu          sync.RWMutex
}

var _ Service = (*service)(nil)

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
func NewService(ctx context.Context, projectID, location string, opts ...option.ClientOption) (*service, error) {
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

	service := &service{
		projectID: projectID,
		location:  location,
		logger:    logging.FromContext(ctx),
	}

	extensionExecutionClient, err := aiplatform.NewExtensionExecutionClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create AI Platform Extension Execution client: %w", err)
	}
	service.extensionExecutionClient = extensionExecutionClient

	extensionRegistryClient, err := aiplatform.NewExtensionRegistryClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create AI Platform Extension Execution client: %w", err)
	}
	service.extensionRegistryClient = extensionRegistryClient

	service.initialized = true

	service.logger.InfoContext(ctx, "Vertex AI Extension service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the Extension Execution service and releases any resources.
func (s *service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return nil
	}

	s.logger.Info("closing Vertex AI Extension services")

	// Close AI Platform clients
	if s.extensionExecutionClient != nil {
		if err := s.extensionExecutionClient.Close(); err != nil {
			s.logger.Error("close Extension Execution client", slog.Any("error", err))
			return fmt.Errorf("close Extension Execution client: %w", err)
		}
	}
	if s.extensionRegistryClient != nil {
		if err := s.extensionRegistryClient.Close(); err != nil {
			s.logger.Error("close Extension Registry client", slog.Any("error", err))
			return fmt.Errorf("close Extension Registry client: %w", err)
		}
	}

	s.initialized = false
	s.logger.Info("successfully closed the Vertex AI Extension services")

	return nil
}

// Extension Management Methods

// CreateExtension creates a new custom extension.
//
// This method allows you to register a custom extension with Vertex AI by providing
// a manifest that defines the API specification, authentication configuration,
// and runtime settings.
func (s *service) CreateExtension(ctx context.Context, req *aiplatformpb.ImportExtensionRequest) (*Extension, error) {
	operationFuture, err := s.extensionRegistryClient.ImportExtension(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to import extension config: %w", err)
	}

	createdExtension, err := operationFuture.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait long running operation: %w", err)
	}

	resourceName := createdExtension.GetName()

	// Clear cached specs when setting new resource name
	s.specMu.Lock()
	s.apiSpec = nil
	s.operationSchemas = nil
	s.specMu.Unlock()

	s.resourceName = resourceName

	s.logger.InfoContext(ctx, "Extension created successfully",
		slog.String("extension_name", resourceName),
	)

	ext := &Extension{
		Extension: createdExtension,
		State:     ExtensionStateActive,
	}

	return ext, nil
}

// ResourceName implements [Service].
func (s *service) ResourceName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.initialized {
		return ""
	}
	return s.resourceName
}

// APISpec implements [Service].
//
// APISpec returns the complete OpenAPI specification for the extension.
// The result is cached to avoid repeated parsing of the same specification.
// Returns an empty map if no extension is loaded or if parsing fails.
func (s *service) APISpec(ctx context.Context) map[string]any {
	s.specMu.RLock()
	if s.apiSpec != nil {
		defer s.specMu.RUnlock()
		return s.apiSpec
	}
	s.specMu.RUnlock()

	// Double-checked locking pattern
	s.specMu.Lock()
	defer s.specMu.Unlock()

	// Check again after acquiring write lock
	if s.apiSpec != nil {
		return s.apiSpec
	}

	// No extension available
	if s.resourceName == "" {
		s.logger.Debug("APISpec called but no extension resource available")
		s.apiSpec = make(map[string]any)
		return s.apiSpec
	}

	// Fetch and parse API spec
	spec, err := s.getExtensionSpec(ctx)
	if err != nil {
		s.logger.Error("failed to get extension API spec",
			slog.String("resource_name", s.resourceName),
			slog.Any("error", err),
		)
		s.apiSpec = make(map[string]any)
		return s.apiSpec
	}

	s.logger.Debug("successfully parsed extension API spec",
		slog.String("resource_name", s.resourceName),
		slog.Int("spec_keys", len(spec)),
	)

	s.apiSpec = spec
	return s.apiSpec
}

// OperationSchemas implements [Service].
//
// OperationSchemas returns a map of operation schemas extracted from the OpenAPI specification.
// Each key represents an operation ID or path+method, and the value contains the operation schema.
// The result is cached to avoid repeated parsing of the same specification.
// Returns an empty map if no extension is loaded or if parsing fails.
func (s *service) OperationSchemas(ctx context.Context) map[string]any {
	s.specMu.RLock()
	if s.operationSchemas != nil {
		defer s.specMu.RUnlock()
		return s.operationSchemas
	}
	s.specMu.RUnlock()

	// Double-checked locking pattern
	s.specMu.Lock()
	defer s.specMu.Unlock()

	// Check again after acquiring write lock
	if s.operationSchemas != nil {
		return s.operationSchemas
	}

	// No extension available
	if s.resourceName == "" {
		s.logger.Debug("OperationSchemas called but no extension resource available")
		s.operationSchemas = make(map[string]any)
		return s.operationSchemas
	}

	// Get the full API spec first
	apiSpec, err := s.getExtensionSpec(ctx)
	if err != nil {
		s.logger.Error("failed to get extension API spec for operation schemas",
			slog.String("resource_name", s.resourceName),
			slog.Any("error", err),
		)
		s.operationSchemas = make(map[string]any)
		return s.operationSchemas
	}

	// Extract operation schemas
	operationSchemas := s.extractOperationSchemas(apiSpec)

	s.logger.Debug("successfully extracted operation schemas",
		slog.String("resource_name", s.resourceName),
		slog.Int("operation_count", len(operationSchemas)),
	)

	s.operationSchemas = operationSchemas
	return s.operationSchemas
}

// Extension Execution Methods

// ExecuteExtension executes an operation on a specific extension.
//
// This method allows you to invoke extension operations with structured parameters
// and receive the execution results. The operation parameters are specific to
// each extension and operation type.
func (s *service) ExecuteExtension(ctx context.Context, req *aiplatformpb.ExecuteExtensionRequest) (*aiplatformpb.ExecuteExtensionResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if req.OperationId == "" {
		return nil, fmt.Errorf("operation_id is required")
	}

	s.logger.InfoContext(ctx, "executing extension operation",
		slog.String("name", req.Name),
		slog.String("operation_id", req.OperationId),
	)

	resp, err := s.extensionExecutionClient.ExecuteExtension(ctx, req)
	if err != nil {
		return nil, err
	}

	s.logger.InfoContext(ctx, "Extension operation executed successfully",
		slog.String("name", req.Name),
		slog.String("operation_id", req.OperationId),
	)

	return resp, nil
}

// ContentsType is a type constraint for the contents parameter in QueryExtension.
type ContentsType interface {
	[]*aiplatformpb.Content | []*genai.Content | []map[string]any | string | []string | *genai.Image | []*genai.Image | *genai.Part | []*genai.Part
}

// toContents converts different kinds of values to gapic_content_types.Content object.
func toContents[T ContentsType](value T) *aiplatformpb.Content {
	content := &aiplatformpb.Content{
		Role: model.RoleUser,
	}

	items := []any{}
	switch value := any(value).(type) {
	case *aiplatformpb.Content:
		return value
	case string:
		items = append(items, value)
	case []string:
		items = append(items, []any{value}...)
	case *genai.Image:
		items = append(items, value)
	case []*genai.Image:
		items = append(items, []any{value}...)
	case *genai.Part:
		items = append(items, value)
	case []*genai.Part:
		items = append(items, []any{value}...)
	}

	parts := []*aiplatformpb.Part{}
	for _, item := range items {
		switch item := item.(type) {
		case *aiplatformpb.Part:
			parts = append(parts, item)
		case *genai.Part:
			parts = append(parts, aiconv.ToAIPlatformPart(item))
		case string:
			parts = append(parts, &aiplatformpb.Part{
				Data: &aiplatformpb.Part_Text{
					Text: item,
				},
			})
		case *genai.Image:
			parts = append(parts, &aiplatformpb.Part{
				Data: &aiplatformpb.Part_InlineData{
					InlineData: &aiplatformpb.Blob{
						MimeType: item.MIMEType,
						Data:     item.ImageBytes,
					},
				},
			})
		case *genai.Content:
			panic(fmt.Errorf("a list of Content objects is not supported here: %v", item))
		default:
			panic(fmt.Errorf("unexpected item type: %T. only types that represent a single Content or a single Part are supported here", item))
		}
	}
	content.Parts = parts

	return content
}

// convertAnyToContents converts any supported content type to a list of aiplatformpb.Content objects.
func convertAnyToContents(contents any) []*aiplatformpb.Content {
	if contents == nil {
		return nil
	}

	switch v := contents.(type) {
	case []*aiplatformpb.Content:
		return v
	case []*genai.Content:
		return aiconv.ToAIPlatformContents(v)
	case *aiplatformpb.Content:
		return []*aiplatformpb.Content{v}
	case string:
		return []*aiplatformpb.Content{toContents(v)}
	case []string:
		return []*aiplatformpb.Content{toContents(v)}
	case *genai.Image:
		return []*aiplatformpb.Content{toContents(v)}
	case []*genai.Image:
		return []*aiplatformpb.Content{toContents(v)}
	case *genai.Part:
		return []*aiplatformpb.Content{toContents(v)}
	case []*genai.Part:
		return []*aiplatformpb.Content{toContents(v)}
	case []map[string]any:
		// Handle []map[string]any by treating it as a single content
		parts := []*aiplatformpb.Part{}
		for _, m := range v {
			// Convert map to a simple text representation for now
			// In a real implementation, you might want to handle this differently
			parts = append(parts, &aiplatformpb.Part{
				Data: &aiplatformpb.Part_Text{
					Text: fmt.Sprintf("%v", m),
				},
			})
		}
		return []*aiplatformpb.Content{
			{
				Role:  model.RoleUser,
				Parts: parts,
			},
		}
	default:
		panic(fmt.Errorf("unsupported content type: %T. supported types are: []*aiplatformpb.Content, []*genai.Content, string, []string, *genai.Image, []*genai.Image, *genai.Part, []*genai.Part, []map[string]any", contents))
	}
}

// QueryExtension Queries an extension with the specified contents.
func (s *service) QueryExtension(ctx context.Context, contents any) (*aiplatformpb.QueryExtensionResponse, error) {
	req := &aiplatformpb.QueryExtensionRequest{
		Name:     s.resourceName,
		Contents: convertAnyToContents(contents),
	}
	resp, err := s.extensionExecutionClient.QueryExtension(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("query extension: %w", err)
	}

	return resp, nil
}

// CreateFromHub creates an extension from Google's prebuilt extension hub.
//
// This method provides easy access to Google's curated extensions like
// code_interpreter and vertex_ai_search without requiring manual manifest creation.
func (s *service) CreateFromHub(ctx context.Context, extensionType PrebuiltExtensionType, runtimeConfig *aiplatformpb.RuntimeConfig) (*Extension, error) {
	s.logger.InfoContext(ctx, "Creating extension from hub", slog.String("extension_type", string(extensionType)))

	extensionInfo := VertexExtensionHub[extensionType]
	extensionInfo.Extension.RuntimeConfig = runtimeConfig

	switch extensionType {
	case "code_interpreter":
		if _, ok := extensionInfo.GetExtension().GetRuntimeConfig().GetGoogleFirstPartyExtensionConfig().(*aiplatformpb.RuntimeConfig_CodeInterpreterRuntimeConfig_); !ok {
			return nil, errors.New("runtime_config is required for code_interpreter extension")
		}
	case "vertex_ai_search":
		if extensionInfo.GetExtension().GetRuntimeConfig() == nil {
			return nil, errors.New("runtime_config is required for vertex_ai_search extension")
		}
		if _, ok := extensionInfo.GetExtension().GetRuntimeConfig().GetGoogleFirstPartyExtensionConfig().(*aiplatformpb.RuntimeConfig_VertexAiSearchRuntimeConfig); !ok {
			return nil, errors.New("runtime_config is required for vertex_ai_search extension")
		}
	case "webpage_browser":
		// nothing to do
	default:
		return nil, fmt.Errorf("unsupported 1P extension name: %s", extensionType)
	}

	extension, err := s.CreateExtension(ctx, extensionInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create extension from hub: %w", err)
	}

	s.logger.InfoContext(ctx, "Extension created from hub successfully", slog.String("extension_id", extension.GetID()))

	return extension, nil
}

// Helper methods for API spec parsing

// parseGCSContent fetches content from a GCS URI and parses it as YAML or JSON.
func (s *service) parseGCSContent(ctx context.Context, gcsURI string) (map[string]any, error) {
	// Parse GCS URI format: gs://bucket/path
	if !strings.HasPrefix(gcsURI, "gs://") {
		return nil, fmt.Errorf("invalid GCS URI format: %s", gcsURI)
	}

	uriPath := strings.TrimPrefix(gcsURI, "gs://")
	parts := strings.SplitN(uriPath, "/", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid GCS URI path: %s", gcsURI)
	}

	bucketName := parts[0]
	objectName := parts[1]

	// Create GCS client
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	// Fetch object content
	obj := client.Bucket(bucketName).Object(objectName)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read GCS object %s: %w", gcsURI, err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read content from %s: %w", gcsURI, err)
	}

	// Parse content based on file extension
	var spec map[string]any
	if strings.HasSuffix(objectName, ".yaml") || strings.HasSuffix(objectName, ".yml") {
		if err := yaml.Unmarshal(content, &spec); err != nil {
			return nil, fmt.Errorf("failed to parse YAML from %s: %w", gcsURI, err)
		}
	} else if strings.HasSuffix(objectName, ".json") {
		if err := json.Unmarshal(content, &spec); err != nil {
			return nil, fmt.Errorf("failed to parse JSON from %s: %w", gcsURI, err)
		}
	} else {
		// Try YAML first, then JSON
		if err := yaml.Unmarshal(content, &spec); err != nil {
			if jsonErr := json.Unmarshal(content, &spec); jsonErr != nil {
				return nil, fmt.Errorf("failed to parse content as YAML or JSON from %s: yaml error: %v, json error: %v", gcsURI, err, jsonErr)
			}
		}
	}

	return spec, nil
}

// extractOperationSchemas extracts operation schemas from a full OpenAPI specification.
func (s *service) extractOperationSchemas(apiSpec map[string]any) map[string]any {
	operationSchemas := make(map[string]any)

	// Extract paths and their operations
	if paths, ok := apiSpec["paths"].(map[string]any); ok {
		for path, pathItem := range paths {
			if pathItemMap, ok := pathItem.(map[string]any); ok {
				for method, operation := range pathItemMap {
					if operationMap, ok := operation.(map[string]any); ok {
						if operationID, exists := operationMap["operationId"]; exists {
							// Use operationId as key if available
							if operationIDStr, ok := operationID.(string); ok {
								operationSchemas[operationIDStr] = operationMap
							}
						} else {
							// Use path+method as key if no operationId
							key := fmt.Sprintf("%s_%s", strings.ToUpper(method), strings.ReplaceAll(path, "/", "_"))
							operationSchemas[key] = operationMap
						}
					}
				}
			}
		}
	}

	// Also include component schemas if available
	if components, ok := apiSpec["components"].(map[string]any); ok {
		if schemas, ok := components["schemas"].(map[string]any); ok {
			for schemaName, schema := range schemas {
				operationSchemas[fmt.Sprintf("schema_%s", schemaName)] = schema
			}
		}
	}

	return operationSchemas
}

// getExtensionSpec fetches and parses the API specification for the current extension.
func (s *service) getExtensionSpec(ctx context.Context) (map[string]any, error) {
	if s.resourceName == "" {
		return nil, fmt.Errorf("no extension created yet")
	}

	// Get extension details
	getReq := &aiplatformpb.GetExtensionRequest{
		Name: s.resourceName,
	}

	extension, err := s.extensionRegistryClient.GetExtension(ctx, getReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get extension %s: %w", s.resourceName, err)
	}

	manifest := extension.GetManifest()
	if manifest == nil {
		return nil, fmt.Errorf("extension %s has no manifest", s.resourceName)
	}

	apiSpec := manifest.GetApiSpec()
	if apiSpec == nil {
		return nil, fmt.Errorf("extension %s has no API spec", s.resourceName)
	}

	// Handle different API spec formats
	var spec map[string]any

	switch apiSpecType := apiSpec.GetApiSpec().(type) {
	case *aiplatformpb.ExtensionManifest_ApiSpec_OpenApiGcsUri:
		// Fetch from GCS
		spec, err = s.parseGCSContent(ctx, apiSpecType.OpenApiGcsUri)
		if err != nil {
			return nil, fmt.Errorf("failed to parse GCS API spec: %w", err)
		}

	case *aiplatformpb.ExtensionManifest_ApiSpec_OpenApiYaml:
		// Parse inline YAML
		if err := yaml.Unmarshal([]byte(apiSpecType.OpenApiYaml), &spec); err != nil {
			return nil, fmt.Errorf("failed to parse inline YAML API spec: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported API spec format")
	}

	return spec, nil
}

// Configuration Access Methods

// GetProjectID returns the configured Google Cloud project ID.
func (s *service) GetProjectID() string {
	return s.projectID
}

// GetLocation returns the configured geographic location.
func (s *service) GetLocation() string {
	return s.location
}

// GetLogger returns the configured logger instance.
func (s *service) GetLogger() *slog.Logger {
	return s.logger
}

// GetParent returns the resource name of the Location to import the Extension in.
func (s *service) GetParent() string {
	return "projects/" + s.projectID + "/locations/" + s.location
}
