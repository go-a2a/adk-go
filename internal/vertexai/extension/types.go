// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"encoding/json"
	"time"
)

// Extension represents a Vertex AI extension with its configuration and metadata.
//
// Extensions enable models to connect to external APIs for real-time data processing
// and performing real-world actions. Each extension is defined by its manifest which
// includes API specifications, authentication configuration, and runtime settings.
type Extension struct {
	// ID is the unique identifier for the extension.
	ID string `json:"id"`

	// Name is the resource name of the extension.
	// Format: projects/{project}/locations/{location}/extensions/{extension_id}
	Name string `json:"name"`

	// DisplayName is the human-readable name of the extension.
	DisplayName string `json:"display_name"`

	// Description provides details about the extension's purpose and functionality.
	Description string `json:"description"`

	// Manifest defines the extension's API specification, authentication, and configuration.
	Manifest *Manifest `json:"manifest"`

	// RuntimeConfig contains runtime-specific configuration for the extension.
	RuntimeConfig *RuntimeConfig `json:"runtime_config,omitempty"`

	// CreateTime is when the extension was created.
	CreateTime time.Time `json:"create_time"`

	// UpdateTime is when the extension was last updated.
	UpdateTime time.Time `json:"update_time"`

	// State indicates the current state of the extension.
	State ExtensionState `json:"state"`

	// Error contains error information if the extension is in an error state.
	Error *ExtensionError `json:"error,omitempty"`
}

// ExtensionState represents the current state of an extension.
type ExtensionState string

const (
	// ExtensionStateUnspecified indicates an unspecified state.
	ExtensionStateUnspecified ExtensionState = "EXTENSION_STATE_UNSPECIFIED"

	// ExtensionStateActive indicates the extension is active and ready for use.
	ExtensionStateActive ExtensionState = "ACTIVE"

	// ExtensionStateCreating indicates the extension is being created.
	ExtensionStateCreating ExtensionState = "CREATING"

	// ExtensionStateDeleting indicates the extension is being deleted.
	ExtensionStateDeleting ExtensionState = "DELETING"

	// ExtensionStateError indicates the extension is in an error state.
	ExtensionStateError ExtensionState = "ERROR"
)

// ExtensionError contains error information for extensions in error state.
type ExtensionError struct {
	// Code is the error code.
	Code int32 `json:"code"`

	// Message is the error message.
	Message string `json:"message"`

	// Details contains additional error details.
	Details []any `json:"details,omitempty"`
}

// Manifest defines the structure and configuration of an extension.
//
// The manifest specifies how the extension integrates with external APIs,
// including authentication methods, API specifications, and runtime behavior.
type Manifest struct {
	// Name is the name of the extension tool that will be used for function calling.
	Name string `json:"name"`

	// Description describes what the extension does.
	Description string `json:"description"`

	// APISpec defines the API specification for the extension.
	APISpec *APISpec `json:"api_spec"`

	// AuthConfig specifies the authentication configuration.
	AuthConfig *AuthConfig `json:"auth_config"`
}

// APISpec defines the API specification for an extension.
type APISpec struct {
	// OpenAPIGCSURI is the Google Cloud Storage URI pointing to the OpenAPI specification.
	// Format: gs://bucket-name/path/to/openapi.yaml
	OpenAPIGCSURI string `json:"open_api_gcs_uri"`
}

// AuthConfig specifies authentication configuration for extensions.
type AuthConfig struct {
	// AuthType specifies the type of authentication to use.
	AuthType AuthType `json:"auth_type"`

	// GoogleServiceAccountConfig contains configuration for Google Service Account authentication.
	GoogleServiceAccountConfig *GoogleServiceAccountConfig `json:"google_service_account_config,omitempty"`

	// HTTPBasicAuthConfig contains configuration for HTTP Basic authentication.
	HTTPBasicAuthConfig *HTTPBasicAuthConfig `json:"http_basic_auth_config,omitempty"`

	// OAuth2Config contains configuration for OAuth2 authentication.
	OAuth2Config *OAuth2Config `json:"oauth2_config,omitempty"`

	// APIKeyConfig contains configuration for API key authentication.
	APIKeyConfig *APIKeyConfig `json:"api_key_config,omitempty"`
}

// AuthType represents the authentication type for extensions.
type AuthType string

const (
	// AuthTypeUnspecified indicates unspecified authentication.
	AuthTypeUnspecified AuthType = "AUTH_TYPE_UNSPECIFIED"

	// AuthTypeGoogleServiceAccount uses Google Service Account authentication.
	AuthTypeGoogleServiceAccount AuthType = "GOOGLE_SERVICE_ACCOUNT_AUTH"

	// AuthTypeHTTPBasic uses HTTP Basic authentication.
	AuthTypeHTTPBasic AuthType = "HTTP_BASIC_AUTH"

	// AuthTypeOAuth2 uses OAuth2 authentication.
	AuthTypeOAuth2 AuthType = "OAUTH2_AUTH"

	// AuthTypeAPIKey uses API key authentication.
	AuthTypeAPIKey AuthType = "API_KEY_AUTH"
)

// GoogleServiceAccountConfig contains configuration for Google Service Account authentication.
type GoogleServiceAccountConfig struct {
	// ServiceAccount is the email address of the service account.
	// If empty, the default Compute Engine service account will be used.
	ServiceAccount string `json:"service_account,omitempty"`
}

// HTTPBasicAuthConfig contains configuration for HTTP Basic authentication.
type HTTPBasicAuthConfig struct {
	// Username is the username for HTTP Basic authentication.
	Username string `json:"username"`

	// PasswordSecretName is the name of the secret containing the password.
	PasswordSecretName string `json:"password_secret_name"`
}

// OAuth2Config contains configuration for OAuth2 authentication.
type OAuth2Config struct {
	// ClientID is the OAuth2 client ID.
	ClientID string `json:"client_id"`

	// ClientSecretName is the name of the secret containing the client secret.
	ClientSecretName string `json:"client_secret_name"`

	// TokenURI is the URI for token requests.
	TokenURI string `json:"token_uri"`

	// Scopes are the OAuth2 scopes to request.
	Scopes []string `json:"scopes,omitempty"`
}

// APIKeyConfig contains configuration for API key authentication.
type APIKeyConfig struct {
	// APIKeySecretName is the name of the secret containing the API key.
	APIKeySecretName string `json:"api_key_secret_name"`

	// APIKeyHeader is the header name for the API key.
	// Default is "X-API-Key" if not specified.
	APIKeyHeader string `json:"api_key_header,omitempty"`
}

// RuntimeConfig contains runtime-specific configuration for extensions.
type RuntimeConfig struct {
	// VertexAISearchRuntimeConfig contains configuration for Vertex AI Search extensions.
	VertexAISearchRuntimeConfig *VertexAISearchRuntimeConfig `json:"vertex_ai_search_runtime_config,omitempty"`

	// CodeInterpreterRuntimeConfig contains configuration for code interpreter extensions.
	CodeInterpreterRuntimeConfig *CodeInterpreterRuntimeConfig `json:"code_interpreter_runtime_config,omitempty"`

	// CustomRuntimeConfig contains custom runtime configuration.
	CustomRuntimeConfig map[string]any `json:"custom_runtime_config,omitempty"`
}

// VertexAISearchRuntimeConfig contains runtime configuration for Vertex AI Search extensions.
type VertexAISearchRuntimeConfig struct {
	// ServingConfigName is the name of the serving configuration.
	// Format: projects/{project}/locations/{location}/collections/{collection}/engines/{engine}/servingConfigs/{serving_config}
	ServingConfigName string `json:"serving_config_name"`

	// MaxResults is the maximum number of search results to return.
	MaxResults int32 `json:"max_results,omitempty"`
}

// CodeInterpreterRuntimeConfig contains runtime configuration for code interpreter extensions.
type CodeInterpreterRuntimeConfig struct {
	// TimeoutSeconds is the maximum execution time in seconds.
	TimeoutSeconds int32 `json:"timeout_seconds,omitempty"`

	// FileInputGCSBucket is the GCS bucket for input files.
	FileInputGCSBucket string `json:"file_input_gcs_bucket,omitempty"`

	// FileOutputGCSBucket is the GCS bucket for output files.
	FileOutputGCSBucket string `json:"file_output_gcs_bucket,omitempty"`
}

// Request and Response Types

// CreateExtensionRequest contains parameters for creating a new extension.
type CreateExtensionRequest struct {
	// DisplayName is the human-readable name for the extension.
	DisplayName string `json:"display_name"`

	// Description provides details about the extension's purpose.
	Description string `json:"description"`

	// Manifest defines the extension's configuration.
	Manifest *Manifest `json:"manifest"`

	// RuntimeConfig contains runtime-specific configuration.
	RuntimeConfig *RuntimeConfig `json:"runtime_config,omitempty"`
}

// ListExtensionsRequest contains parameters for listing extensions.
type ListExtensionsRequest struct {
	// PageSize is the maximum number of extensions to return in a single page.
	// If not specified or zero, the server will determine the page size.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the page token for pagination.
	PageToken string `json:"page_token,omitempty"`

	// Filter is an optional filter expression.
	Filter string `json:"filter,omitempty"`

	// OrderBy is an optional order by expression.
	OrderBy string `json:"order_by,omitempty"`
}

// ListExtensionsResponse contains the response from listing extensions.
type ListExtensionsResponse struct {
	// Extensions is the list of extensions.
	Extensions []*Extension `json:"extensions"`

	// NextPageToken is the token for the next page of results.
	NextPageToken string `json:"next_page_token"`
}

// GetExtensionRequest contains parameters for getting a specific extension.
type GetExtensionRequest struct {
	// Name is the resource name of the extension.
	// Format: projects/{project}/locations/{location}/extensions/{extension_id}
	Name string `json:"name"`
}

// DeleteExtensionRequest contains parameters for deleting an extension.
type DeleteExtensionRequest struct {
	// Name is the resource name of the extension to delete.
	// Format: projects/{project}/locations/{location}/extensions/{extension_id}
	Name string `json:"name"`
}

// ExecuteExtensionRequest contains parameters for executing an extension operation.
type ExecuteExtensionRequest struct {
	// Name is the resource name of the extension.
	// Format: projects/{project}/locations/{location}/extensions/{extension_id}
	Name string `json:"name"`

	// OperationID is the ID of the operation to execute.
	OperationID string `json:"operation_id"`

	// OperationParams are the parameters for the operation.
	OperationParams map[string]any `json:"operation_params"`

	// RequestID is an optional request ID for idempotency.
	RequestID string `json:"request_id,omitempty"`
}

// ExecuteExtensionResponse contains the result of executing an extension operation.
type ExecuteExtensionResponse struct {
	// Content is the response content from the extension.
	Content json.RawMessage `json:"content"`

	// Error contains error information if the execution failed.
	Error *ExecutionErrorResponse `json:"error,omitempty"`

	// Metadata contains additional metadata about the execution.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ExecutionErrorResponse represents an error response from extension execution.
type ExecutionErrorResponse struct {
	// Code is the error code.
	Code string `json:"code"`

	// Message is the error message.
	Message string `json:"message"`

	// Details contains additional error details.
	Details map[string]any `json:"details,omitempty"`
}

// Prebuilt Extension Types

// PrebuiltExtensionType represents the type of prebuilt extension.
type PrebuiltExtensionType string

const (
	// PrebuiltExtensionCodeInterpreter is the code interpreter extension.
	PrebuiltExtensionCodeInterpreter PrebuiltExtensionType = "code_interpreter"

	// PrebuiltExtensionVertexAISearch is the Vertex AI Search extension.
	PrebuiltExtensionVertexAISearch PrebuiltExtensionType = "vertex_ai_search"
)

// CodeInterpreterExecutionRequest contains parameters for code interpreter execution.
type CodeInterpreterExecutionRequest struct {
	// Query is the query or task for the code interpreter.
	Query string `json:"query"`

	// Files are optional input files for the execution.
	Files []string `json:"files,omitempty"`
}

// CodeInterpreterExecutionResponse contains the result of code interpreter execution.
type CodeInterpreterExecutionResponse struct {
	// GeneratedCode is the code generated by the interpreter.
	GeneratedCode string `json:"generated_code"`

	// ExecutionResult is the result of executing the code.
	ExecutionResult string `json:"execution_result"`

	// ExecutionError contains any execution errors.
	ExecutionError string `json:"execution_error"`

	// OutputFiles are any files generated during execution.
	OutputFiles []string `json:"output_files"`
}

// VertexAISearchExecutionRequest contains parameters for Vertex AI Search execution.
type VertexAISearchExecutionRequest struct {
	// Query is the search query.
	Query string `json:"query"`

	// MaxResults is the maximum number of results to return.
	MaxResults int32 `json:"max_results,omitempty"`
}

// VertexAISearchExecutionResponse contains the result of Vertex AI Search execution.
type VertexAISearchExecutionResponse struct {
	// Results are the search results.
	Results []SearchResult `json:"results"`

	// NextPageToken is the token for the next page of results.
	NextPageToken string `json:"next_page_token,omitempty"`
}

// SearchResult represents a single search result.
type SearchResult struct {
	// ID is the unique identifier for the result.
	ID string `json:"id"`

	// Title is the title of the result.
	Title string `json:"title"`

	// Content is the content of the result.
	Content string `json:"content"`

	// URI is the URI of the source document.
	URI string `json:"uri"`

	// Score is the relevance score.
	Score float64 `json:"score"`

	// Metadata contains additional metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
}
