// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestExtension_JSON(t *testing.T) {
	// Test JSON marshaling and unmarshaling of Extension
	ext := &Extension{
		ID:          "ext_123",
		Name:        "projects/test-project/locations/us-central1/extensions/ext_123",
		DisplayName: "Test Extension",
		Description: "A test extension",
		Manifest: &Manifest{
			Name:        "test_extension",
			Description: "Test extension manifest",
			APISpec: &APISpec{
				OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
			},
			AuthConfig: &AuthConfig{
				AuthType:                   AuthTypeGoogleServiceAccount,
				GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
			},
		},
		RuntimeConfig: &RuntimeConfig{
			CodeInterpreterRuntimeConfig: &CodeInterpreterRuntimeConfig{
				TimeoutSeconds: 300,
			},
		},
		CreateTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdateTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		State:      ExtensionStateActive,
	}

	// Marshal to JSON
	data, err := json.Marshal(ext)
	if err != nil {
		t.Fatalf("Failed to marshal extension to JSON: %v", err)
	}

	// Unmarshal from JSON
	var unmarshaled Extension
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal extension from JSON: %v", err)
	}

	// Compare (note: we need to handle time comparison carefully)
	if diff := cmp.Diff(ext, &unmarshaled); diff != "" {
		t.Errorf("Extension JSON roundtrip mismatch (-want +got):\n%s", diff)
	}
}

func TestManifest_Validation(t *testing.T) {
	tests := []struct {
		name     string
		manifest *Manifest
		isValid  bool
	}{
		{
			name: "valid manifest",
			manifest: &Manifest{
				Name:        "test_extension",
				Description: "Test extension",
				APISpec: &APISpec{
					OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
				},
				AuthConfig: &AuthConfig{
					AuthType:                   AuthTypeGoogleServiceAccount,
					GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
				},
			},
			isValid: true,
		},
		{
			name: "manifest with OAuth2 auth",
			manifest: &Manifest{
				Name:        "oauth_extension",
				Description: "Extension with OAuth2",
				APISpec: &APISpec{
					OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
				},
				AuthConfig: &AuthConfig{
					AuthType: AuthTypeOAuth2,
					OAuth2Config: &OAuth2Config{
						ClientID:         "client123",
						ClientSecretName: "secret-name",
						TokenURI:         "https://oauth.example.com/token",
						Scopes:           []string{"read", "write"},
					},
				},
			},
			isValid: true,
		},
		{
			name: "manifest with API key auth",
			manifest: &Manifest{
				Name:        "apikey_extension",
				Description: "Extension with API key",
				APISpec: &APISpec{
					OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
				},
				AuthConfig: &AuthConfig{
					AuthType: AuthTypeAPIKey,
					APIKeyConfig: &APIKeyConfig{
						APIKeySecretName: "api-key-secret",
						APIKeyHeader:     "X-API-Key",
					},
				},
			},
			isValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshaling
			data, err := json.Marshal(tt.manifest)
			if err != nil {
				t.Errorf("Failed to marshal manifest: %v", err)
				return
			}

			// Test JSON unmarshaling
			var unmarshaled Manifest
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Errorf("Failed to unmarshal manifest: %v", err)
				return
			}

			// Compare
			if diff := cmp.Diff(tt.manifest, &unmarshaled); diff != "" {
				t.Errorf("Manifest JSON roundtrip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRuntimeConfig_JSON(t *testing.T) {
	tests := []struct {
		name   string
		config *RuntimeConfig
	}{
		{
			name: "code interpreter config",
			config: &RuntimeConfig{
				CodeInterpreterRuntimeConfig: &CodeInterpreterRuntimeConfig{
					TimeoutSeconds:      300,
					FileInputGCSBucket:  "input-bucket",
					FileOutputGCSBucket: "output-bucket",
				},
			},
		},
		{
			name: "vertex ai search config",
			config: &RuntimeConfig{
				VertexAISearchRuntimeConfig: &VertexAISearchRuntimeConfig{
					ServingConfigName: "projects/test/locations/us-central1/collections/default/engines/search/servingConfigs/default",
					MaxResults:        10,
				},
			},
		},
		{
			name: "custom config",
			config: &RuntimeConfig{
				CustomRuntimeConfig: map[string]any{
					"custom_param": "value",
					"timeout":      float64(300), // Use float64 to match JSON unmarshaling behavior
					"enabled":      true,
				},
			},
		},
		{
			name: "mixed config",
			config: &RuntimeConfig{
				CodeInterpreterRuntimeConfig: &CodeInterpreterRuntimeConfig{
					TimeoutSeconds: 300,
				},
				CustomRuntimeConfig: map[string]any{
					"debug": true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal to JSON
			data, err := json.Marshal(tt.config)
			if err != nil {
				t.Fatalf("Failed to marshal runtime config to JSON: %v", err)
			}

			// Unmarshal from JSON
			var unmarshaled RuntimeConfig
			err = json.Unmarshal(data, &unmarshaled)
			if err != nil {
				t.Fatalf("Failed to unmarshal runtime config from JSON: %v", err)
			}

			// Compare
			if diff := cmp.Diff(tt.config, &unmarshaled); diff != "" {
				t.Errorf("RuntimeConfig JSON roundtrip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRequestResponse_JSON(t *testing.T) {
	// Test CreateExtensionRequest
	createReq := &CreateExtensionRequest{
		DisplayName: "Test Extension",
		Description: "A test extension",
		Manifest: &Manifest{
			Name:        "test_extension",
			Description: "Test extension",
			APISpec: &APISpec{
				OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
			},
			AuthConfig: &AuthConfig{
				AuthType:                   AuthTypeGoogleServiceAccount,
				GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
			},
		},
	}

	data, err := json.Marshal(createReq)
	if err != nil {
		t.Fatalf("Failed to marshal CreateExtensionRequest: %v", err)
	}

	var unmarshaledCreateReq CreateExtensionRequest
	err = json.Unmarshal(data, &unmarshaledCreateReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal CreateExtensionRequest: %v", err)
	}

	if diff := cmp.Diff(createReq, &unmarshaledCreateReq); diff != "" {
		t.Errorf("CreateExtensionRequest JSON roundtrip mismatch (-want +got):\n%s", diff)
	}

	// Test ListExtensionsRequest
	listReq := &ListExtensionsRequest{
		PageSize:  10,
		PageToken: "token123",
		Filter:    "state=ACTIVE",
		OrderBy:   "create_time desc",
	}

	data, err = json.Marshal(listReq)
	if err != nil {
		t.Fatalf("Failed to marshal ListExtensionsRequest: %v", err)
	}

	var unmarshaledListReq ListExtensionsRequest
	err = json.Unmarshal(data, &unmarshaledListReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal ListExtensionsRequest: %v", err)
	}

	if diff := cmp.Diff(listReq, &unmarshaledListReq); diff != "" {
		t.Errorf("ListExtensionsRequest JSON roundtrip mismatch (-want +got):\n%s", diff)
	}

	// Test ExecuteExtensionRequest
	executeReq := &ExecuteExtensionRequest{
		Name:        "projects/test-project/locations/us-central1/extensions/ext_123",
		OperationID: "generate_and_execute",
		OperationParams: map[string]any{
			"query": "find max value",
			"files": []any{"file1.txt", "file2.csv"}, // Use []any to match JSON unmarshaling behavior
		},
		RequestID: "req_123",
	}

	data, err = json.Marshal(executeReq)
	if err != nil {
		t.Fatalf("Failed to marshal ExecuteExtensionRequest: %v", err)
	}

	var unmarshaledExecuteReq ExecuteExtensionRequest
	err = json.Unmarshal(data, &unmarshaledExecuteReq)
	if err != nil {
		t.Fatalf("Failed to unmarshal ExecuteExtensionRequest: %v", err)
	}

	if diff := cmp.Diff(executeReq, &unmarshaledExecuteReq); diff != "" {
		t.Errorf("ExecuteExtensionRequest JSON roundtrip mismatch (-want +got):\n%s", diff)
	}
}

func TestPrebuiltExtensionTypes(t *testing.T) {
	tests := []struct {
		name          string
		extensionType PrebuiltExtensionType
		expected      string
	}{
		{
			name:          "code interpreter",
			extensionType: PrebuiltExtensionCodeInterpreter,
			expected:      "code_interpreter",
		},
		{
			name:          "vertex ai search",
			extensionType: PrebuiltExtensionVertexAISearch,
			expected:      "vertex_ai_search",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.extensionType) != tt.expected {
				t.Errorf("PrebuiltExtensionType %v = %v, want %v", tt.name, string(tt.extensionType), tt.expected)
			}
		})
	}
}

func TestExtensionState(t *testing.T) {
	tests := []struct {
		name     string
		state    ExtensionState
		expected string
	}{
		{
			name:     "unspecified",
			state:    ExtensionStateUnspecified,
			expected: "EXTENSION_STATE_UNSPECIFIED",
		},
		{
			name:     "active",
			state:    ExtensionStateActive,
			expected: "ACTIVE",
		},
		{
			name:     "creating",
			state:    ExtensionStateCreating,
			expected: "CREATING",
		},
		{
			name:     "deleting",
			state:    ExtensionStateDeleting,
			expected: "DELETING",
		},
		{
			name:     "error",
			state:    ExtensionStateError,
			expected: "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.state) != tt.expected {
				t.Errorf("ExtensionState %v = %v, want %v", tt.name, string(tt.state), tt.expected)
			}
		})
	}
}

func TestAuthType(t *testing.T) {
	tests := []struct {
		name     string
		authType AuthType
		expected string
	}{
		{
			name:     "unspecified",
			authType: AuthTypeUnspecified,
			expected: "AUTH_TYPE_UNSPECIFIED",
		},
		{
			name:     "google service account",
			authType: AuthTypeGoogleServiceAccount,
			expected: "GOOGLE_SERVICE_ACCOUNT_AUTH",
		},
		{
			name:     "http basic",
			authType: AuthTypeHTTPBasic,
			expected: "HTTP_BASIC_AUTH",
		},
		{
			name:     "oauth2",
			authType: AuthTypeOAuth2,
			expected: "OAUTH2_AUTH",
		},
		{
			name:     "api key",
			authType: AuthTypeAPIKey,
			expected: "API_KEY_AUTH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.authType) != tt.expected {
				t.Errorf("AuthType %v = %v, want %v", tt.name, string(tt.authType), tt.expected)
			}
		})
	}
}

func TestCodeInterpreterExecutionResponse_JSON(t *testing.T) {
	response := &CodeInterpreterExecutionResponse{
		GeneratedCode:   "import pandas as pd\ndf = pd.DataFrame([1,2,3,4,5])\nprint(df.max())",
		ExecutionResult: "5",
		ExecutionError:  "",
		OutputFiles:     []string{"output.csv", "chart.png"},
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal CodeInterpreterExecutionResponse: %v", err)
	}

	var unmarshaled CodeInterpreterExecutionResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal CodeInterpreterExecutionResponse: %v", err)
	}

	if diff := cmp.Diff(response, &unmarshaled); diff != "" {
		t.Errorf("CodeInterpreterExecutionResponse JSON roundtrip mismatch (-want +got):\n%s", diff)
	}
}

func TestVertexAISearchExecutionResponse_JSON(t *testing.T) {
	response := &VertexAISearchExecutionResponse{
		Results: []SearchResult{
			{
				ID:      "result1",
				Title:   "Test Document 1",
				Content: "This is the content of the first document",
				URI:     "gs://bucket/doc1.pdf",
				Score:   0.95,
				Metadata: map[string]any{
					"author": "John Doe",
					"year":   float64(2024), // Use float64 to match JSON unmarshaling behavior
				},
			},
			{
				ID:      "result2",
				Title:   "Test Document 2",
				Content: "This is the content of the second document",
				URI:     "gs://bucket/doc2.pdf",
				Score:   0.87,
				Metadata: map[string]any{
					"author": "Jane Smith",
					"year":   float64(2023), // Use float64 to match JSON unmarshaling behavior
				},
			},
		},
		NextPageToken: "next_page_123",
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal VertexAISearchExecutionResponse: %v", err)
	}

	var unmarshaled VertexAISearchExecutionResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal VertexAISearchExecutionResponse: %v", err)
	}

	if diff := cmp.Diff(response, &unmarshaled); diff != "" {
		t.Errorf("VertexAISearchExecutionResponse JSON roundtrip mismatch (-want +got):\n%s", diff)
	}
}
