// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name        string
		projectID   string
		location    string
		wantErr     bool
		expectedErr string
	}{
		{
			name:      "valid us-central1",
			projectID: "test-project",
			location:  "us-central1",
			wantErr:   false,
		},
		{
			name:        "empty project ID",
			projectID:   "",
			location:    "us-central1",
			wantErr:     true,
			expectedErr: "projectID is required",
		},
		{
			name:        "empty location",
			projectID:   "test-project",
			location:    "",
			wantErr:     true,
			expectedErr: "location is required",
		},
		{
			name:        "invalid region",
			projectID:   "test-project",
			location:    "us-east1",
			wantErr:     true,
			expectedErr: "Extensions API is not supported in region 'us-east1'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			service, err := NewService(ctx, tt.projectID, tt.location)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewService() expected error but got none")
					return
				}
				if tt.expectedErr != "" && !strings.Contains(err.Error(), tt.expectedErr) {
					t.Errorf("NewService() error = %v, want error containing %v", err, tt.expectedErr)
				}
				return
			}

			if err != nil {
				t.Errorf("NewService() unexpected error = %v", err)
				return
			}

			if service == nil {
				t.Errorf("NewService() returned nil service")
				return
			}

			// Verify service configuration
			if service.GetProjectID() != tt.projectID {
				t.Errorf("NewService() projectID = %v, want %v", service.GetProjectID(), tt.projectID)
			}
			if service.GetLocation() != tt.location {
				t.Errorf("NewService() location = %v, want %v", service.GetLocation(), tt.location)
			}

			// Clean up
			service.Close()
		})
	}
}

func TestService_CreateExtension(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	tests := []struct {
		name    string
		req     *CreateExtensionRequest
		wantErr bool
	}{
		{
			name: "valid extension",
			req: &CreateExtensionRequest{
				DisplayName: "Test Extension",
				Description: "A test extension",
				Manifest: &Manifest{
					Name:        "test_extension",
					Description: "Test extension for validation",
					APISpec: &APISpec{
						OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
					},
					AuthConfig: &AuthConfig{
						AuthType:                   AuthTypeGoogleServiceAccount,
						GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "empty display name",
			req: &CreateExtensionRequest{
				DisplayName: "",
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
			},
			wantErr: true,
		},
		{
			name: "nil manifest",
			req: &CreateExtensionRequest{
				DisplayName: "Test Extension",
				Manifest:    nil,
			},
			wantErr: true,
		},
		{
			name: "invalid manifest - missing name",
			req: &CreateExtensionRequest{
				DisplayName: "Test Extension",
				Manifest: &Manifest{
					Name:        "",
					Description: "Test extension",
					APISpec: &APISpec{
						OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
					},
					AuthConfig: &AuthConfig{
						AuthType:                   AuthTypeGoogleServiceAccount,
						GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid manifest - invalid GCS URI",
			req: &CreateExtensionRequest{
				DisplayName: "Test Extension",
				Manifest: &Manifest{
					Name:        "test_extension",
					Description: "Test extension",
					APISpec: &APISpec{
						OpenAPIGCSURI: "invalid-uri",
					},
					AuthConfig: &AuthConfig{
						AuthType:                   AuthTypeGoogleServiceAccount,
						GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := service.CreateExtension(ctx, tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CreateExtension() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("CreateExtension() unexpected error = %v", err)
				return
			}

			if ext == nil {
				t.Errorf("CreateExtension() returned nil extension")
				return
			}

			// Verify extension properties
			if ext.DisplayName != tt.req.DisplayName {
				t.Errorf("CreateExtension() displayName = %v, want %v", ext.DisplayName, tt.req.DisplayName)
			}
			if ext.Description != tt.req.Description {
				t.Errorf("CreateExtension() description = %v, want %v", ext.Description, tt.req.Description)
			}
			if ext.State != ExtensionStateActive {
				t.Errorf("CreateExtension() state = %v, want %v", ext.State, ExtensionStateActive)
			}
		})
	}
}

func TestService_CreateFromHub(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	tests := []struct {
		name          string
		extensionType PrebuiltExtensionType
		wantErr       bool
	}{
		{
			name:          "code interpreter",
			extensionType: PrebuiltExtensionCodeInterpreter,
			wantErr:       false,
		},
		{
			name:          "vertex ai search",
			extensionType: PrebuiltExtensionVertexAISearch,
			wantErr:       false,
		},
		{
			name:          "invalid extension type",
			extensionType: "invalid_type",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := service.CreateFromHub(ctx, tt.extensionType)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CreateFromHub() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("CreateFromHub() unexpected error = %v", err)
				return
			}

			if ext == nil {
				t.Errorf("CreateFromHub() returned nil extension")
				return
			}

			// Verify extension was created with expected properties
			expectedDisplayName := service.getPrebuiltDisplayName(tt.extensionType)
			if ext.DisplayName != expectedDisplayName {
				t.Errorf("CreateFromHub() displayName = %v, want %v", ext.DisplayName, expectedDisplayName)
			}
		})
	}
}

func TestService_ExecuteExtension(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	tests := []struct {
		name    string
		req     *ExecuteExtensionRequest
		wantErr bool
	}{
		{
			name: "valid execution",
			req: &ExecuteExtensionRequest{
				Name:        "projects/test-project/locations/us-central1/extensions/ext_123",
				OperationID: "test_operation",
				OperationParams: map[string]any{
					"param1": "value1",
					"param2": 42,
				},
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
		},
		{
			name: "empty name",
			req: &ExecuteExtensionRequest{
				Name:        "",
				OperationID: "test_operation",
			},
			wantErr: true,
		},
		{
			name: "empty operation ID",
			req: &ExecuteExtensionRequest{
				Name:        "projects/test-project/locations/us-central1/extensions/ext_123",
				OperationID: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := service.ExecuteExtension(ctx, tt.req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExecuteExtension() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ExecuteExtension() unexpected error = %v", err)
				return
			}

			if resp == nil {
				t.Errorf("ExecuteExtension() returned nil response")
				return
			}

			// Verify response has content
			if len(resp.Content) == 0 {
				t.Errorf("ExecuteExtension() response content is empty")
			}
		})
	}
}

func TestService_ListExtensions(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with nil request (should use defaults)
	resp, err := service.ListExtensions(ctx, nil)
	if err != nil {
		t.Errorf("ListExtensions() unexpected error = %v", err)
		return
	}

	if resp == nil {
		t.Errorf("ListExtensions() returned nil response")
		return
	}

	// Verify response structure
	if resp.Extensions == nil {
		t.Errorf("ListExtensions() extensions list is nil")
	}

	// Test with custom request
	req := &ListExtensionsRequest{
		PageSize:  10,
		PageToken: "test-token",
		Filter:    "state=ACTIVE",
	}

	resp, err = service.ListExtensions(ctx, req)
	if err != nil {
		t.Errorf("ListExtensions() with custom request unexpected error = %v", err)
		return
	}

	if resp == nil {
		t.Errorf("ListExtensions() with custom request returned nil response")
	}
}

func TestValidateManifest(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name     string
		manifest *Manifest
		wantErr  bool
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
			wantErr: false,
		},
		{
			name: "missing name",
			manifest: &Manifest{
				Name:        "",
				Description: "Test extension",
				APISpec: &APISpec{
					OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
				},
				AuthConfig: &AuthConfig{
					AuthType:                   AuthTypeGoogleServiceAccount,
					GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
				},
			},
			wantErr: true,
		},
		{
			name: "missing description",
			manifest: &Manifest{
				Name:        "test_extension",
				Description: "",
				APISpec: &APISpec{
					OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
				},
				AuthConfig: &AuthConfig{
					AuthType:                   AuthTypeGoogleServiceAccount,
					GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
				},
			},
			wantErr: true,
		},
		{
			name: "missing API spec",
			manifest: &Manifest{
				Name:        "test_extension",
				Description: "Test extension",
				APISpec:     nil,
				AuthConfig: &AuthConfig{
					AuthType:                   AuthTypeGoogleServiceAccount,
					GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid GCS URI",
			manifest: &Manifest{
				Name:        "test_extension",
				Description: "Test extension",
				APISpec: &APISpec{
					OpenAPIGCSURI: "invalid-uri",
				},
				AuthConfig: &AuthConfig{
					AuthType:                   AuthTypeGoogleServiceAccount,
					GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
				},
			},
			wantErr: true,
		},
		{
			name: "missing auth config",
			manifest: &Manifest{
				Name:        "test_extension",
				Description: "Test extension",
				APISpec: &APISpec{
					OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
				},
				AuthConfig: nil,
			},
			wantErr: true,
		},
		{
			name: "unspecified auth type",
			manifest: &Manifest{
				Name:        "test_extension",
				Description: "Test extension",
				APISpec: &APISpec{
					OpenAPIGCSURI: "gs://test-bucket/openapi.yaml",
				},
				AuthConfig: &AuthConfig{
					AuthType: AuthTypeUnspecified,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateManifest(tt.manifest)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateManifest() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("validateManifest() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestGetPrebuiltExtensionConfig(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name          string
		extensionType PrebuiltExtensionType
		wantErr       bool
	}{
		{
			name:          "code interpreter",
			extensionType: PrebuiltExtensionCodeInterpreter,
			wantErr:       false,
		},
		{
			name:          "vertex ai search",
			extensionType: PrebuiltExtensionVertexAISearch,
			wantErr:       false,
		},
		{
			name:          "unknown type",
			extensionType: "unknown_type",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, runtimeConfig, err := service.getPrebuiltExtensionConfig(tt.extensionType)

			if tt.wantErr {
				if err == nil {
					t.Errorf("getPrebuiltExtensionConfig() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("getPrebuiltExtensionConfig() unexpected error = %v", err)
				return
			}

			if manifest == nil {
				t.Errorf("getPrebuiltExtensionConfig() manifest is nil")
				return
			}

			if runtimeConfig == nil {
				t.Errorf("getPrebuiltExtensionConfig() runtimeConfig is nil")
				return
			}

			// Verify manifest structure
			if manifest.Name == "" {
				t.Errorf("getPrebuiltExtensionConfig() manifest name is empty")
			}
			if manifest.Description == "" {
				t.Errorf("getPrebuiltExtensionConfig() manifest description is empty")
			}
			if manifest.APISpec == nil || manifest.APISpec.OpenAPIGCSURI == "" {
				t.Errorf("getPrebuiltExtensionConfig() manifest API spec is invalid")
			}
			if manifest.AuthConfig == nil || manifest.AuthConfig.AuthType != AuthTypeGoogleServiceAccount {
				t.Errorf("getPrebuiltExtensionConfig() manifest auth config is invalid")
			}
		})
	}
}

func TestGenerateExtensionName(t *testing.T) {
	service := &Service{
		projectID: "test-project",
		location:  "us-central1",
	}

	extensionID := "ext_123"
	expectedName := "projects/test-project/locations/us-central1/extensions/ext_123"

	actualName := service.generateExtensionName(extensionID)

	if actualName != expectedName {
		t.Errorf("generateExtensionName() = %v, want %v", actualName, expectedName)
	}
}

func TestGetSupportedPrebuiltExtensions(t *testing.T) {
	service := &Service{}

	extensions := service.GetSupportedPrebuiltExtensions()

	if len(extensions) == 0 {
		t.Errorf("GetSupportedPrebuiltExtensions() returned empty list")
		return
	}

	expected := []PrebuiltExtensionType{
		PrebuiltExtensionCodeInterpreter,
		PrebuiltExtensionVertexAISearch,
	}

	if diff := cmp.Diff(expected, extensions); diff != "" {
		t.Errorf("GetSupportedPrebuiltExtensions() mismatch (-want +got):\n%s", diff)
	}
}

func TestValidatePrebuiltExtensionType(t *testing.T) {
	service := &Service{}

	// Test valid types
	validTypes := []PrebuiltExtensionType{
		PrebuiltExtensionCodeInterpreter,
		PrebuiltExtensionVertexAISearch,
	}

	for _, extensionType := range validTypes {
		err := service.ValidatePrebuiltExtensionType(extensionType)
		if err != nil {
			t.Errorf("ValidatePrebuiltExtensionType(%v) unexpected error = %v", extensionType, err)
		}
	}

	// Test invalid type
	err := service.ValidatePrebuiltExtensionType("invalid_type")
	if err == nil {
		t.Errorf("ValidatePrebuiltExtensionType() expected error for invalid type but got none")
	}
}
