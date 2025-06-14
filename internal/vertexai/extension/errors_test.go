// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"errors"
	"testing"
)

func TestRegionNotSupportedError(t *testing.T) {
	err := &RegionNotSupportedError{
		RequestedRegion:  "us-east1",
		SupportedRegions: []string{"us-central1"},
	}

	expected := "Extensions API is not supported in region 'us-east1'. Supported regions: us-central1"
	if err.Error() != expected {
		t.Errorf("RegionNotSupportedError.Error() = %v, want %v", err.Error(), expected)
	}

	// Test with multiple supported regions
	err = &RegionNotSupportedError{
		RequestedRegion:  "us-east1",
		SupportedRegions: []string{"us-central1", "europe-west1", "asia-east1"},
	}

	expected = "Extensions API is not supported in region 'us-east1'. Supported regions: us-central1, europe-west1, asia-east1"
	if err.Error() != expected {
		t.Errorf("RegionNotSupportedError.Error() with multiple regions = %v, want %v", err.Error(), expected)
	}
}

func TestExtensionNotFoundError(t *testing.T) {
	extensionName := "projects/test-project/locations/us-central1/extensions/ext_123"
	err := &ExtensionNotFoundError{
		Name: extensionName,
	}

	expected := "extension not found: " + extensionName
	if err.Error() != expected {
		t.Errorf("ExtensionNotFoundError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestManifestValidationError(t *testing.T) {
	err := &ManifestValidationError{
		Message: "manifest name is required",
		Details: map[string]any{
			"field": "name",
			"value": "",
		},
	}

	expected := "manifest validation failed: manifest name is required"
	if err.Error() != expected {
		t.Errorf("ManifestValidationError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestExecutionError(t *testing.T) {
	err := &ExecutionError{
		ExtensionName: "projects/test-project/locations/us-central1/extensions/ext_123",
		OperationID:   "generate_and_execute",
		Message:       "timeout exceeded",
		Details: map[string]any{
			"timeout_seconds": 300,
			"actual_time":     450,
		},
	}

	expected := "extension execution failed for projects/test-project/locations/us-central1/extensions/ext_123.generate_and_execute: timeout exceeded"
	if err.Error() != expected {
		t.Errorf("ExecutionError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestPrebuiltExtensionError(t *testing.T) {
	err := &PrebuiltExtensionError{
		ExtensionType: PrebuiltExtensionCodeInterpreter,
		Message:       "serving_config_name is required for Vertex AI Search extension",
	}

	expected := "prebuilt extension error for code_interpreter: serving_config_name is required for Vertex AI Search extension"
	if err.Error() != expected {
		t.Errorf("PrebuiltExtensionError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestAuthenticationError(t *testing.T) {
	err := &AuthenticationError{
		Message: "failed to obtain access token",
		Details: map[string]any{
			"scope": "https://www.googleapis.com/auth/cloud-platform",
			"code":  "invalid_grant",
		},
	}

	expected := "authentication error: failed to obtain access token"
	if err.Error() != expected {
		t.Errorf("AuthenticationError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestAPIError(t *testing.T) {
	err := &APIError{
		StatusCode: 404,
		Message:    "extension not found",
		Details: map[string]any{
			"resource": "projects/test-project/locations/us-central1/extensions/ext_123",
		},
	}

	expected := "API error (status 404): extension not found"
	if err.Error() != expected {
		t.Errorf("APIError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestConfigurationError(t *testing.T) {
	err := &ConfigurationError{
		Parameter: "location",
		Message:   "must be us-central1",
	}

	expected := "configuration error for location: must be us-central1"
	if err.Error() != expected {
		t.Errorf("ConfigurationError.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestErrorTypes_Unwrapping(t *testing.T) {
	// Test that our custom errors can be identified using errors.As()
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "RegionNotSupportedError",
			err:  &RegionNotSupportedError{RequestedRegion: "us-east1", SupportedRegions: []string{"us-central1"}},
		},
		{
			name: "ExtensionNotFoundError",
			err:  &ExtensionNotFoundError{Name: "test"},
		},
		{
			name: "ManifestValidationError",
			err:  &ManifestValidationError{Message: "test"},
		},
		{
			name: "ExecutionError",
			err:  &ExecutionError{ExtensionName: "test", OperationID: "test", Message: "test"},
		},
		{
			name: "PrebuiltExtensionError",
			err:  &PrebuiltExtensionError{ExtensionType: PrebuiltExtensionCodeInterpreter, Message: "test"},
		},
		{
			name: "AuthenticationError",
			err:  &AuthenticationError{Message: "test"},
		},
		{
			name: "APIError",
			err:  &APIError{StatusCode: 500, Message: "test"},
		},
		{
			name: "ConfigurationError",
			err:  &ConfigurationError{Parameter: "test", Message: "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.err.(type) {
			case *RegionNotSupportedError:
				var target *RegionNotSupportedError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			case *ExtensionNotFoundError:
				var target *ExtensionNotFoundError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			case *ManifestValidationError:
				var target *ManifestValidationError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			case *ExecutionError:
				var target *ExecutionError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			case *PrebuiltExtensionError:
				var target *PrebuiltExtensionError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			case *AuthenticationError:
				var target *AuthenticationError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			case *APIError:
				var target *APIError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			case *ConfigurationError:
				var target *ConfigurationError
				if !errors.As(tt.err, &target) {
					t.Errorf("errors.As() failed for %v", tt.name)
				}
			}
		})
	}
}

func TestErrorFields_Access(t *testing.T) {
	// Test that error fields are accessible for programmatic handling

	// RegionNotSupportedError
	regionErr := &RegionNotSupportedError{
		RequestedRegion:  "us-east1",
		SupportedRegions: []string{"us-central1", "europe-west1"},
	}
	if regionErr.RequestedRegion != "us-east1" {
		t.Errorf("RegionNotSupportedError.RequestedRegion = %v, want us-east1", regionErr.RequestedRegion)
	}
	if len(regionErr.SupportedRegions) != 2 {
		t.Errorf("RegionNotSupportedError.SupportedRegions length = %v, want 2", len(regionErr.SupportedRegions))
	}

	// ExtensionNotFoundError
	notFoundErr := &ExtensionNotFoundError{Name: "test-extension"}
	if notFoundErr.Name != "test-extension" {
		t.Errorf("ExtensionNotFoundError.Name = %v, want test-extension", notFoundErr.Name)
	}

	// ManifestValidationError
	manifestErr := &ManifestValidationError{
		Message: "validation failed",
		Details: map[string]any{"field": "name"},
	}
	if manifestErr.Message != "validation failed" {
		t.Errorf("ManifestValidationError.Message = %v, want validation failed", manifestErr.Message)
	}
	if manifestErr.Details["field"] != "name" {
		t.Errorf("ManifestValidationError.Details[field] = %v, want name", manifestErr.Details["field"])
	}

	// ExecutionError
	execErr := &ExecutionError{
		ExtensionName: "test-ext",
		OperationID:   "test-op",
		Message:       "execution failed",
		Details:       map[string]any{"timeout": 300},
	}
	if execErr.ExtensionName != "test-ext" {
		t.Errorf("ExecutionError.ExtensionName = %v, want test-ext", execErr.ExtensionName)
	}
	if execErr.OperationID != "test-op" {
		t.Errorf("ExecutionError.OperationID = %v, want test-op", execErr.OperationID)
	}
	if execErr.Details["timeout"] != 300 {
		t.Errorf("ExecutionError.Details[timeout] = %v, want 300", execErr.Details["timeout"])
	}

	// PrebuiltExtensionError
	prebuiltErr := &PrebuiltExtensionError{
		ExtensionType: PrebuiltExtensionVertexAISearch,
		Message:       "configuration error",
	}
	if prebuiltErr.ExtensionType != PrebuiltExtensionVertexAISearch {
		t.Errorf("PrebuiltExtensionError.ExtensionType = %v, want %v", prebuiltErr.ExtensionType, PrebuiltExtensionVertexAISearch)
	}

	// AuthenticationError
	authErr := &AuthenticationError{
		Message: "auth failed",
		Details: map[string]any{"scope": "test-scope"},
	}
	if authErr.Details["scope"] != "test-scope" {
		t.Errorf("AuthenticationError.Details[scope] = %v, want test-scope", authErr.Details["scope"])
	}

	// APIError
	apiErr := &APIError{
		StatusCode: 500,
		Message:    "internal error",
		Details:    map[string]any{"request_id": "req123"},
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("APIError.StatusCode = %v, want 500", apiErr.StatusCode)
	}
	if apiErr.Details["request_id"] != "req123" {
		t.Errorf("APIError.Details[request_id] = %v, want req123", apiErr.Details["request_id"])
	}

	// ConfigurationError
	configErr := &ConfigurationError{
		Parameter: "location",
		Message:   "invalid value",
	}
	if configErr.Parameter != "location" {
		t.Errorf("ConfigurationError.Parameter = %v, want location", configErr.Parameter)
	}
}
