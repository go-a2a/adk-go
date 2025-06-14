// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"fmt"
	"strings"
)

// RegionNotSupportedError is returned when attempting to use extensions
// in a region that doesn't support the Extensions API.
type RegionNotSupportedError struct {
	RequestedRegion  string
	SupportedRegions []string
}

func (e *RegionNotSupportedError) Error() string {
	return fmt.Sprintf("Extensions API is not supported in region '%s'. Supported regions: %s",
		e.RequestedRegion, strings.Join(e.SupportedRegions, ", "))
}

// ExtensionNotFoundError is returned when attempting to access
// an extension that doesn't exist.
type ExtensionNotFoundError struct {
	Name string
}

func (e *ExtensionNotFoundError) Error() string {
	return fmt.Sprintf("extension not found: %s", e.Name)
}

// ManifestValidationError is returned when an extension manifest
// fails validation.
type ManifestValidationError struct {
	Message string
	Details map[string]any
}

func (e *ManifestValidationError) Error() string {
	return fmt.Sprintf("manifest validation failed: %s", e.Message)
}

// ExecutionError is returned when extension execution fails.
type ExecutionError struct {
	ExtensionName string
	OperationID   string
	Message       string
	Details       map[string]any
}

func (e *ExecutionError) Error() string {
	return fmt.Sprintf("extension execution failed for %s.%s: %s",
		e.ExtensionName, e.OperationID, e.Message)
}

// PrebuiltExtensionError is returned when there's an issue with
// prebuilt extension configuration.
type PrebuiltExtensionError struct {
	ExtensionType PrebuiltExtensionType
	Message       string
}

func (e *PrebuiltExtensionError) Error() string {
	return fmt.Sprintf("prebuilt extension error for %s: %s",
		e.ExtensionType, e.Message)
}

// AuthenticationError is returned when there's an authentication
// issue with the extension service.
type AuthenticationError struct {
	Message string
	Details map[string]any
}

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("authentication error: %s", e.Message)
}

// APIError represents an error from the Vertex AI Extensions API.
type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]any
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// ConfigurationError is returned when there's a configuration
// issue with the extension service.
type ConfigurationError struct {
	Parameter string
	Message   string
}

func (e *ConfigurationError) Error() string {
	return fmt.Sprintf("configuration error for %s: %s", e.Parameter, e.Message)
}
