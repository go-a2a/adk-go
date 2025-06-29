// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package extension

import (
	"context"
	"fmt"
	"slices"

	"cloud.google.com/go/aiplatform/apiv1beta1/aiplatformpb"
)

// getPrebuiltExtensionConfig returns the manifest and runtime configuration
// for a prebuilt extension type.
func (s *service) getPrebuiltExtensionConfig(extensionType PrebuiltExtensionType) (*aiplatformpb.ExtensionManifest, *aiplatformpb.RuntimeConfig, error) {
	switch extensionType {
	case PrebuiltExtensionCodeInterpreter:
		return s.getCodeInterpreterConfig()
	case PrebuiltExtensionVertexAISearch:
		return s.getVertexAISearchConfig()
	default:
		return nil, nil, &PrebuiltExtensionError{
			ExtensionType: extensionType,
			Message:       "unknown prebuilt extension type",
		}
	}
}

// getCodeInterpreterConfig returns the configuration for the code interpreter extension.
func (s *service) getCodeInterpreterConfig() (*aiplatformpb.ExtensionManifest, *aiplatformpb.RuntimeConfig, error) {
	manifest := NewExtensionManifest(
		"code_interpreter_tool",
		"Google Code Interpreter Extension",
		"gs://vertex-extension-public/code_interpreter.yaml",
		NewGoogleServiceAccountConfig(""), // Empty string uses default service account
	)

	runtimeConfig := NewCodeInterpreterRuntimeConfig(
		"", // No specific input bucket
		"", // No specific output bucket
	)

	return manifest, runtimeConfig, nil
}

// getVertexAISearchConfig returns the configuration for the Vertex AI Search extension.
func (s *service) getVertexAISearchConfig() (*aiplatformpb.ExtensionManifest, *aiplatformpb.RuntimeConfig, error) {
	manifest := NewExtensionManifest(
		"vertex_ai_search",
		"Google Vertex AI Search Extension",
		"gs://vertex-extension-public/vertex_ai_search.yaml",
		NewGoogleServiceAccountConfig(""), // Empty string uses default service account
	)

	// Note: RuntimeConfig for Vertex AI Search requires serving_config_name
	// which must be provided when creating the extension
	runtimeConfig := NewVertexAISearchRuntimeConfig(
		"", // Serving config name must be set later
		"", // Engine ID not specified
	)

	return manifest, runtimeConfig, nil
}

// getPrebuiltDisplayName returns the display name for a prebuilt extension.
func (s *service) getPrebuiltDisplayName(extensionType PrebuiltExtensionType) string {
	switch extensionType {
	case PrebuiltExtensionCodeInterpreter:
		return "Code Interpreter"
	case PrebuiltExtensionVertexAISearch:
		return "Vertex AI Search"
	default:
		return string(extensionType)
	}
}

// getPrebuiltDescription returns the description for a prebuilt extension.
func (s *service) getPrebuiltDescription(extensionType PrebuiltExtensionType) string {
	switch extensionType {
	case PrebuiltExtensionCodeInterpreter:
		return "This extension generates and executes code in the specified language"
	case PrebuiltExtensionVertexAISearch:
		return "This extension searches from provided datastore"
	default:
		return fmt.Sprintf("Prebuilt extension: %s", extensionType)
	}
}

// CreateCodeInterpreterExtension creates a code interpreter extension with default configuration.
func (s *service) CreateCodeInterpreterExtension(ctx context.Context, inputBucket, outputBucket string) (*Extension, error) {
	return s.CreateFromHub(ctx, PrebuiltExtensionCodeInterpreter, NewCodeInterpreterRuntimeConfig(inputBucket, outputBucket))
}

// CreateVertexAISearchExtension creates a Vertex AI Search extension with the specified serving config.
func (s *service) CreateVertexAISearchExtension(ctx context.Context, servingConfigName string) (*Extension, error) {
	if servingConfigName == "" {
		return nil, &PrebuiltExtensionError{
			ExtensionType: PrebuiltExtensionVertexAISearch,
			Message:       "serving_config_name is required for Vertex AI Search extension",
		}
	}

	manifest, runtimeConfig, err := s.getVertexAISearchConfig()
	if err != nil {
		return nil, err
	}

	// Set the serving config name
	if vertexSearchConfig := runtimeConfig.GetVertexAiSearchRuntimeConfig(); vertexSearchConfig != nil {
		vertexSearchConfig.ServingConfigName = servingConfigName
	}

	req := &aiplatformpb.ImportExtensionRequest{
		Parent: s.GetParent(),
		Extension: &aiplatformpb.Extension{
			Name:          servingConfigName,
			DisplayName:   s.getPrebuiltDisplayName(PrebuiltExtensionVertexAISearch),
			Description:   s.getPrebuiltDescription(PrebuiltExtensionVertexAISearch),
			Manifest:      manifest,
			RuntimeConfig: runtimeConfig,
		},
	}

	return s.CreateExtension(ctx, req)
}

// GetSupportedPrebuiltExtensions returns a list of supported prebuilt extension types.
func (s *service) GetSupportedPrebuiltExtensions() []PrebuiltExtensionType {
	return []PrebuiltExtensionType{
		PrebuiltExtensionCodeInterpreter,
		PrebuiltExtensionVertexAISearch,
	}
}

// ValidatePrebuiltExtensionType validates that the extension type is supported.
func (s *service) ValidatePrebuiltExtensionType(extensionType PrebuiltExtensionType) error {
	supported := s.GetSupportedPrebuiltExtensions()
	if slices.Contains(supported, extensionType) {
		return nil
	}

	return &PrebuiltExtensionError{
		ExtensionType: extensionType,
		Message:       "unsupported prebuilt extension type",
	}
}
