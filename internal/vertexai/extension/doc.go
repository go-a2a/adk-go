// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package extension provides a comprehensive Go implementation of Google Cloud Vertex AI Extensions functionality.
//
// This package is a port of the Python vertexai.preview.extensions module, providing access to
// Vertex AI's Extension API which allows you to register, manage, and execute extensions that
// connect models to external APIs for real-time data processing and real-world actions.
//
// # Overview
//
// Vertex AI Extensions enable you to:
//   - Register custom extensions with API specifications and authentication
//   - Use prebuilt extensions like code_interpreter and vertex_ai_search
//   - Execute extension operations with structured parameters
//   - Manage extension lifecycles and configurations
//
// # Key Features
//
//   - Extension Management: Create, list, get, and delete extensions
//   - Prebuilt Extensions: Access to Google's curated extension hub
//   - Execution Engine: Execute extension operations with real-time results
//   - Manifest Support: Define API specifications, authentication, and runtime configurations
//   - Region Support: Currently restricted to us-central1 region only
//
// # Architecture
//
// The package follows the ADK's service pattern with these main components:
//
//   - Service: Main extension service providing all operations
//   - Extension: Individual extension representation with metadata and configuration
//   - Manifest: Extension definition including API specs and authentication
//   - RuntimeConfig: Runtime-specific configuration for extension execution
//   - PrebuiltExtensions: Factory for creating well-known extensions
//
// # Usage
//
// Basic usage starts with creating an extension service:
//
//	service, err := extension.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
// Create an extension from the hub:
//
//	ext, err := service.CreateFromHub(ctx, "code_interpreter")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Execute an extension operation:
//
//	result, err := service.ExecuteExtension(ctx, ext.ID, "generate_and_execute", map[string]any{
//		"query": "find the max value in the list: [1,2,3,4,-5]",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Create a custom extension:
//
//	manifest := &Manifest{
//		Name:        "my_custom_extension",
//		Description: "Custom extension for specialized tasks",
//		APISpec: &APISpec{
//			OpenAPIGCSURI: "gs://my-bucket/openapi.yaml",
//		},
//		AuthConfig: &AuthConfig{
//			AuthType: AuthTypeGoogleServiceAccount,
//			GoogleServiceAccountConfig: &GoogleServiceAccountConfig{},
//		},
//	}
//
//	req := &CreateExtensionRequest{
//		DisplayName: "My Custom Extension",
//		Description: "A custom extension for my use case",
//		Manifest:    manifest,
//	}
//
//	ext, err := service.CreateExtension(ctx, req)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Prebuilt Extensions
//
// Google provides several prebuilt extensions:
//
//   - code_interpreter: Generates and executes Python code for data analysis
//   - vertex_ai_search: Connects to Vertex AI Search datastores for semantic search
//
// # Limitations
//
//   - Geographic Restriction: Extensions API is only available in us-central1 region
//   - Preview Status: Subject to "Pre-GA Offerings Terms" with limited support
//   - Authentication: Currently supports Google Service Account authentication only
//
// # Error Handling
//
// The package provides specific error types for common failure scenarios:
//
//   - RegionNotSupportedError: When attempting to use extensions outside us-central1
//   - ExtensionNotFoundError: When referencing non-existent extensions
//   - ExecutionError: When extension execution fails
//   - ManifestValidationError: When extension manifests are invalid
//
// # Thread Safety
//
// All service methods are safe for concurrent use across multiple goroutines.
// Extension objects are immutable after creation.
//
// # Authentication
//
// The package uses Google Cloud authentication via Application Default Credentials (ADC).
// Ensure proper credentials are configured before using extension services.
package extension
