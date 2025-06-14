// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package generative_models provides enhanced generative model capabilities for Vertex AI.
//
// This package extends the standard generative model functionality with preview features
// that are experimental and subject to change. It provides advanced configuration options,
// enhanced safety features, and integration with other preview services like content caching.
//
// # Enhanced Features
//
// The package provides preview capabilities including:
//   - Advanced content caching integration
//   - Enhanced safety and content filtering options
//   - Experimental model parameters and configurations
//   - Advanced function calling capabilities
//   - Preview-specific model access and features
//   - Custom generation configurations
//   - Enhanced streaming capabilities
//
// # Model Support
//
// The service supports preview features for various model families:
//   - Gemini 2.0 models with enhanced capabilities
//   - Experimental model variants
//   - Models with content caching support
//   - Custom fine-tuned models in preview
//
// # Architecture
//
// The package provides:
//   - PreviewGenerativeService: Core service for enhanced model operations
//   - PreviewGenerateRequest/Response: Extended request/response types
//   - SafetyConfig: Enhanced safety configuration options
//   - ToolConfig: Advanced tool calling configuration
//   - Integration with content_caching for optimized token usage
//
// # Usage
//
// Basic enhanced generation:
//
//	service, err := generative_models.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Create a preview request with enhanced features
//	request := &generative_models.PreviewGenerateRequest{
//		GenerateContentRequest: &genai.GenerateContentRequest{
//			Contents: []*genai.Content{
//				{Parts: []genai.Part{genai.Text("Explain quantum computing")}},
//			},
//		},
//		UseContentCache:   true,
//		CacheID:          "projects/my-project/locations/us-central1/cachedContents/my-cache",
//		EnhancedSafety:   &generative_models.SafetyConfig{StrictMode: true},
//		ExperimentalOpts: map[string]any{"temperature": 0.9},
//	}
//
//	// Generate content with preview features
//	response, err := service.GenerateContentWithPreview(ctx, "gemini-2.0-flash-001", request)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Content Caching Integration
//
// The service seamlessly integrates with content caching:
//
//	// Use cached content in generation
//	request.UseContentCache = true
//	request.CacheID = "projects/my-project/locations/us-central1/cachedContents/my-cache"
//
//	response, err := service.GenerateContentWithPreview(ctx, modelName, request)
//
// # Enhanced Safety
//
// Preview safety features provide additional control:
//
//	safetyConfig := &generative_models.SafetyConfig{
//		StrictMode: true,
//		CustomThresholds: map[string]string{
//			"HARM_CATEGORY_HARASSMENT": "BLOCK_LOW_AND_ABOVE",
//		},
//		EnableAdvancedDetection: true,
//	}
//
//	request.EnhancedSafety = safetyConfig
//
// # Streaming
//
// Enhanced streaming with preview features:
//
//	for response, err := range service.GenerateContentStreamWithPreview(ctx, modelName, request) {
//		if err != nil {
//			log.Printf("Streaming error: %v", err)
//			continue
//		}
//		// Process streaming response
//	}
//
// # Function Calling
//
// Advanced function calling capabilities:
//
//	toolConfig := &generative_models.ToolConfig{
//		ParallelCalling: true,
//		MaxConcurrency: 5,
//		TimeoutPerTool: time.Second * 30,
//	}
//
//	request.ToolConfig = toolConfig
//
// # Error Handling
//
// The package provides detailed error information for preview features,
// including model compatibility errors, safety violations, and experimental
// feature limitations.
//
// # Thread Safety
//
// All service operations are safe for concurrent use across multiple goroutines.
package generativemodels
