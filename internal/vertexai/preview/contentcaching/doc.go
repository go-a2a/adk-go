// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package content_caching provides content caching functionality for Vertex AI generative models.
//
// This package implements content caching capabilities that allow models to reuse previously
// cached content to optimize token usage when dealing with large pieces of content. This is
// especially useful for conversational flows or scenarios where the model references a large
// piece of content consistently across multiple requests.
//
// # Supported Models
//
// Content caching is currently supported by specific models:
//   - gemini-2.0-flash-001
//   - gemini-2.0-pro-001
//
// Note: Only specific model versions support context caching, and you must specify the
// version number (e.g., "001") when using caching features.
//
// # Architecture
//
// The package provides:
//   - CacheService: Core caching operations (create, get, list, update, delete)
//   - CachedContent: Represents cached content with metadata and configuration
//   - CacheConfig: Configuration options for cache creation and management
//   - Integration with genai.Content types for seamless model integration
//
// # Usage
//
// Basic cache creation and usage:
//
//	service, err := content_caching.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Create a cache with large content
//	content := &genai.Content{
//		Parts: []genai.Part{genai.Text("Large document content...")},
//	}
//
//	config := &content_caching.CacheConfig{
//		DisplayName: "My Document Cache",
//		ModelName:   "gemini-2.0-flash-001",
//		TTL:         time.Hour * 24, // Cache for 24 hours
//	}
//
//	cache, err := service.CreateCache(ctx, content, config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Use the cache in model requests
//	model := genai.NewGenerativeModel(client, "gemini-2.0-flash-001")
//	model.CachedContent = cache.Name
//
//	resp, err := model.GenerateContent(ctx, genai.Text("What does this document say about...?"))
//
// # Cache Management
//
// Caches have configurable time-to-live (TTL) values and can be managed through:
//   - List all caches
//   - Get specific cache details
//   - Update cache content or configuration
//   - Delete caches when no longer needed
//
// # Performance Benefits
//
// Content caching provides several benefits:
//   - Reduced token usage for repeated large content
//   - Faster response times for cached content
//   - Cost optimization for applications with consistent large contexts
//   - Improved scalability for multi-turn conversations
//
// # Error Handling
//
// The package provides detailed error information for cache operations, including:
//   - Model compatibility errors
//   - Content size limitations
//   - TTL validation errors
//   - Cache quota and rate limiting errors
//
// # Thread Safety
//
// All service operations are safe for concurrent use across multiple goroutines.
package contentcaching
