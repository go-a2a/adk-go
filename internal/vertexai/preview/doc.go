// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package preview provides a comprehensive Go implementation of Google Cloud Vertex AI preview functionality.
//
// This package is a port of the Python vertexai.preview module, providing access to experimental and
// preview features of Vertex AI services. It includes support for:
//
//   - RAG (Retrieval-Augmented Generation): Comprehensive corpus and document management
//   - Content Caching: Optimized content caching for large contexts and improved token efficiency
//   - Enhanced Generative Models: Preview features for generative AI models
//   - Model Garden Integration: Access to experimental and community models
//   - Advanced Language Models: Preview capabilities for language understanding and generation
//   - Vision Models: Preview features for image and video processing
//   - Evaluation Tools: Model evaluation and benchmarking capabilities
//   - Resource Management: Enhanced resource lifecycle management
//
// # Architecture
//
// The package follows a modular architecture with specialized services:
//
//   - PreviewClient: Unified client providing access to all preview services
//   - RAG Service: Retrieval-augmented generation functionality
//   - Content Caching Service: Advanced caching capabilities for models
//   - Generative Models Service: Enhanced generative model features
//   - Model Garden Service: Access to experimental model deployments
//   - Language Models Service: Preview language processing capabilities
//   - Vision Models Service: Preview vision and multimodal capabilities
//   - Evaluation Service: Model evaluation and benchmarking tools
//   - Resources Service: Advanced resource management features
//
// # Usage
//
// Basic usage starts with creating a preview client:
//
//	client, err := preview.NewClient(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
// Access individual services:
//
//	// RAG operations
//	ragClient := client.RAG()
//	corpus, err := ragClient.CreateDefaultCorpus(ctx, "My Corpus", "Description")
//
//	// Content caching
//	cacheService := client.ContentCaching()
//	cache, err := cacheService.CreateCache(ctx, content, cacheConfig)
//
//	// Enhanced generative models
//	genService := client.GenerativeModels()
//	response, err := genService.GenerateContentWithPreview(ctx, previewRequest)
//
//	// Model Garden
//	gardenService := client.ModelGarden()
//	models, err := gardenService.ListModels(ctx, listOptions)
//
// # Preview Features
//
// Preview features are experimental and subject to change. They provide early access to:
//
//   - Advanced model capabilities not yet in stable API
//   - Experimental model architectures and parameters
//   - Enhanced safety and content filtering options
//   - Optimized performance features like content caching
//   - Integration with specialized vector databases and search systems
//
// # Thread Safety
//
// All clients and services are safe for concurrent use across multiple goroutines.
// Resource cleanup is handled automatically, but clients should be explicitly closed
// when no longer needed.
//
// # Error Handling
//
// All operations return Go-idiomatic errors with detailed context. Preview features
// may have additional error conditions related to experimental functionality.
//
// # Authentication
//
// The package uses Google Cloud authentication via Application Default Credentials (ADC).
// Ensure proper credentials are configured before using preview services.
package preview
