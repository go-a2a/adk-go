// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package rag provides a Go implementation of Google Cloud Vertex AI RAG (Retrieval-Augmented Generation) functionality.
//
// This package is a port of the Python vertexai.preview.rag module, providing comprehensive support for:
//
//   - Corpus Management: Create, list, get, update, and delete RAG corpora
//   - File Management: Import, upload, list, get, and delete files in RAG corpora
//   - Retrieval Services: Query and search documents using vector similarity
//   - Augmented Generation: Combine retrieval with generation for enhanced LLM responses
//
// # Architecture
//
// The package is organized into several key components:
//
//   - Client: Unified interface for all RAG operations
//   - CorpusService: Manages RAG corpus lifecycle operations
//   - FileService: Handles file operations within corpora
//   - RetrievalService: Provides document retrieval and search capabilities
//   - Types: Comprehensive type definitions matching the Vertex AI RAG API
//
// # Usage
//
// Basic usage starts with creating a client:
//
//	client, err := rag.NewClient(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer client.Close()
//
// Create a corpus:
//
//	corpus, err := client.CreateDefaultCorpus(ctx, "My Corpus", "A test corpus")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Import files:
//
//	err = client.ImportFilesFromGCS(ctx, corpus.Name, []string{"gs://my-bucket/docs/*"}, 1000, 100)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Query the corpus:
//
//	results, err := client.QuickQuery(ctx, corpus.Name, "What is machine learning?")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Backend Configuration
//
// The package supports multiple vector database backends:
//
//   - Managed RAG Database (default): Google-managed vector database
//   - Weaviate: Self-managed Weaviate instances
//   - Pinecone: Pinecone vector database service
//   - Vertex Vector Search: Google Cloud Vector Search
//
// # File Sources
//
// Files can be imported from various sources:
//
//   - Google Cloud Storage (GCS)
//   - Google Drive
//   - Direct upload
//
// # Search Capabilities
//
// The package provides multiple search methods:
//
//   - Semantic Search: Vector similarity-based search
//   - Hybrid Search: Combines vector and keyword search
//   - Augmented Generation: Retrieval-augmented generation
//
// # Error Handling
//
// All operations return Go-idiomatic errors with detailed error messages.
// The package handles rate limiting and retries internally where appropriate.
//
// # Thread Safety
//
// The Client and all service instances are safe for concurrent use across
// multiple goroutines.
package rag
