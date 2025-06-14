// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package examplestore provides functionality for managing Vertex AI Example Stores.
//
// Example Stores allow you to store examples when developing your LLM application
// and dynamically retrieve them to use in your LLM prompts. This enables few-shot
// learning and improves model performance by providing relevant examples during inference.
//
// # Key Features
//
//   - Create and manage Example Store instances
//   - Upload examples with input/output content
//   - Search and retrieve relevant examples based on queries
//   - Support for multiple embedding models
//   - Regional deployment (currently us-central1 only)
//
// # Example Usage
//
//	ctx := context.Background()
//	service, err := examplestore.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Create an example store
//	store, err := service.CreateStore(ctx, &examplestore.StoreConfig{
//		EmbeddingModel: "text-embedding-005",
//		DisplayName:    "My Example Store",
//		Description:    "Examples for my LLM application",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Upload examples
//	examples := []*examplestore.Example{
//		{
//			Input:  &examplestore.Content{Text: "What is the capital of France?"},
//			Output: &examplestore.Content{Text: "The capital of France is Paris."},
//		},
//	}
//	if err := service.UploadExamples(ctx, store.Name, examples); err != nil {
//		log.Fatal(err)
//	}
//
//	// Search for relevant examples
//	results, err := service.SearchExamples(ctx, store.Name, "capital cities", 5)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Limitations
//
//   - Only us-central1 region is currently supported
//   - Maximum of 50 Example Store instances per project/location
//   - Maximum of 5 examples per upload request
//   - Examples become available immediately after upload
//
// # Authentication
//
// This package requires Google Cloud authentication. Use Application Default
// Credentials (ADC) or set the GOOGLE_APPLICATION_CREDENTIALS environment variable.
package examplestore
