// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
)

// ExampleService handles example management operations within Example Stores.
type ExampleService struct {
	client    *aiplatform.VertexRagDataClient
	projectID string
	location  string
	logger    *slog.Logger
}

// NewExampleService creates a new example service.
func NewExampleService(client *aiplatform.VertexRagDataClient, projectID, location string, logger *slog.Logger) *ExampleService {
	return &ExampleService{
		client:    client,
		projectID: projectID,
		location:  location,
		logger:    logger,
	}
}

// UploadExamples uploads examples to an Example Store.
func (e *ExampleService) UploadExamples(ctx context.Context, req *UploadExamplesRequest) (*UploadExamplesResponse, error) {
	e.logger.InfoContext(ctx, "Uploading examples",
		slog.String("store", req.Parent),
		slog.Int("example_count", len(req.Examples)),
	)

	if err := ValidateExamples(req.Examples); err != nil {
		return nil, fmt.Errorf("invalid examples: %w", err)
	}

	// TODO: Replace with actual Vertex AI API call
	// This would typically involve calling something like:
	// resp, err := e.client.UploadExamples(ctx, protoReq)

	// For now, simulate the upload by creating stored examples
	now := time.Now()
	var storedExamples []*StoredExample

	for i, example := range req.Examples {
		exampleID := generateExampleID(example.DisplayName, i)
		exampleName := fmt.Sprintf("%s/examples/%s", req.Parent, exampleID)

		storedExample := &StoredExample{
			Name:        exampleName,
			DisplayName: example.DisplayName,
			Input:       example.Input,
			Output:      example.Output,
			Metadata:    example.Metadata,
			CreateTime:  &now,
			UpdateTime:  &now,
			State:       ExampleStateActive,
			// TODO: Generate actual embedding vector using the store's embedding model
			EmbeddingVector: generateMockEmbedding(example.Input.Text),
		}

		storedExamples = append(storedExamples, storedExample)

		e.logger.InfoContext(ctx, "Example uploaded",
			slog.String("example_name", storedExample.Name),
			slog.String("display_name", storedExample.DisplayName),
		)
	}

	response := &UploadExamplesResponse{
		Examples: storedExamples,
	}

	e.logger.InfoContext(ctx, "Examples upload completed",
		slog.String("store", req.Parent),
		slog.Int("uploaded_count", len(storedExamples)),
	)

	return response, nil
}

// ListExamples lists examples in an Example Store.
func (e *ExampleService) ListExamples(ctx context.Context, req *ListExamplesRequest) (*ListExamplesResponse, error) {
	e.logger.InfoContext(ctx, "Listing examples",
		slog.String("store", req.Parent),
		slog.Int("page_size", int(req.PageSize)),
	)

	// TODO: Replace with actual Vertex AI API call
	// This would typically involve calling something like:
	// resp, err := e.client.ListExamples(ctx, protoReq)

	// For now, return empty list as this is a mock implementation
	response := &ListExamplesResponse{
		Examples:      []*StoredExample{},
		NextPageToken: "",
	}

	e.logger.InfoContext(ctx, "Listed examples",
		slog.String("store", req.Parent),
		slog.Int("example_count", len(response.Examples)),
	)

	return response, nil
}

// GetExample retrieves a specific example.
func (e *ExampleService) GetExample(ctx context.Context, exampleName string) (*StoredExample, error) {
	e.logger.InfoContext(ctx, "Getting example",
		slog.String("example_name", exampleName),
	)

	// TODO: Replace with actual Vertex AI API call
	// This would typically involve calling something like:
	// resp, err := e.client.GetExample(ctx, protoReq)

	// For now, return a mock example
	now := time.Now()
	example := &StoredExample{
		Name:        exampleName,
		DisplayName: "Mock Example",
		Input: &Content{
			Text:     "What is the capital of France?",
			Metadata: map[string]any{"category": "geography"},
		},
		Output: &Content{
			Text:     "The capital of France is Paris.",
			Metadata: map[string]any{"confidence": 0.95},
		},
		Metadata:        map[string]any{"source": "mock", "difficulty": "easy"},
		CreateTime:      &now,
		UpdateTime:      &now,
		State:           ExampleStateActive,
		EmbeddingVector: generateMockEmbedding("What is the capital of France?"),
	}

	e.logger.InfoContext(ctx, "Retrieved example",
		slog.String("example_name", example.Name),
		slog.String("state", string(example.State)),
	)

	return example, nil
}

// DeleteExample deletes a specific example.
func (e *ExampleService) DeleteExample(ctx context.Context, req *DeleteExampleRequest) error {
	e.logger.InfoContext(ctx, "Deleting example",
		slog.String("example_name", req.Name),
	)

	// TODO: Replace with actual Vertex AI API call
	// This would typically involve calling something like:
	// _, err := e.client.DeleteExample(ctx, protoReq)

	e.logger.InfoContext(ctx, "Example deleted",
		slog.String("example_name", req.Name),
	)

	return nil
}

// BatchDeleteExamples deletes multiple examples.
func (e *ExampleService) BatchDeleteExamples(ctx context.Context, req *BatchDeleteExamplesRequest) error {
	e.logger.InfoContext(ctx, "Batch deleting examples",
		slog.Int("example_count", len(req.Names)),
	)

	// TODO: Replace with actual Vertex AI API call
	// For now, delete each example individually
	for _, exampleName := range req.Names {
		deleteReq := &DeleteExampleRequest{Name: exampleName}
		if err := e.DeleteExample(ctx, deleteReq); err != nil {
			return fmt.Errorf("failed to delete example %s: %w", exampleName, err)
		}
	}

	e.logger.InfoContext(ctx, "Batch delete completed",
		slog.Int("deleted_count", len(req.Names)),
	)

	return nil
}

// UpdateExample updates an existing example.
func (e *ExampleService) UpdateExample(ctx context.Context, example *StoredExample, updateMask []string) (*StoredExample, error) {
	e.logger.InfoContext(ctx, "Updating example",
		slog.String("example_name", example.Name),
		slog.Any("update_mask", updateMask),
	)

	// TODO: Replace with actual Vertex AI API call
	// This would typically involve calling something like:
	// resp, err := e.client.UpdateExample(ctx, protoReq)

	// Update the timestamp
	now := time.Now()
	example.UpdateTime = &now

	e.logger.InfoContext(ctx, "Example updated",
		slog.String("example_name", example.Name),
	)

	return example, nil
}

// ListAllExamples lists all examples in a store, handling pagination automatically.
func (e *ExampleService) ListAllExamples(ctx context.Context, storeName string) ([]*StoredExample, error) {
	e.logger.InfoContext(ctx, "Listing all examples",
		slog.String("store", storeName),
	)

	allExamples := make([]*StoredExample, 0)
	pageToken := ""

	for {
		resp, err := e.ListExamples(ctx, &ListExamplesRequest{
			Parent:    storeName,
			PageSize:  100, // Use reasonable page size
			PageToken: pageToken,
		})
		if err != nil {
			return allExamples, fmt.Errorf("failed to list examples: %w", err)
		}

		allExamples = append(allExamples, resp.Examples...)

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	e.logger.InfoContext(ctx, "Listed all examples",
		slog.String("store", storeName),
		slog.Int("total_examples", len(allExamples)),
	)

	return allExamples, nil
}

// UploadExamplesFromSlice uploads examples from a slice, automatically batching.
func (e *ExampleService) UploadExamplesFromSlice(ctx context.Context, storeName string, examples []*Example) ([]*StoredExample, error) {
	e.logger.InfoContext(ctx, "Uploading examples from slice",
		slog.String("store", storeName),
		slog.Int("total_examples", len(examples)),
	)

	if len(examples) == 0 {
		return nil, fmt.Errorf("no examples provided")
	}

	var allResults []*StoredExample
	batchSize := MaxExamplesPerUpload

	for i := 0; i < len(examples); i += batchSize {
		end := i + batchSize
		if end > len(examples) {
			end = len(examples)
		}

		batch := examples[i:end]
		req := &UploadExamplesRequest{
			Parent:   storeName,
			Examples: batch,
		}

		response, err := e.UploadExamples(ctx, req)
		if err != nil {
			return allResults, fmt.Errorf("failed to upload batch %d-%d: %w", i, end-1, err)
		}

		allResults = append(allResults, response.Examples...)

		e.logger.InfoContext(ctx, "Uploaded example batch",
			slog.String("store", storeName),
			slog.Int("batch_start", i),
			slog.Int("batch_end", end-1),
			slog.Int("batch_size", len(batch)),
		)
	}

	e.logger.InfoContext(ctx, "Slice upload completed",
		slog.String("store", storeName),
		slog.Int("total_examples", len(examples)),
		slog.Int("total_uploaded", len(allResults)),
	)

	return allResults, nil
}

// Helper functions

// generateExampleID generates a unique example ID.
func generateExampleID(displayName string, index int) string {
	timestamp := time.Now().UnixNano()
	if displayName != "" {
		return fmt.Sprintf("example-%s-%d-%d", displayName, index, timestamp)
	}
	return fmt.Sprintf("example-%d-%d", index, timestamp)
}

// generateMockEmbedding generates a mock embedding vector for testing.
// TODO: Replace with actual embedding generation using the store's embedding model.
func generateMockEmbedding(text string) []float32 {
	// Generate a simple mock embedding based on text length and content
	// In a real implementation, this would use the configured embedding model
	embedding := make([]float32, 768) // Common embedding dimension

	// Simple hash-based mock embedding
	hash := 0
	for _, char := range text {
		hash = hash*31 + int(char)
	}

	for i := range embedding {
		embedding[i] = float32((hash+i)%1000) / 1000.0
	}

	return embedding
}

// ValidateUploadRequest validates an upload examples request.
func (e *ExampleService) ValidateUploadRequest(req *UploadExamplesRequest) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}

	if req.Parent == "" {
		return fmt.Errorf("parent store is required")
	}

	return ValidateExamples(req.Examples)
}

// GetExampleMetrics calculates metrics for examples in a store.
func (e *ExampleService) GetExampleMetrics(ctx context.Context, storeName string) (map[string]any, error) {
	e.logger.InfoContext(ctx, "Calculating example metrics",
		slog.String("store", storeName),
	)

	examples, err := e.ListAllExamples(ctx, storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to list examples: %w", err)
	}

	metrics := map[string]any{
		"total_count":           len(examples),
		"average_input_length":  0.0,
		"average_output_length": 0.0,
		"metadata_keys":         []string{},
		"states":                map[string]int{},
	}

	if len(examples) == 0 {
		return metrics, nil
	}

	var totalInputLength, totalOutputLength int
	metadataKeys := make(map[string]bool)
	states := make(map[string]int)

	for _, example := range examples {
		// Calculate lengths
		if example.Input != nil {
			totalInputLength += len(example.Input.Text)
		}
		if example.Output != nil {
			totalOutputLength += len(example.Output.Text)
		}

		// Collect metadata keys
		for key := range example.Metadata {
			metadataKeys[key] = true
		}
		if example.Input != nil {
			for key := range example.Input.Metadata {
				metadataKeys[key] = true
			}
		}
		if example.Output != nil {
			for key := range example.Output.Metadata {
				metadataKeys[key] = true
			}
		}

		// Count states
		states[string(example.State)]++
	}

	// Calculate averages
	metrics["average_input_length"] = float64(totalInputLength) / float64(len(examples))
	metrics["average_output_length"] = float64(totalOutputLength) / float64(len(examples))

	// Convert metadata keys to slice
	keys := make([]string, 0, len(metadataKeys))
	for key := range metadataKeys {
		keys = append(keys, key)
	}
	metrics["metadata_keys"] = keys
	metrics["states"] = states

	e.logger.InfoContext(ctx, "Example metrics calculated",
		slog.String("store", storeName),
		slog.Int("total_examples", len(examples)),
		slog.Float64("avg_input_length", metrics["average_input_length"].(float64)),
		slog.Float64("avg_output_length", metrics["average_output_length"].(float64)),
	)

	return metrics, nil
}
