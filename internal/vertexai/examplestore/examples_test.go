// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExample_Validate(t *testing.T) {
	tests := []struct {
		name    string
		example *Example
		wantErr bool
	}{
		{
			name: "valid example",
			example: &Example{
				Input: &Content{
					Text: "What is the capital of France?",
				},
				Output: &Content{
					Text: "The capital of France is Paris.",
				},
				DisplayName: "Geography Example",
			},
			wantErr: false,
		},
		{
			name: "nil input",
			example: &Example{
				Input: nil,
				Output: &Content{
					Text: "The capital of France is Paris.",
				},
			},
			wantErr: true,
		},
		{
			name: "empty input text",
			example: &Example{
				Input: &Content{
					Text: "",
				},
				Output: &Content{
					Text: "The capital of France is Paris.",
				},
			},
			wantErr: true,
		},
		{
			name: "nil output",
			example: &Example{
				Input: &Content{
					Text: "What is the capital of France?",
				},
				Output: nil,
			},
			wantErr: true,
		},
		{
			name: "empty output text",
			example: &Example{
				Input: &Content{
					Text: "What is the capital of France?",
				},
				Output: &Content{
					Text: "",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.example.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Example.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExampleService_UploadExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	examples := []*Example{
		{
			Input: &Content{
				Text: "What is the capital of France?",
				Metadata: map[string]any{
					"category": "geography",
				},
			},
			Output: &Content{
				Text: "The capital of France is Paris.",
				Metadata: map[string]any{
					"confidence": 0.95,
				},
			},
			DisplayName: "Geography Example 1",
			Metadata: map[string]any{
				"source": "test",
			},
		},
		{
			Input: &Content{
				Text: "What is 2 + 2?",
			},
			Output: &Content{
				Text: "2 + 2 equals 4.",
			},
			DisplayName: "Math Example 1",
		},
	}

	req := &UploadExamplesRequest{
		Parent:   storeName,
		Examples: examples,
	}

	resp, err := exampleService.UploadExamples(ctx, req)
	if err != nil {
		t.Errorf("ExampleService.UploadExamples() error = %v", err)
		return
	}

	if resp == nil {
		t.Error("ExampleService.UploadExamples() returned nil response")
		return
	}

	if len(resp.Examples) != len(examples) {
		t.Errorf("UploadExamples() returned %d examples, want %d", len(resp.Examples), len(examples))
	}

	// Verify each uploaded example
	for i, storedExample := range resp.Examples {
		if storedExample.DisplayName != examples[i].DisplayName {
			t.Errorf("StoredExample[%d].DisplayName = %v, want %v", i, storedExample.DisplayName, examples[i].DisplayName)
		}

		if storedExample.Input.Text != examples[i].Input.Text {
			t.Errorf("StoredExample[%d].Input.Text = %v, want %v", i, storedExample.Input.Text, examples[i].Input.Text)
		}

		if storedExample.Output.Text != examples[i].Output.Text {
			t.Errorf("StoredExample[%d].Output.Text = %v, want %v", i, storedExample.Output.Text, examples[i].Output.Text)
		}

		if storedExample.State != ExampleStateActive {
			t.Errorf("StoredExample[%d].State = %v, want %v", i, storedExample.State, ExampleStateActive)
		}

		if storedExample.CreateTime == nil {
			t.Errorf("StoredExample[%d].CreateTime should not be nil", i)
		}

		if storedExample.UpdateTime == nil {
			t.Errorf("StoredExample[%d].UpdateTime should not be nil", i)
		}

		if len(storedExample.EmbeddingVector) == 0 {
			t.Errorf("StoredExample[%d].EmbeddingVector should not be empty", i)
		}
	}
}

func TestExampleService_ListExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	req := &ListExamplesRequest{
		Parent:   "projects/test-project/locations/us-central1/exampleStores/test-store",
		PageSize: 10,
	}

	resp, err := exampleService.ListExamples(ctx, req)
	if err != nil {
		t.Errorf("ExampleService.ListExamples() error = %v", err)
		return
	}

	if resp == nil {
		t.Error("ExampleService.ListExamples() returned nil response")
		return
	}

	// Mock implementation returns empty list
	if len(resp.Examples) != 0 {
		t.Errorf("ExampleService.ListExamples() returned %d examples, expected 0 for mock", len(resp.Examples))
	}
}

func TestExampleService_GetExample(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	exampleName := "projects/test-project/locations/us-central1/exampleStores/test-store/examples/test-example"

	example, err := exampleService.GetExample(ctx, exampleName)
	if err != nil {
		t.Errorf("ExampleService.GetExample() error = %v", err)
		return
	}

	if example == nil {
		t.Error("ExampleService.GetExample() returned nil example")
		return
	}

	if example.Name != exampleName {
		t.Errorf("StoredExample.Name = %v, want %v", example.Name, exampleName)
	}

	if example.State != ExampleStateActive {
		t.Errorf("StoredExample.State = %v, want %v", example.State, ExampleStateActive)
	}

	if example.Input == nil {
		t.Error("StoredExample.Input should not be nil")
	}

	if example.Output == nil {
		t.Error("StoredExample.Output should not be nil")
	}
}

func TestExampleService_DeleteExample(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	req := &DeleteExampleRequest{
		Name: "projects/test-project/locations/us-central1/exampleStores/test-store/examples/test-example",
	}

	err = exampleService.DeleteExample(ctx, req)
	if err != nil {
		t.Errorf("ExampleService.DeleteExample() error = %v", err)
	}
}

func TestExampleService_BatchDeleteExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	exampleNames := []string{
		"projects/test-project/locations/us-central1/exampleStores/test-store/examples/example-1",
		"projects/test-project/locations/us-central1/exampleStores/test-store/examples/example-2",
		"projects/test-project/locations/us-central1/exampleStores/test-store/examples/example-3",
	}

	req := &BatchDeleteExamplesRequest{
		Names: exampleNames,
	}

	err = exampleService.BatchDeleteExamples(ctx, req)
	if err != nil {
		t.Errorf("ExampleService.BatchDeleteExamples() error = %v", err)
	}
}

func TestExampleService_UpdateExample(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	// Get a mock example first
	exampleName := "projects/test-project/locations/us-central1/exampleStores/test-store/examples/test-example"
	example, err := exampleService.GetExample(ctx, exampleName)
	if err != nil {
		t.Errorf("Failed to get example for update test: %v", err)
		return
	}

	originalUpdateTime := example.UpdateTime

	// Update the example
	example.DisplayName = "Updated Example"
	updateMask := []string{"display_name"}

	updatedExample, err := exampleService.UpdateExample(ctx, example, updateMask)
	if err != nil {
		t.Errorf("ExampleService.UpdateExample() error = %v", err)
		return
	}

	if updatedExample == nil {
		t.Error("ExampleService.UpdateExample() returned nil example")
		return
	}

	// Check that update time was updated
	if updatedExample.UpdateTime.Before(*originalUpdateTime) {
		t.Error("StoredExample.UpdateTime should have been updated")
	}
}

func TestExampleService_ListAllExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	examples, err := exampleService.ListAllExamples(ctx, storeName)
	if err != nil {
		t.Errorf("ExampleService.ListAllExamples() error = %v", err)
		return
	}

	// examples can be an empty slice, but should not be nil
	if examples == nil {
		t.Error("ExampleService.ListAllExamples() returned nil examples")
		return
	}

	// Mock implementation returns empty list
	if len(examples) != 0 {
		t.Errorf("ExampleService.ListAllExamples() returned %d examples, expected 0 for mock", len(examples))
	}
}

func TestExampleService_UploadExamplesFromSlice(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	// Create 12 examples to test batching
	examples := make([]*Example, 12)
	for i := 0; i < 12; i++ {
		examples[i] = &Example{
			Input: &Content{
				Text: fmt.Sprintf("Input text %d", i),
			},
			Output: &Content{
				Text: fmt.Sprintf("Output text %d", i),
			},
			DisplayName: fmt.Sprintf("Example %d", i),
		}
	}

	results, err := exampleService.UploadExamplesFromSlice(ctx, storeName, examples)
	if err != nil {
		t.Errorf("ExampleService.UploadExamplesFromSlice() error = %v", err)
		return
	}

	if len(results) != len(examples) {
		t.Errorf("UploadExamplesFromSlice() returned %d results, want %d", len(results), len(examples))
	}

	// Verify each result
	for i, result := range results {
		if result.DisplayName != examples[i].DisplayName {
			t.Errorf("Result %d DisplayName = %v, want %v", i, result.DisplayName, examples[i].DisplayName)
		}
	}
}

func TestExampleService_GetExampleMetrics(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	exampleService := service.exampleService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	metrics, err := exampleService.GetExampleMetrics(ctx, storeName)
	if err != nil {
		t.Errorf("ExampleService.GetExampleMetrics() error = %v", err)
		return
	}

	if metrics == nil {
		t.Error("ExampleService.GetExampleMetrics() returned nil metrics")
		return
	}

	// Check required fields
	requiredFields := []string{
		"total_count",
		"average_input_length",
		"average_output_length",
		"metadata_keys",
		"states",
	}

	for _, field := range requiredFields {
		if _, exists := metrics[field]; !exists {
			t.Errorf("ExampleService.GetExampleMetrics() missing field: %s", field)
		}
	}

	// Check types
	if totalCount, ok := metrics["total_count"].(int); !ok || totalCount < 0 {
		t.Errorf("metrics['total_count'] should be non-negative int, got %v", metrics["total_count"])
	}

	if avgInputLength, ok := metrics["average_input_length"].(float64); !ok || avgInputLength < 0 {
		t.Errorf("metrics['average_input_length'] should be non-negative float64, got %v", metrics["average_input_length"])
	}

	if avgOutputLength, ok := metrics["average_output_length"].(float64); !ok || avgOutputLength < 0 {
		t.Errorf("metrics['average_output_length'] should be non-negative float64, got %v", metrics["average_output_length"])
	}

	if metadataKeys, ok := metrics["metadata_keys"].([]string); !ok {
		t.Errorf("metrics['metadata_keys'] should be []string, got %v", metrics["metadata_keys"])
	} else if metadataKeys == nil {
		t.Error("metrics['metadata_keys'] should not be nil")
	}

	if states, ok := metrics["states"].(map[string]int); !ok {
		t.Errorf("metrics['states'] should be map[string]int, got %v", metrics["states"])
	} else if states == nil {
		t.Error("metrics['states'] should not be nil")
	}
}

func TestGenerateExampleID(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		index       int
	}{
		{
			name:        "with display name",
			displayName: "Test Example",
			index:       0,
		},
		{
			name:        "empty display name",
			displayName: "",
			index:       1,
		},
		{
			name:        "with special characters",
			displayName: "Test@Example#1",
			index:       2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1 := generateExampleID(tt.displayName, tt.index)
			id2 := generateExampleID(tt.displayName, tt.index)

			// IDs should be unique (contain timestamp)
			if id1 == id2 {
				t.Error("generateExampleID() should generate unique IDs")
			}

			// IDs should not be empty
			if id1 == "" {
				t.Error("generateExampleID() should not return empty string")
			}

			// IDs should start with "example-"
			if !strings.HasPrefix(id1, "example-") {
				t.Errorf("generateExampleID() = %v, should start with 'example-'", id1)
			}
		})
	}
}

func TestGenerateMockEmbedding(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{
			name: "simple text",
			text: "Hello world",
		},
		{
			name: "empty text",
			text: "",
		},
		{
			name: "long text",
			text: "This is a longer text that should still generate a proper embedding vector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedding := generateMockEmbedding(tt.text)

			// Check that embedding is not nil
			if embedding == nil {
				t.Error("generateMockEmbedding() returned nil")
			}

			// Check expected length
			expectedLength := 768
			if len(embedding) != expectedLength {
				t.Errorf("generateMockEmbedding() returned length %d, want %d", len(embedding), expectedLength)
			}

			// Check that values are in reasonable range [0, 1]
			for i, val := range embedding {
				if val < 0 || val > 1 {
					t.Errorf("embedding[%d] = %f, should be in range [0, 1]", i, val)
				}
			}

			// Different texts should produce different embeddings
			if tt.text != "" {
				differentEmbedding := generateMockEmbedding(tt.text + " different")
				if cmp.Equal(embedding, differentEmbedding) {
					t.Error("Different texts should produce different embeddings")
				}
			}
		})
	}
}
