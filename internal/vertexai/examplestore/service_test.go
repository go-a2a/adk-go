// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"context"
	"fmt"
	"testing"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name      string
		projectID string
		location  string
		wantErr   bool
	}{
		{
			name:      "valid parameters",
			projectID: "test-project",
			location:  SupportedRegion,
			wantErr:   false,
		},
		{
			name:      "empty project ID",
			projectID: "",
			location:  SupportedRegion,
			wantErr:   true,
		},
		{
			name:      "empty location",
			projectID: "test-project",
			location:  "",
			wantErr:   true,
		},
		{
			name:      "unsupported location",
			projectID: "test-project",
			location:  "us-west1",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Note: This test will fail if credentials are not available
			// In a real test environment, you might want to mock the client
			service, err := NewService(ctx, tt.projectID, tt.location)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewService() expected error, got nil")
				}
				return
			}

			if err != nil {
				// Skip test if credentials are not available
				t.Skipf("Skipping test due to credential error: %v", err)
				return
			}

			defer func() {
				if closeErr := service.Close(); closeErr != nil {
					t.Errorf("Failed to close service: %v", closeErr)
				}
			}()

			if service.GetProjectID() != tt.projectID {
				t.Errorf("GetProjectID() = %v, want %v", service.GetProjectID(), tt.projectID)
			}

			if service.GetLocation() != tt.location {
				t.Errorf("GetLocation() = %v, want %v", service.GetLocation(), tt.location)
			}
		})
	}
}

func TestService_GenerateStoreName(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	tests := []struct {
		name    string
		storeID string
		want    string
	}{
		{
			name:    "simple store ID",
			storeID: "my-store",
			want:    "projects/test-project/locations/us-central1/exampleStores/my-store",
		},
		{
			name:    "store ID with numbers",
			storeID: "store-123",
			want:    "projects/test-project/locations/us-central1/exampleStores/store-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.GenerateStoreName(tt.storeID)
			if got != tt.want {
				t.Errorf("GenerateStoreName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_GenerateExampleName(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	tests := []struct {
		name      string
		storeID   string
		exampleID string
		want      string
	}{
		{
			name:      "simple IDs",
			storeID:   "my-store",
			exampleID: "example-1",
			want:      "projects/test-project/locations/us-central1/exampleStores/my-store/examples/example-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.GenerateExampleName(tt.storeID, tt.exampleID)
			if got != tt.want {
				t.Errorf("GenerateExampleName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_HealthCheck(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	if err := service.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
}

func TestService_GetServiceStatus(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	status := service.GetServiceStatus()

	expectedServices := []string{
		"store_service",
		"example_service",
		"search_service",
		"rag_data_client",
	}

	for _, serviceName := range expectedServices {
		if status[serviceName] != "initialized" {
			t.Errorf("Service %s status = %v, want %v", serviceName, status[serviceName], "initialized")
		}
	}
}

func TestService_CreateDefaultStore(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	displayName := "Test Default Store"
	description := "Test description"

	store, err := service.CreateDefaultStore(ctx, displayName, description)
	if err != nil {
		t.Errorf("CreateDefaultStore() error = %v", err)
		return
	}

	if store.DisplayName != displayName {
		t.Errorf("Store.DisplayName = %v, want %v", store.DisplayName, displayName)
	}

	if store.Description != description {
		t.Errorf("Store.Description = %v, want %v", store.Description, description)
	}

	if store.Config.EmbeddingModel != DefaultEmbeddingModel {
		t.Errorf("Store.Config.EmbeddingModel = %v, want %v", store.Config.EmbeddingModel, DefaultEmbeddingModel)
	}

	if store.State != StoreStateCreating {
		t.Errorf("Store.State = %v, want %v", store.State, StoreStateCreating)
	}
}

func TestService_BatchUploadExamples(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeName := service.GenerateStoreName("test-store")

	// Create 12 examples to test batching (should be split into 3 batches of 5, 5, 2)
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

	results, err := service.BatchUploadExamples(ctx, storeName, examples)
	if err != nil {
		t.Errorf("BatchUploadExamples() error = %v", err)
		return
	}

	if len(results) != len(examples) {
		t.Errorf("BatchUploadExamples() returned %d results, want %d", len(results), len(examples))
	}

	// Verify each result
	for i, result := range results {
		if result.DisplayName != examples[i].DisplayName {
			t.Errorf("Result %d DisplayName = %v, want %v", i, result.DisplayName, examples[i].DisplayName)
		}
	}
}

func TestService_QuickSearch(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeName := service.GenerateStoreName("test-store")
	queryText := "capital of France"

	results, err := service.QuickSearch(ctx, storeName, queryText)
	if err != nil {
		t.Errorf("QuickSearch() error = %v", err)
		return
	}

	// Should return some mock results
	if len(results) == 0 {
		t.Error("QuickSearch() returned no results")
	}

	// Verify results are sorted by similarity score
	for i := 1; i < len(results); i++ {
		if results[i-1].SimilarityScore < results[i].SimilarityScore {
			t.Errorf("Results not sorted by similarity score: %f < %f at positions %d, %d",
				results[i-1].SimilarityScore, results[i].SimilarityScore, i-1, i)
		}
	}
}

func TestValidateExamples(t *testing.T) {
	tests := []struct {
		name     string
		examples []*Example
		wantErr  bool
	}{
		{
			name:     "empty examples",
			examples: []*Example{},
			wantErr:  true,
		},
		{
			name:     "too many examples",
			examples: make([]*Example, MaxExamplesPerUpload+1),
			wantErr:  true,
		},
		{
			name: "valid examples",
			examples: []*Example{
				{
					Input:  &Content{Text: "Input 1"},
					Output: &Content{Text: "Output 1"},
				},
				{
					Input:  &Content{Text: "Input 2"},
					Output: &Content{Text: "Output 2"},
				},
			},
			wantErr: false,
		},
		{
			name: "example with nil input",
			examples: []*Example{
				{
					Input:  nil,
					Output: &Content{Text: "Output 1"},
				},
			},
			wantErr: true,
		},
		{
			name: "example with empty input text",
			examples: []*Example{
				{
					Input:  &Content{Text: ""},
					Output: &Content{Text: "Output 1"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExamples(tt.examples)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExamples() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
