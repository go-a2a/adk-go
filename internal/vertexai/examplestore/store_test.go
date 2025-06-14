// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package examplestore

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStoreConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *StoreConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &StoreConfig{
				EmbeddingModel: "text-embedding-005",
				DisplayName:    "Test Store",
				Description:    "Test description",
			},
			wantErr: false,
		},
		{
			name: "empty display name",
			config: &StoreConfig{
				EmbeddingModel: "text-embedding-005",
				DisplayName:    "",
				Description:    "Test description",
			},
			wantErr: true,
		},
		{
			name: "invalid embedding model",
			config: &StoreConfig{
				EmbeddingModel: "invalid-model",
				DisplayName:    "Test Store",
				Description:    "Test description",
			},
			wantErr: true,
		},
		{
			name: "empty embedding model defaults to valid",
			config: &StoreConfig{
				EmbeddingModel: "",
				DisplayName:    "Test Store",
				Description:    "Test description",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// If no error and embedding model was empty, check it was set to default
			if err == nil && tt.config.EmbeddingModel == "" {
				t.Errorf("Empty embedding model should be set to default")
			}
		})
	}
}

func TestStoreService_CreateStore(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	tests := []struct {
		name    string
		req     *CreateStoreRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: &CreateStoreRequest{
				Parent: "projects/test-project/locations/us-central1",
				Store: &Store{
					DisplayName: "Test Store",
					Description: "Test description",
					Config: &StoreConfig{
						EmbeddingModel: "text-embedding-005",
						DisplayName:    "Test Store",
						Description:    "Test description",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid config",
			req: &CreateStoreRequest{
				Parent: "projects/test-project/locations/us-central1",
				Store: &Store{
					DisplayName: "", // Invalid: empty display name
					Description: "Test description",
					Config: &StoreConfig{
						EmbeddingModel: "text-embedding-005",
						DisplayName:    "", // Invalid: empty display name
						Description:    "Test description",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := storeService.CreateStore(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreService.CreateStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if store == nil {
					t.Error("StoreService.CreateStore() returned nil store")
					return
				}

				if store.DisplayName != tt.req.Store.DisplayName {
					t.Errorf("Store.DisplayName = %v, want %v", store.DisplayName, tt.req.Store.DisplayName)
				}

				if store.State != StoreStateCreating {
					t.Errorf("Store.State = %v, want %v", store.State, StoreStateCreating)
				}

				if store.CreateTime == nil {
					t.Error("Store.CreateTime should not be nil")
				}

				if store.UpdateTime == nil {
					t.Error("Store.UpdateTime should not be nil")
				}
			}
		})
	}
}

func TestStoreService_ListStores(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	req := &ListStoresRequest{
		Parent:   "projects/test-project/locations/us-central1",
		PageSize: 10,
	}

	resp, err := storeService.ListStores(ctx, req)
	if err != nil {
		t.Errorf("StoreService.ListStores() error = %v", err)
		return
	}

	if resp == nil {
		t.Error("StoreService.ListStores() returned nil response")
		return
	}

	// Mock implementation returns empty list
	if len(resp.Stores) != 0 {
		t.Errorf("StoreService.ListStores() returned %d stores, expected 0 for mock", len(resp.Stores))
	}
}

func TestStoreService_GetStore(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"
	req := &GetStoreRequest{
		Name: storeName,
	}

	store, err := storeService.GetStore(ctx, req)
	if err != nil {
		t.Errorf("StoreService.GetStore() error = %v", err)
		return
	}

	if store == nil {
		t.Error("StoreService.GetStore() returned nil store")
		return
	}

	if store.Name != storeName {
		t.Errorf("Store.Name = %v, want %v", store.Name, storeName)
	}

	if store.State != StoreStateActive {
		t.Errorf("Store.State = %v, want %v", store.State, StoreStateActive)
	}
}

func TestStoreService_DeleteStore(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	req := &DeleteStoreRequest{
		Name:  "projects/test-project/locations/us-central1/exampleStores/test-store",
		Force: true,
	}

	err = storeService.DeleteStore(ctx, req)
	if err != nil {
		t.Errorf("StoreService.DeleteStore() error = %v", err)
	}
}

func TestStoreService_GetStoreStats(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"

	stats, err := storeService.GetStoreStats(ctx, storeName)
	if err != nil {
		t.Errorf("StoreService.GetStoreStats() error = %v", err)
		return
	}

	if stats == nil {
		t.Error("StoreService.GetStoreStats() returned nil stats")
		return
	}

	// Check that required fields are present
	if stats.LastExampleUpload == nil {
		t.Error("StoreStats.LastExampleUpload should not be nil")
	}

	if stats.MetadataKeys == nil {
		t.Error("StoreStats.MetadataKeys should not be nil")
	}
}

func TestStoreService_UpdateStore(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	originalTime := time.Now().Add(-time.Hour)
	store := &Store{
		Name:        "projects/test-project/locations/us-central1/exampleStores/test-store",
		DisplayName: "Original Name",
		Description: "Original Description",
		UpdateTime:  &originalTime,
	}

	updateMask := []string{"display_name", "description"}

	updatedStore, err := storeService.UpdateStore(ctx, store, updateMask)
	if err != nil {
		t.Errorf("StoreService.UpdateStore() error = %v", err)
		return
	}

	if updatedStore == nil {
		t.Error("StoreService.UpdateStore() returned nil store")
		return
	}

	// Check that update time was updated
	if updatedStore.UpdateTime.Before(originalTime) {
		t.Error("Store.UpdateTime should have been updated")
	}
}

func TestStoreService_WaitForStoreCreation(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	storeName := "projects/test-project/locations/us-central1/exampleStores/test-store"
	timeout := 5 * time.Second

	// This will return immediately since mock GetStore returns ACTIVE state
	store, err := storeService.WaitForStoreCreation(ctx, storeName, timeout)
	if err != nil {
		t.Errorf("StoreService.WaitForStoreCreation() error = %v", err)
		return
	}

	if store == nil {
		t.Error("StoreService.WaitForStoreCreation() returned nil store")
		return
	}

	if store.State != StoreStateActive {
		t.Errorf("Store.State = %v, want %v", store.State, StoreStateActive)
	}
}

func TestStoreService_ListAllStores(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", SupportedRegion)
	if err != nil {
		t.Skipf("Skipping test due to credential error: %v", err)
	}
	defer service.Close()

	storeService := service.storeService

	parent := "projects/test-project/locations/us-central1"

	stores, err := storeService.ListAllStores(ctx, parent)
	if err != nil {
		t.Errorf("StoreService.ListAllStores() error = %v", err)
		return
	}

	// stores can be an empty slice, but should not be nil
	if stores == nil {
		t.Error("StoreService.ListAllStores() returned nil stores")
		return
	}

	// Mock implementation returns empty list
	if len(stores) != 0 {
		t.Errorf("StoreService.ListAllStores() returned %d stores, expected 0 for mock", len(stores))
	}
}

func TestGenerateStoreID(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
	}{
		{
			name:        "simple name",
			displayName: "Test Store",
		},
		{
			name:        "empty name",
			displayName: "",
		},
		{
			name:        "name with special characters",
			displayName: "Test Store @#$%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1 := generateStoreID(tt.displayName)
			time.Sleep(1 * time.Millisecond) // Small delay to ensure different timestamps
			id2 := generateStoreID(tt.displayName)

			// IDs should be unique (contain timestamp)
			if id1 == id2 {
				t.Error("generateStoreID() should generate unique IDs")
			}

			// IDs should not be empty
			if id1 == "" {
				t.Error("generateStoreID() should not return empty string")
			}

			// IDs should start with "store-"
			if !strings.HasPrefix(id1, "store-") {
				t.Errorf("generateStoreID() = %v, should start with 'store-'", id1)
			}
		})
	}
}
