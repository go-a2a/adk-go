// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package preview

import (
	"context"
	"log/slog"
	"testing"
)

func TestNewClient(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		projectID string
		location  string
		opts      []ClientOption
		wantErr   bool
	}{
		{
			name:      "valid configuration",
			projectID: "test-project",
			location:  "us-central1",
			opts:      nil,
			wantErr:   false,
		},
		{
			name:      "with custom logger",
			projectID: "test-project",
			location:  "us-central1",
			opts:      []ClientOption{WithLogger(slog.Default())},
			wantErr:   false,
		},
		{
			name:      "empty project ID",
			projectID: "",
			location:  "us-central1",
			opts:      nil,
			wantErr:   true,
		},
		{
			name:      "empty location",
			projectID: "test-project",
			location:  "",
			opts:      nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ctx, tt.projectID, tt.location, tt.opts...)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if client == nil {
					t.Error("NewClient() returned nil client")
					return
				}

				// Verify client configuration
				if got := client.GetProjectID(); got != tt.projectID {
					t.Errorf("GetProjectID() = %v, want %v", got, tt.projectID)
				}

				if got := client.GetLocation(); got != tt.location {
					t.Errorf("GetLocation() = %v, want %v", got, tt.location)
				}

				// Verify services are initialized
				if client.RAG() == nil {
					t.Error("RAG service not initialized")
				}

				if client.ContentCaching() == nil {
					t.Error("ContentCaching service not initialized")
				}

				if client.GenerativeModels() == nil {
					t.Error("GenerativeModels service not initialized")
				}

				if client.ModelGarden() == nil {
					t.Error("ModelGarden service not initialized")
				}

				// Clean up
				if err := client.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			}
		})
	}
}

func TestClient_HealthCheck(t *testing.T) {
	ctx := context.Background()

	client, err := NewClient(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if err := client.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
}

func TestClient_GetServiceStatus(t *testing.T) {
	ctx := context.Background()

	client, err := NewClient(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	status := client.GetServiceStatus()

	expectedServices := []string{"rag", "content_caching", "generative_models", "model_garden"}
	for _, service := range expectedServices {
		if _, ok := status[service]; !ok {
			t.Errorf("Service %s not found in status", service)
		}

		if status[service] != "initialized" {
			t.Errorf("Service %s status = %v, want initialized", service, status[service])
		}
	}
}

func TestClientOption_WithLogger(t *testing.T) {
	ctx := context.Background()
	customLogger := slog.Default()

	client, err := NewClient(ctx, "test-project", "us-central1", WithLogger(customLogger))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if got := client.GetLogger(); got != customLogger {
		t.Errorf("GetLogger() = %v, want %v", got, customLogger)
	}
}

func TestClient_ServiceAccess(t *testing.T) {
	ctx := context.Background()

	client, err := NewClient(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Test service access methods
	t.Run("RAG service", func(t *testing.T) {
		service := client.RAG()
		if service == nil {
			t.Error("RAG() returned nil")
		}

		// Verify the service has correct configuration
		if got := service.GetProjectID(); got != "test-project" {
			t.Errorf("RAG service project ID = %v, want test-project", got)
		}

		if got := service.GetLocation(); got != "us-central1" {
			t.Errorf("RAG service location = %v, want us-central1", got)
		}
	})

	t.Run("ContentCaching service", func(t *testing.T) {
		service := client.ContentCaching()
		if service == nil {
			t.Error("ContentCaching() returned nil")
		}

		// Verify the service has correct configuration
		if got := service.GetProjectID(); got != "test-project" {
			t.Errorf("ContentCaching service project ID = %v, want test-project", got)
		}

		if got := service.GetLocation(); got != "us-central1" {
			t.Errorf("ContentCaching service location = %v, want us-central1", got)
		}
	})

	t.Run("GenerativeModels service", func(t *testing.T) {
		service := client.GenerativeModels()
		if service == nil {
			t.Error("GenerativeModels() returned nil")
		}

		// Verify the service has correct configuration
		if got := service.GetProjectID(); got != "test-project" {
			t.Errorf("GenerativeModels service project ID = %v, want test-project", got)
		}

		if got := service.GetLocation(); got != "us-central1" {
			t.Errorf("GenerativeModels service location = %v, want us-central1", got)
		}
	})

	t.Run("ModelGarden service", func(t *testing.T) {
		service := client.ModelGarden()
		if service == nil {
			t.Error("ModelGarden() returned nil")
		}

		// Verify the service has correct configuration
		if got := service.GetProjectID(); got != "test-project" {
			t.Errorf("ModelGarden service project ID = %v, want test-project", got)
		}

		if got := service.GetLocation(); got != "us-central1" {
			t.Errorf("ModelGarden service location = %v, want us-central1", got)
		}
	})
}

func TestClient_Close(t *testing.T) {
	t.Skip()
	ctx := context.Background()

	client, err := NewClient(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test closing the client
	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Test multiple close calls (should not error)
	if err := client.Close(); err != nil {
		t.Errorf("Second Close() error = %v", err)
	}
}

// Benchmark tests for client operations
func BenchmarkNewClient(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		client, err := NewClient(ctx, "test-project", "us-central1")
		if err != nil {
			b.Fatalf("Failed to create client: %v", err)
		}
		client.Close()
	}
}

func BenchmarkClient_HealthCheck(b *testing.B) {
	ctx := context.Background()

	client, err := NewClient(ctx, "test-project", "us-central1")
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	b.ResetTimer()
	for b.Loop() {
		if err := client.HealthCheck(ctx); err != nil {
			b.Fatalf("HealthCheck() error = %v", err)
		}
	}
}

// Example tests demonstrating usage patterns
func ExampleNewClient() {
	ctx := context.Background()

	// Create a new preview client
	client, err := NewClient(ctx, "my-project", "us-central1")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	// Access individual services
	ragService := client.RAG()
	contentCacheService := client.ContentCaching()
	generativeService := client.GenerativeModels()
	modelGardenService := client.ModelGarden()

	// Use the services for various operations
	_ = ragService
	_ = contentCacheService
	_ = generativeService
	_ = modelGardenService

	// Perform health check
	if err := client.HealthCheck(ctx); err != nil {
		panic(err)
	}
}

func ExampleClient_GetServiceStatus() {
	ctx := context.Background()

	client, err := NewClient(ctx, "my-project", "us-central1")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	// Get service status
	status := client.GetServiceStatus()
	for service, state := range status {
		if state == "initialized" {
			continue // Service is ready
		}
		// Handle service not ready
		_ = service
	}
}
