// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package vertexai

import (
	"log/slog"
	"testing"

	nooptrace "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewClient(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name      string
		projectID string
		location  string
		opts      []option.ClientOption
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
			opts:      []option.ClientOption{WithTracerProvider(nooptrace.NewTracerProvider())},
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

				if client.Cache() == nil {
					t.Error("ContentCaching service not initialized")
				}

				if client.GenerativeModel() == nil {
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
	ctx := t.Context()

	client, err := NewClient(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if err := client.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
}

type slogOption struct {
	*internaloption.EmbeddableAdapter
	*slog.Logger
}

func (o slogOption) apply(c *Client) {
	c.logger = o.Logger
}

// withLogger sets the [*slog.Logger] for the client.
//
// This function for the testing.
func withLogger(logger *slog.Logger) option.ClientOption {
	return slogOption{Logger: logger}
}

func TestClient_GetServiceStatus(t *testing.T) {
	ctx := t.Context()

	client, err := NewClient(ctx, "test-project", "us-central1", withLogger(slog.Default()))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	client.logger = slog.Default()

	status := client.GetServiceStatus()

	expectedServices := []string{
		"cache",
		"example_store",
		"generative_model",
		"model_garden",
		"extension",
		"prompt",
		"rag",
		"evaluation",
		"reasoning_engine",
		"tuning",
	}
	for _, service := range expectedServices {
		if _, ok := status[service]; !ok {
			t.Errorf("Service %s not found in status", service)
		}

		if status[service] != "initialized" {
			t.Errorf("Service %s status = %v, want initialized", service, status[service])
		}
	}
}

func TestClient_ServiceAccess(t *testing.T) {
	ctx := t.Context()

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
		service := client.Cache()
		if service == nil {
			t.Error("ContentCaching() returned nil")
		}
	})

	t.Run("GenerativeModels service", func(t *testing.T) {
		service := client.GenerativeModel()
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
	})
}

func TestClient_Close(t *testing.T) {
	ctx := t.Context()

	client, err := NewClient(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test closing the client
	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Test multiple close calls (should not error)
	if err := client.Close(); status.Convert(err).Code() != codes.Canceled {
		t.Errorf("Second Close() error = %v", err)
	}
}

// Benchmark tests for client operations
func BenchmarkNewClient(b *testing.B) {
	ctx := b.Context()

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
	ctx := b.Context()

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
