// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package generativemodels

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/genai"
)

func TestNewService(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		projectID string
		location  string
		opts      []ServiceOption
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
			opts:      []ServiceOption{WithLogger(slog.Default())},
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
			service, err := NewService(ctx, tt.projectID, tt.location, tt.opts...)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if service == nil {
					t.Error("NewService() returned nil service")
					return
				}

				// Verify service configuration
				if got := service.GetProjectID(); got != tt.projectID {
					t.Errorf("GetProjectID() = %v, want %v", got, tt.projectID)
				}

				if got := service.GetLocation(); got != tt.location {
					t.Errorf("GetLocation() = %v, want %v", got, tt.location)
				}

				// Clean up
				if err := service.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			}
		})
	}
}

func TestService_GenerateContentWithPreview(t *testing.T) {
	ctx := context.Background()

	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	baseContents := []*genai.Content{
		{
			Parts: []*genai.Part{{Text: "What is machine learning?"}},
			Role:  "user",
		},
	}

	tests := []struct {
		name      string
		modelName string
		request   *PreviewGenerateRequest
		wantErr   bool
	}{
		{
			name:      "basic preview request",
			modelName: "gemini-2.0-flash-001",
			request: &PreviewGenerateRequest{
				Contents: baseContents,
			},
			wantErr: false,
		},
		{
			name:      "with content caching",
			modelName: "gemini-2.0-flash-001",
			request: &PreviewGenerateRequest{
				Contents:        baseContents,
				UseContentCache: true,
				CacheID:         "projects/test-project/locations/us-central1/cachedContents/test-cache",
			},
			wantErr: false,
		},
		{
			name:      "with enhanced safety",
			modelName: "gemini-2.0-flash-001",
			request: &PreviewGenerateRequest{
				Contents: baseContents,
				EnhancedSafety: &SafetyConfig{
					StrictMode: true,
					CustomThresholds: map[string]string{
						"HARM_CATEGORY_HARASSMENT": "BLOCK_LOW_AND_ABOVE",
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "with experimental options",
			modelName: "gemini-2.0-flash-001",
			request: &PreviewGenerateRequest{
				Contents: baseContents,
				ExperimentalOpts: map[string]any{
					"temperature": 0.9,
					"top_p":       0.95,
				},
			},
			wantErr: false,
		},
		{
			name:      "nil request",
			modelName: "gemini-2.0-flash-001",
			request:   nil,
			wantErr:   true,
		},
		{
			name:      "nil base request",
			modelName: "gemini-2.0-flash-001",
			request: &PreviewGenerateRequest{
				Contents: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.GenerateContentWithPreview(ctx, tt.modelName, tt.request)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateContentWithPreview() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if response == nil {
					t.Error("GenerateContentWithPreview() returned nil response")
					return
				}

				// Verify response structure
				if response.Candidates == nil {
					t.Error("Response candidates are nil")
				}

				if response.ModelMetadata == nil {
					t.Error("ModelMetadata is nil")
				}

				// Verify content caching integration
				if tt.request.UseContentCache {
					if !response.CacheHit {
						t.Error("Expected cache hit but got false")
					}

					if response.CacheID != tt.request.CacheID {
						t.Errorf("Response CacheID = %v, want %v", response.CacheID, tt.request.CacheID)
					}
				}

				// Verify safety metadata
				if response.SafetyMetadata == nil {
					t.Error("SafetyMetadata is nil")
				}

				// Verify experimental metadata
				if tt.request.ExperimentalOpts != nil {
					if response.ExperimentalMetadata == nil {
						t.Error("ExperimentalMetadata is nil")
					}
				}
			}
		})
	}
}

func TestService_GenerateContentStreamWithPreview(t *testing.T) {
	ctx := context.Background()

	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	request := &PreviewGenerateRequest{
		Contents: []*genai.Content{
			{
				Parts: []*genai.Part{{Text: "Tell me a story"}},
				Role:  "user",
			},
		},
		UseContentCache: true,
		CacheID:         "projects/test-project/locations/us-central1/cachedContents/test-cache",
	}

	// Test streaming generation
	var responses []*PreviewGenerateResponse
	for response, err := range service.GenerateContentStreamWithPreview(ctx, "gemini-2.0-flash-001", request) {
		if err != nil {
			t.Errorf("Streaming error: %v", err)
			continue
		}

		if response == nil {
			t.Error("Received nil response in stream")
			continue
		}

		responses = append(responses, response)

		// Verify each streaming response
		if response.Candidates == nil {
			t.Error("Response candidates are nil in streaming response")
		}

		// Verify cache information is consistent across stream
		if response.CacheHit != request.UseContentCache {
			t.Errorf("CacheHit = %v, want %v", response.CacheHit, request.UseContentCache)
		}

		if response.CacheID != request.CacheID {
			t.Errorf("CacheID = %v, want %v", response.CacheID, request.CacheID)
		}
	}

	if len(responses) == 0 {
		t.Error("No streaming responses received")
	}

	// Verify final response has complete metadata
	if len(responses) > 0 {
		finalResponse := responses[len(responses)-1]
		if finalResponse.ModelMetadata == nil {
			t.Error("Final response missing ModelMetadata")
		}

		if finalResponse.ExperimentalMetadata == nil {
			t.Error("Final response missing ExperimentalMetadata")
		}
	}
}

func TestService_GenerateContentWithTools(t *testing.T) {
	ctx := context.Background()

	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	tools := []*genai.Tool{
		{
			FunctionDeclarations: []*genai.FunctionDeclaration{
				{
					Name:        "search_tool",
					Description: "Search for information",
					Parameters: &genai.Schema{
						Type: genai.TypeObject,
						Properties: map[string]*genai.Schema{
							"query": {Type: genai.TypeString},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name    string
		request *ToolGenerateRequest
		wantErr bool
	}{
		{
			name: "basic tool request",
			request: &ToolGenerateRequest{
				PreviewGenerateRequest: &PreviewGenerateRequest{
					Contents: []*genai.Content{
						{
							Parts: []*genai.Part{{Text: "Search for machine learning"}},
							Role:  "user",
						},
					},
				},
				Tools: tools,
			},
			wantErr: false,
		},
		{
			name: "with advanced tool config",
			request: &ToolGenerateRequest{
				PreviewGenerateRequest: &PreviewGenerateRequest{
					Contents: []*genai.Content{
						{
							Parts: []*genai.Part{{Text: "Search and calculate"}},
							Role:  "user",
						},
					},
					AdvancedToolConfig: &AdvancedToolConfig{
						ParallelCalling: true,
						MaxConcurrency:  3,
						TimeoutPerTool:  30 * time.Second,
					},
				},
				Tools: tools,
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			wantErr: true,
		},
		{
			name: "nil preview request",
			request: &ToolGenerateRequest{
				PreviewGenerateRequest: nil,
				Tools:                  tools,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.GenerateContentWithTools(ctx, "gemini-2.0-flash-001", tt.request)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateContentWithTools() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if response == nil {
					t.Error("GenerateContentWithTools() returned nil response")
					return
				}

				// Verify response structure
				if response.PreviewGenerateResponse == nil {
					t.Error("PreviewGenerateResponse is nil")
				}

				// Verify tool call information
				if len(response.ToolCalls) == 0 {
					t.Error("No tool calls in response")
				}

				if len(response.ToolResults) == 0 {
					t.Error("No tool results in response")
				}

				// Verify tool call metadata
				for _, toolCall := range response.ToolCalls {
					if toolCall.ToolName == "" {
						t.Error("Tool call missing tool name")
					}

					if toolCall.CallID == "" {
						t.Error("Tool call missing call ID")
					}

					if toolCall.StartTime.IsZero() {
						t.Error("Tool call missing start time")
					}
				}

				// Verify tool results
				for _, result := range response.ToolResults {
					if result.CallID == "" {
						t.Error("Tool result missing call ID")
					}

					if result.Result == nil {
						t.Error("Tool result missing result data")
					}
				}
			}
		})
	}
}

func TestService_CountTokensPreview(t *testing.T) {
	ctx := context.Background()

	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	contents := []*genai.Content{
		{
			Parts: []*genai.Part{{Text: "Hello, world!"}},
			Role:  "user",
		},
		{
			Parts: []*genai.Part{{Text: "This is a test message."}},
			Role:  "user",
		},
	}

	tests := []struct {
		name    string
		request *TokenCountRequest
		wantErr bool
	}{
		{
			name: "basic token count",
			request: &TokenCountRequest{
				Contents: contents,
				Model:    "gemini-2.0-flash-001",
			},
			wantErr: false,
		},
		{
			name: "with content caching",
			request: &TokenCountRequest{
				Contents:        contents,
				Model:           "gemini-2.0-flash-001",
				UseContentCache: true,
				CacheID:         "projects/test-project/locations/us-central1/cachedContents/test-cache",
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			request: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.CountTokensPreview(ctx, tt.request)

			if (err != nil) != tt.wantErr {
				t.Errorf("CountTokensPreview() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if response == nil {
					t.Error("CountTokensPreview() returned nil response")
					return
				}

				// Verify token counts
				if response.TotalTokens <= 0 {
					t.Error("TotalTokens should be greater than 0")
				}

				if response.BillableTokens <= 0 {
					t.Error("BillableTokens should be greater than 0")
				}

				// Verify content caching optimization
				if tt.request.UseContentCache {
					if response.CachedTokens <= 0 {
						t.Error("CachedTokens should be greater than 0 when using cache")
					}

					if response.BillableTokens >= response.TotalTokens {
						t.Error("BillableTokens should be less than TotalTokens when using cache")
					}
				} else {
					if response.CachedTokens != 0 {
						t.Error("CachedTokens should be 0 when not using cache")
					}

					if response.BillableTokens != response.TotalTokens {
						t.Error("BillableTokens should equal TotalTokens when not using cache")
					}
				}

				// Verify token breakdown
				if response.TokenBreakdown == nil {
					t.Error("TokenBreakdown is nil")
				} else {
					totalFromBreakdown := int32(0)
					for _, count := range response.TokenBreakdown {
						totalFromBreakdown += count
					}

					if totalFromBreakdown != response.TotalTokens {
						t.Errorf("Token breakdown sum (%v) != TotalTokens (%v)",
							totalFromBreakdown, response.TotalTokens)
					}
				}
			}
		})
	}
}

func TestService_GetSupportedModels(t *testing.T) {
	ctx := context.Background()

	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	models := service.GetSupportedModels()

	if len(models) == 0 {
		t.Error("GetSupportedModels() returned empty list")
	}

	expectedModels := []string{
		"gemini-2.0-flash-001",
		"gemini-2.0-pro-001",
		"gemini-2.0-flash-exp",
		"gemini-2.0-pro-exp",
	}

	if diff := cmp.Diff(expectedModels, models); diff != "" {
		t.Errorf("GetSupportedModels() mismatch (-want +got):\n%s", diff)
	}
}

func TestService_IsModelSupported(t *testing.T) {
	ctx := context.Background()

	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	tests := []struct {
		name      string
		modelName string
		want      bool
	}{
		{
			name:      "supported model",
			modelName: "gemini-2.0-flash-001",
			want:      true,
		},
		{
			name:      "unsupported model",
			modelName: "gemini-1.5-pro",
			want:      false,
		},
		{
			name:      "empty model name",
			modelName: "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := service.IsModelSupported(tt.modelName); got != tt.want {
				t.Errorf("IsModelSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Benchmark tests
func BenchmarkService_GenerateContentWithPreview(b *testing.B) {
	ctx := context.Background()

	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		b.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	request := &PreviewGenerateRequest{
		Contents: []*genai.Content{
			{
				Parts: []*genai.Part{{Text: "What is AI?"}},
				Role:  "user",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.GenerateContentWithPreview(ctx, "gemini-2.0-flash-001", request)
		if err != nil {
			b.Fatalf("GenerateContentWithPreview() error = %v", err)
		}
	}
}

// Example tests
func ExampleService_GenerateContentWithPreview() {
	ctx := context.Background()

	service, err := NewService(ctx, "my-project", "us-central1")
	if err != nil {
		panic(err)
	}
	defer service.Close()

	// Create a preview request with enhanced features
	request := &PreviewGenerateRequest{
		Contents: []*genai.Content{
			{
				Parts: []*genai.Part{{Text: "Explain quantum computing"}},
				Role:  "user",
			},
		},
		UseContentCache: true,
		CacheID:         "projects/my-project/locations/us-central1/cachedContents/my-cache",
		EnhancedSafety: &SafetyConfig{
			StrictMode: true,
		},
		ExperimentalOpts: map[string]any{
			"temperature": 0.7,
		},
	}

	// Generate content with preview features
	response, err := service.GenerateContentWithPreview(ctx, "gemini-2.0-flash-001", request)
	if err != nil {
		panic(err)
	}

	// Use the response
	_ = response
}
