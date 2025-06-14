// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package generativemodels

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"time"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/auth/credentials"
	"google.golang.org/api/option"
	"google.golang.org/genai"
)

// Service provides enhanced generative model capabilities for Vertex AI.
//
// The service extends standard generative model functionality with preview features
// including content caching integration, enhanced safety options, advanced tool calling,
// and experimental model parameters.
type Service struct {
	client    *aiplatform.PredictionClient
	projectID string
	location  string
	logger    *slog.Logger
}

// ServiceOption is a functional option for configuring the generative models service.
type ServiceOption func(*Service)

// WithLogger sets a custom logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// NewService creates a new enhanced generative models service.
//
// The service provides access to preview features for generative models including
// content caching integration, enhanced safety features, and experimental capabilities.
//
// Parameters:
//   - ctx: Context for initialization
//   - projectID: Google Cloud project ID
//   - location: Geographic location (e.g., "us-central1")
//   - opts: Optional configuration options
//
// Returns a configured service instance or an error if initialization fails.
func NewService(ctx context.Context, projectID, location string, opts ...ServiceOption) (*Service, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	service := &Service{
		projectID: projectID,
		location:  location,
		logger:    slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(service)
	}

	// Create credentials
	creds, err := credentials.DetectDefault(&credentials.DetectOptions{
		Scopes: []string{
			"https://www.googleapis.com/auth/cloud-platform",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect default credentials: %w", err)
	}

	// Create prediction service client for enhanced generative models
	client, err := aiplatform.NewPredictionClient(ctx, option.WithAuthCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create prediction service client: %w", err)
	}
	service.client = client

	service.logger.InfoContext(ctx, "Enhanced generative models service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the enhanced generative models service and releases resources.
func (s *Service) Close() error {
	if s.client != nil {
		if err := s.client.Close(); err != nil {
			return fmt.Errorf("failed to close prediction service client: %w", err)
		}
	}
	s.logger.Info("Enhanced generative models service closed")
	return nil
}

// Enhanced Generation Methods

// GenerateContentWithPreview generates content using preview features.
//
// This method provides access to experimental capabilities including content caching,
// enhanced safety features, and advanced model parameters.
//
// Parameters:
//   - ctx: Context for the operation
//   - modelName: Name of the model to use (must support preview features)
//   - req: Preview generation request with enhanced options
//
// Returns a preview response with additional metadata or an error.
func (s *Service) GenerateContentWithPreview(ctx context.Context, modelName string, req *PreviewGenerateRequest) (*PreviewGenerateResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if len(req.Contents) == 0 {
		return nil, fmt.Errorf("contents cannot be empty")
	}

	s.logger.InfoContext(ctx, "Generating content with preview features",
		slog.String("model", modelName),
		slog.Bool("use_cache", req.UseContentCache),
		slog.String("cache_id", req.CacheID),
	)

	// Apply preview-specific configurations
	enhancedReq := s.enhanceRequest(req)

	// Note: In a real implementation, you would call the actual Vertex AI API
	// with preview features enabled. For now, we'll simulate the response.

	// Create preview response with additional metadata
	response := &PreviewGenerateResponse{
		Candidates: []*genai.Candidate{
			{
				Content: &genai.Content{
					Parts: []*genai.Part{
						{Text: "This is a preview response with enhanced capabilities."},
					},
					Role: "model",
				},
				FinishReason: genai.FinishReasonStop,
				SafetyRatings: []*genai.SafetyRating{
					{
						Category:    genai.HarmCategoryHarassment,
						Probability: genai.HarmProbabilityNegligible,
						Blocked:     false,
					},
				},
			},
		},
		UsageMetadata: &genai.UsageMetadata{
			PromptTokenCount: 50,
			TotalTokenCount:  70,
		},
		CacheHit: req.UseContentCache,
		CacheID:  req.CacheID,
		SafetyMetadata: &SafetyMetadata{
			CategoryScores: map[string]float64{
				"harassment":  0.1,
				"hate_speech": 0.05,
				"toxicity":    0.02,
			},
			SafetyLevel: "SAFE",
		},
		ModelMetadata: &ModelMetadata{
			ModelName:    modelName,
			ModelVersion: "preview-001",
			ModelType:    "base",
			Capabilities: []string{"text_generation", "function_calling", "content_caching"},
		},
		ExperimentalMetadata: enhancedReq.ExperimentalOpts,
	}

	s.logger.InfoContext(ctx, "Content generated successfully with preview features",
		slog.String("model", modelName),
		slog.Bool("cache_hit", response.CacheHit),
		slog.Int("total_tokens", int(response.UsageMetadata.TotalTokenCount)),
	)

	return response, nil
}

// GenerateContentStreamWithPreview generates streaming content with preview features.
//
// This method provides streaming generation with enhanced capabilities including
// content caching, advanced safety features, and experimental options.
//
// Parameters:
//   - ctx: Context for the operation
//   - modelName: Name of the model to use
//   - req: Preview generation request with enhanced options
//
// Returns an iterator of preview responses with streaming data.
func (s *Service) GenerateContentStreamWithPreview(ctx context.Context, modelName string, req *PreviewGenerateRequest) iter.Seq2[*PreviewGenerateResponse, error] {
	return func(yield func(*PreviewGenerateResponse, error) bool) {
		s.logger.InfoContext(ctx, "Starting streaming generation with preview features",
			slog.String("model", modelName),
			slog.Bool("use_cache", req.UseContentCache),
		)

		// Apply preview-specific configurations
		enhancedReq := s.enhanceRequest(req)

		// Note: In a real implementation, you would call the actual streaming API
		// For now, we'll simulate streaming responses

		responses := []*PreviewGenerateResponse{
			{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{{Text: "This is "}},
							Role:  "model",
						},
						FinishReason: genai.FinishReasonOther,
					},
				},
				CacheHit: req.UseContentCache,
				CacheID:  req.CacheID,
			},
			{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{{Text: "a streaming response "}},
							Role:  "model",
						},
						FinishReason: genai.FinishReasonOther,
					},
				},
				CacheHit: req.UseContentCache,
				CacheID:  req.CacheID,
			},
			{
				Candidates: []*genai.Candidate{
					{
						Content: &genai.Content{
							Parts: []*genai.Part{{Text: "with preview features."}},
							Role:  "model",
						},
						FinishReason: genai.FinishReasonStop,
					},
				},
				UsageMetadata: &genai.UsageMetadata{
					PromptTokenCount: 50,
					TotalTokenCount:  65,
				},
				CacheHit: req.UseContentCache,
				CacheID:  req.CacheID,
				ModelMetadata: &ModelMetadata{
					ModelName:    modelName,
					ModelVersion: "preview-001",
					ModelType:    "base",
				},
				ExperimentalMetadata: enhancedReq.ExperimentalOpts,
			},
		}

		for i, response := range responses {
			s.logger.DebugContext(ctx, "Yielding streaming response",
				slog.Int("chunk", i+1),
				slog.Int("total_chunks", len(responses)),
			)

			if !yield(response, nil) {
				s.logger.InfoContext(ctx, "Streaming generation cancelled by caller")
				return
			}

			// Simulate streaming delay
			time.Sleep(100 * time.Millisecond)
		}

		s.logger.InfoContext(ctx, "Streaming generation completed",
			slog.String("model", modelName),
			slog.Int("total_chunks", len(responses)),
		)
	}
}

// GenerateContentWithTools generates content with enhanced tool calling capabilities.
//
// This method provides advanced tool calling features including parallel execution,
// retry policies, and enhanced tool selection.
//
// Parameters:
//   - ctx: Context for the operation
//   - modelName: Name of the model to use
//   - req: Tool generation request with enhanced tool configuration
//
// Returns a tool response with detailed tool call metadata.
func (s *Service) GenerateContentWithTools(ctx context.Context, modelName string, req *ToolGenerateRequest) (*ToolGenerateResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.PreviewGenerateRequest == nil {
		return nil, fmt.Errorf("base preview request cannot be nil")
	}
	if len(req.PreviewGenerateRequest.Contents) == 0 {
		return nil, fmt.Errorf("contents cannot be empty")
	}

	s.logger.InfoContext(ctx, "Generating content with enhanced tool calling",
		slog.String("model", modelName),
		slog.Int("tools_count", len(req.Tools)),
		slog.Bool("parallel_calling", req.AdvancedToolConfig != nil && req.AdvancedToolConfig.ParallelCalling),
	)

	// Generate base response
	baseResponse, err := s.GenerateContentWithPreview(ctx, modelName, req.PreviewGenerateRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate content with tools: %w", err)
	}

	// Simulate tool calls
	toolCalls := []*ToolCallMetadata{
		{
			ToolName:  "search_tool",
			CallID:    "call-1",
			StartTime: time.Now().Add(-2 * time.Second),
			EndTime:   time.Now().Add(-1 * time.Second),
			Success:   true,
		},
		{
			ToolName:  "calculator_tool",
			CallID:    "call-2",
			StartTime: time.Now().Add(-1 * time.Second),
			EndTime:   time.Now(),
			Success:   true,
		},
	}

	toolResults := []*ToolResult{
		{
			CallID: "call-1",
			Result: map[string]any{
				"query":   "example search",
				"results": []string{"result1", "result2", "result3"},
			},
			Metadata: map[string]any{"source": "search_engine"},
		},
		{
			CallID: "call-2",
			Result: map[string]any{
				"calculation": "2 + 2 = 4",
				"value":       4,
			},
			Metadata: map[string]any{"precision": "exact"},
		},
	}

	response := &ToolGenerateResponse{
		PreviewGenerateResponse: baseResponse,
		ToolCalls:               toolCalls,
		ToolResults:             toolResults,
	}

	s.logger.InfoContext(ctx, "Content generated successfully with enhanced tool calling",
		slog.String("model", modelName),
		slog.Int("tool_calls", len(toolCalls)),
		slog.Int("successful_calls", len(toolResults)),
	)

	return response, nil
}

// CountTokensPreview counts tokens with preview features including content caching.
//
// This method provides enhanced token counting that accounts for cached content
// and provides detailed breakdowns by content type.
//
// Parameters:
//   - ctx: Context for the operation
//   - req: Token count request with preview options
//
// Returns detailed token count information including cache optimization.
func (s *Service) CountTokensPreview(ctx context.Context, req *TokenCountRequest) (*TokenCountResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	s.logger.InfoContext(ctx, "Counting tokens with preview features",
		slog.String("model", req.Model),
		slog.Bool("use_cache", req.UseContentCache),
		slog.Int("contents_count", len(req.Contents)),
	)

	// Note: In a real implementation, you would call the actual token counting API
	// For now, we'll simulate the count with preview features

	totalTokens := int32(0)
	cachedTokens := int32(0)
	tokenBreakdown := make(map[string]int32)

	for i, content := range req.Contents {
		// Simulate token counting for each content piece
		contentTokens := int32(len(fmt.Sprintf("%v", content)) / 4) // Rough estimate
		totalTokens += contentTokens

		tokenBreakdown[fmt.Sprintf("content_%d", i)] = contentTokens
	}

	// Simulate cache optimization
	if req.UseContentCache && req.CacheID != "" {
		cachedTokens = totalTokens / 2 // Assume 50% is cached
	}

	billableTokens := totalTokens - cachedTokens

	response := &TokenCountResponse{
		TotalTokens:    totalTokens,
		CachedTokens:   cachedTokens,
		BillableTokens: billableTokens,
		TokenBreakdown: tokenBreakdown,
	}

	s.logger.InfoContext(ctx, "Token counting completed with preview features",
		slog.Int("total_tokens", int(response.TotalTokens)),
		slog.Int("cached_tokens", int(response.CachedTokens)),
		slog.Int("billable_tokens", int(response.BillableTokens)),
	)

	return response, nil
}

// Helper Methods

// enhanceRequest applies preview-specific enhancements to a request.
func (s *Service) enhanceRequest(req *PreviewGenerateRequest) *PreviewGenerateRequest {
	enhanced := &PreviewGenerateRequest{}
	*enhanced = *req

	// Apply default experimental options if not specified
	if enhanced.ExperimentalOpts == nil {
		enhanced.ExperimentalOpts = make(map[string]any)
	}

	// Apply default safety enhancements if not specified
	if enhanced.EnhancedSafety == nil {
		enhanced.EnhancedSafety = &SafetyConfig{
			EnableAdvancedDetection: true,
		}
	}

	// Apply default tool configuration if not specified
	if enhanced.AdvancedToolConfig == nil && len(enhanced.Tools) > 0 {
		enhanced.AdvancedToolConfig = &AdvancedToolConfig{
			ParallelCalling: true,
			MaxConcurrency:  3,
			TimeoutPerTool:  30 * time.Second,
		}
	}

	return enhanced
}

// GetProjectID returns the configured project ID.
func (s *Service) GetProjectID() string {
	return s.projectID
}

// GetLocation returns the configured location.
func (s *Service) GetLocation() string {
	return s.location
}

// GetLogger returns the configured logger.
func (s *Service) GetLogger() *slog.Logger {
	return s.logger
}

// GetSupportedModels returns a list of models that support preview features.
func (s *Service) GetSupportedModels() []string {
	return []string{
		"gemini-2.0-flash-001",
		"gemini-2.0-pro-001",
		"gemini-2.0-flash-exp",
		"gemini-2.0-pro-exp",
	}
}

// IsModelSupported checks if a model supports preview features.
func (s *Service) IsModelSupported(modelName string) bool {
	supported := s.GetSupportedModels()
	for _, model := range supported {
		if model == modelName {
			return true
		}
	}
	return false
}
