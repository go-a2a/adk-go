// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"iter"
	"os"
	"strings"
	"sync"

	"google.golang.org/genai"
)

// GeminiLLM represents a Google Gemini Large Language Model.
type GeminiLLM struct {
	*BaseLLM
	apiClient       *genai.Client
	apiClientOnce   sync.Once
	apiClientError  error
	trackingHeaders map[string]string
}

var _ GenerativeModel = (*GeminiLLM)(nil)

// NewGeminiLLM creates a new Gemini LLM instance.
func NewGeminiLLM(ctx context.Context, apiKey string, modelName string) (*GeminiLLM, error) {
	// Use default model if none provided
	if modelName == "" {
		modelName = "gemini-1.5-pro"
	}

	// Create genai client for BaseLLM
	genaiClient, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create genai client: %w", err)
	}

	return &GeminiLLM{
		BaseLLM:         NewBaseLLM(modelName, genaiClient),
		trackingHeaders: make(map[string]string),
	}, nil
}

// SupportedModels returns a list of supported Gemini models.
func (m *GeminiLLM) SupportedModels() []string {
	return []string{
		"gemini-1.0-pro",
		"gemini-1.5-pro",
		"gemini-1.5-flash",
	}
}

// Connect creates a live connection to the Gemini LLM.
func (m *GeminiLLM) Connect() (BaseLLMConnection, error) {
	// Ensure we have an API client
	apiClient, err := m.getAPIClient()
	if err != nil {
		return nil, err
	}

	// Create and return a new connection
	return newGeminiLLMConnection(m.model, apiClient), nil
}

// getAPIClient returns a cached API client.
func (m *GeminiLLM) getAPIClient() (*genai.Client, error) {
	m.apiClientOnce.Do(func() {
		apiKey := os.Getenv("GOOGLE_API_KEY")
		if apiKey == "" {
			m.apiClientError = fmt.Errorf("GOOGLE_API_KEY environment variable not set")
			return
		}

		ctx := context.Background()
		client, err := genai.NewClient(ctx, &genai.ClientConfig{
			APIKey: apiKey,
		})
		if err != nil {
			m.apiClientError = fmt.Errorf("failed to create genai client: %w", err)
			return
		}

		m.apiClient = client
	})

	return m.apiClient, m.apiClientError
}

// maybeAppendUserContent checks if the last message is from the user and if not, appends an empty user message.
func (m *GeminiLLM) maybeAppendUserContent(contents []*genai.Content) []*genai.Content {
	if len(contents) == 0 {
		return []*genai.Content{{
			Role:  "user",
			Parts: []*genai.Part{},
		}}
	}

	lastContent := contents[len(contents)-1]
	if strings.ToLower(lastContent.Role) != "user" {
		return append(contents, &genai.Content{
			Role:  "user",
			Parts: []*genai.Part{},
		})
	}

	return contents
}

// Generate generates content from the model.
func (m *GeminiLLM) Generate(ctx context.Context, request GenerateRequest) (*GenerateResponse, error) {
	// Ensure we have an API client
	apiClient, err := m.getAPIClient()
	if err != nil {
		return nil, err
	}

	// Get access to the Models service
	models := apiClient.Models

	// Create config for generate content
	config := &genai.GenerateContentConfig{}

	// Apply generation config if provided
	if request.GenerationConfig != nil {
		config.Temperature = request.GenerationConfig.Temperature
		config.MaxOutputTokens = request.GenerationConfig.MaxOutputTokens
		config.TopP = request.GenerationConfig.TopP
		config.TopK = request.GenerationConfig.TopK
	}

	// Apply safety settings if provided
	if request.SafetySettings != nil && len(request.SafetySettings) > 0 {
		config.SafetySettings = request.SafetySettings
	}

	// Ensure the last message is from the user
	contents := m.maybeAppendUserContent(request.Content)

	// Generate content
	resp, err := models.GenerateContent(ctx, m.model, contents, config)
	if err != nil {
		return nil, fmt.Errorf("gemini API error: %w", err)
	}

	return &GenerateResponse{
		Content: resp,
	}, nil
}

// GenerateContent generates content from the model.
func (m *GeminiLLM) GenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error) {
	// Ensure we have an API client
	apiClient, err := m.getAPIClient()
	if err != nil {
		return nil, err
	}

	// Get access to the Models service
	models := apiClient.Models

	// Create generate content config
	genConfig := &genai.GenerateContentConfig{}

	// Apply generation config if provided
	if config != nil {
		genConfig.MaxOutputTokens = config.MaxOutputTokens
		genConfig.Temperature = config.Temperature
		genConfig.TopP = config.TopP
		genConfig.TopK = config.TopK
	}

	// Ensure the last message is from the user
	contents = m.maybeAppendUserContent(contents)

	// Generate content
	return models.GenerateContent(ctx, m.model, contents, genConfig)
}

// StreamGenerate streams generated content from the model.
func (m *GeminiLLM) StreamGenerate(ctx context.Context, request GenerateRequest) (GenerateStreamResponse, error) {
	// Ensure we have an API client
	apiClient, err := m.getAPIClient()
	if err != nil {
		return nil, err
	}

	// Get access to the Models service
	models := apiClient.Models

	// Create config for generate content
	config := &genai.GenerateContentConfig{}

	// Apply generation config if provided
	if request.GenerationConfig != nil {
		config.Temperature = request.GenerationConfig.Temperature
		config.MaxOutputTokens = request.GenerationConfig.MaxOutputTokens
		config.TopP = request.GenerationConfig.TopP
		config.TopK = request.GenerationConfig.TopK
	}

	// Apply safety settings if provided
	if request.SafetySettings != nil && len(request.SafetySettings) > 0 {
		config.SafetySettings = request.SafetySettings
	}

	// Ensure the last message is from the user
	contents := m.maybeAppendUserContent(request.Content)

	// Stream generate content
	iterResponse := models.GenerateContentStream(ctx, m.model, contents, config)

	return &geminiStreamResponse{
		itr: iterResponse,
	}, nil
}

// StreamGenerateContent streams generated content from the model.
func (m *GeminiLLM) StreamGenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (GenerateStreamResponse, error) {
	// Ensure we have an API client
	apiClient, err := m.getAPIClient()
	if err != nil {
		return nil, err
	}

	// Get access to the Models service
	models := apiClient.Models

	// Create generate content config
	genConfig := &genai.GenerateContentConfig{}

	// Apply generation config if provided
	if config != nil {
		genConfig.MaxOutputTokens = config.MaxOutputTokens
		genConfig.Temperature = config.Temperature
		genConfig.TopP = config.TopP
		genConfig.TopK = config.TopK
	}

	// Ensure the last message is from the user
	contents = m.maybeAppendUserContent(contents)

	// Stream generate content
	iterResponse := models.GenerateContentStream(ctx, m.model, contents, genConfig)
	// if err != nil {
	// 	return nil, fmt.Errorf("gemini API error: %w", err)
	// }

	return &geminiStreamResponse{
		itr: iterResponse,
	}, nil
}

// WithGenerationConfig returns a new model with the specified generation config.
func (m *GeminiLLM) WithGenerationConfig(config *genai.GenerationConfig) GenerativeModel {
	// Create a new instance to avoid modifying the original
	clone := &GeminiLLM{
		BaseLLM:         m.BaseLLM.WithGenerationConfig(config),
		apiClient:       m.apiClient,
		trackingHeaders: m.trackingHeaders,
	}
	return clone
}

// WithSafetySettings returns a new model with the specified safety settings.
func (m *GeminiLLM) WithSafetySettings(settings []*genai.SafetySetting) GenerativeModel {
	// Create a new instance to avoid modifying the original
	clone := &GeminiLLM{
		BaseLLM:         m.BaseLLM.WithSafetySettings(settings),
		apiClient:       m.apiClient,
		trackingHeaders: m.trackingHeaders,
	}
	return clone
}

// geminiStreamResponse implements GenerateStreamResponse for Gemini models.
type geminiStreamResponse struct {
	itr iter.Seq2[*genai.GenerateContentResponse, error]
}

// Next returns the next response in the stream.
func (s *geminiStreamResponse) Next() (*genai.GenerateContentResponse, error) {
	// Type assert the stream to get access to HasNext and Next methods
	iter := s.itr
	if !iter.HasNext() {
		return nil, nil // End of stream
	}

	resp, err := iter.Next()
	if err != nil {
		return nil, err
	}

	return resp, nil
}
