// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"google.golang.org/genai"
)

// Model represents a generative AI model.
type Model interface {
	// Name returns the name of the model.
	Name() string

	// Connect creates a live connection to the model.
	Connect() (BaseLLMConnection, error)

	// Generate generates content from the model.
	Generate(ctx context.Context, request GenerateRequest) (*GenerateResponse, error)

	// GenerateContent generates content from the model.
	GenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error)
}

// GenerateRequest represents a request to generate content.
type GenerateRequest struct {
	// Content is the content to generate from.
	Content []*genai.Content

	// GenerationConfig is the configuration for generation.
	GenerationConfig *genai.GenerationConfig

	// SafetySettings are the safety settings for generation.
	SafetySettings []*genai.SafetySetting
}

// GenerateResponse represents a response from generating content.
type GenerateResponse struct {
	// Content is the generated content.
	Content *genai.GenerateContentResponse
}

// GenerativeModel represents a generative AI model.
type GenerativeModel interface {
	Model

	// StreamGenerate streams generated content from the model.
	StreamGenerate(ctx context.Context, request GenerateRequest) (GenerateStreamResponse, error)

	// StreamGenerateContent streams generated content from the model.
	StreamGenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (GenerateStreamResponse, error)

	// WithGenerationConfig returns a new model with the specified generation config.
	WithGenerationConfig(config *genai.GenerationConfig) GenerativeModel

	// WithSafetySettings returns a new model with the specified safety settings.
	WithSafetySettings(settings []*genai.SafetySetting) GenerativeModel
}

// GenerateStreamResponse represents a stream of generated content.
type GenerateStreamResponse interface {
	// Next returns the next response in the stream.
	Next() (*genai.GenerateContentResponse, error)
}

// BaseGenerativeModel provides a base implementation of GenerativeModel.
type BaseGenerativeModel struct {
	*BaseLLM
}

var _ GenerativeModel = (*BaseGenerativeModel)(nil)

// NewBaseGenerativeModel creates a new base generative model.
func NewBaseGenerativeModel(name string, client *genai.Client) *BaseGenerativeModel {
	return &BaseGenerativeModel{
		BaseLLM: NewBaseLLM(name, client),
	}
}

// WithGenerationConfig returns a new model with the specified generation config.
func (m *BaseGenerativeModel) WithGenerationConfig(config *genai.GenerationConfig) GenerativeModel {
	clone := *m
	clone.BaseLLM = m.BaseLLM.WithGenerationConfig(config)
	return &clone
}

// WithSafetySettings returns a new model with the specified safety settings.
func (m *BaseGenerativeModel) WithSafetySettings(settings []*genai.SafetySetting) GenerativeModel {
	clone := *m
	clone.BaseLLM = m.BaseLLM.WithSafetySettings(settings)
	return &clone
}

// Generate generates content from the model.
func (m *BaseGenerativeModel) Generate(ctx context.Context, request GenerateRequest) (*GenerateResponse, error) {
	return m.BaseLLM.Generate(ctx, request)
}

// GenerateContent generates content from the model.
func (m *BaseGenerativeModel) GenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error) {
	return m.BaseLLM.GenerateContent(ctx, contents, config)
}

// StreamGenerate streams generated content from the model.
func (m *BaseGenerativeModel) StreamGenerate(ctx context.Context, request GenerateRequest) (GenerateStreamResponse, error) {
	return m.BaseLLM.StreamGenerate(ctx, request)
}

// StreamGenerateContent streams generated content from the model.
func (m *BaseGenerativeModel) StreamGenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (GenerateStreamResponse, error) {
	return m.BaseLLM.StreamGenerateContent(ctx, contents, config)
}
