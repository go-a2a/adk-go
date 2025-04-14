// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package models

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/api/option"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/observability"
)

// Vision-specific utilities for Gemini models

// ImageProcessor provides functionality to process images with Gemini models
type ImageProcessor struct {
	client      *genai.Client
	geminiModel *genai.Model
	modelID     string
}

// NewImageProcessor creates a new image processor using Gemini's multimodal capabilities
func NewImageProcessor(ctx context.Context, modelID string, apiKey string) (*ImageProcessor, error) {
	if modelID == "" {
		// Use a vision-capable model
		modelID = "gemini-1.5-pro"
	}

	var cc genai.ClientConfig
	if apiKey != "" {
		cc.APIKey = apiKey
	}
	var clientOpts []option.ClientOption
	if apiKey != "" {
		clientOpts = append(clientOpts, option.WithAPIKey(apiKey))
	}

	client, err := genai.NewClient(ctx, &cc)
	if err != nil {
		return nil, fmt.Errorf("failed to create genai client: %w", err)
	}

	// Create the model with appropriate settings
	model := client.GenerativeModel(modelID)
	model.SafetySettings = []*genai.SafetySetting{
		{
			Category:  genai.HarmCategoryHateSpeech,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategoryDangerousContent,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategoryHarassment,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategorySexuallyExplicit,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategoryCivicIntegrity,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
	}

	return &ImageProcessor{
		client:      client,
		geminiModel: model,
		modelID:     modelID,
	}, nil
}

// AnalyzeImageFromURL processes an image from a URL with the image processor
func (p *ImageProcessor) AnalyzeImageFromURL(ctx context.Context, imageURL, prompt string) (string, error) {
	ctx, span := observability.Tracer("github.com/go-a2a/adk-go/pkg/model/models.ImageProcessor").Start(ctx, "ImageProcessor.AnalyzeImageFromURL",
		trace.WithAttributes(
			attribute.String("image_url", imageURL),
			attribute.String("model_id", p.modelID),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Analyzing image with Gemini",
		slog.String("url", imageURL),
		slog.String("model", p.modelID),
	)

	// Fetch the image data
	imgData, err := fetchImageFromURL(ctx, imageURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch image: %w", err)
	}

	// Create the full prompt with the image
	var parts []genai.Part
	parts = append(parts, genai.Part{
		InlineData: &genai.Blob{
			MIMEType: "image/jpeg",
			Data:     imgData,
		},
	})
	if prompt != "" {
		parts = append(parts, genai.Part{
			Text: genai.Text(prompt),
		})
	} else {
		// Default prompt if none provided
		parts = append(parts, genai.Text("Describe this image in detail. If it shows a product, identify it and suggest its likely uses."))
	}

	// Send the prompt to the model
	resp, err := p.geminiModel.GenerateContent(ctx, parts...)
	if err != nil {
		return "", fmt.Errorf("generating content failed: %w", err)
	}

	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return "", fmt.Errorf("no response from model")
	}

	// Check for safety or other errors
	if resp.Candidates[0].FinishReason == genai.FinishReasonSafety {
		return "", fmt.Errorf("content blocked for safety reasons")
	}

	// Extract the text response
	var result string
	for _, part := range resp.Candidates[0].Content.Parts {
		if text, ok := part.(genai.Text); ok {
			result += string(text)
		}
	}

	return result, nil
}

// AnalyzeImageFromFile processes an image from a local file with the image processor
func (p *ImageProcessor) AnalyzeImageFromFile(ctx context.Context, filePath, prompt string) (string, error) {
	ctx, span := observability.Tracer().Start(ctx, "ImageProcessor.AnalyzeImageFromFile",
		trace.WithAttributes(
			observability.KeyString("file_path", filePath),
			observability.KeyString("model_id", p.modelID),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Analyzing image file with Gemini",
		slog.String("file", filePath),
		slog.String("model", p.modelID),
	)

	// Read the file
	imgData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read image file: %w", err)
	}

	// Create the full prompt with the image
	var parts []genai.Part
	parts = append(parts, genai.ImageData("image/jpeg", imgData))
	if prompt != "" {
		parts = append(parts, genai.Text(prompt))
	} else {
		// Default prompt if none provided
		parts = append(parts, genai.Text("Describe this image in detail. If it shows a product, identify it and suggest its likely uses."))
	}

	// Send the prompt to the model
	resp, err := p.geminiModel.GenerateContent(ctx, parts...)
	if err != nil {
		return "", fmt.Errorf("generating content failed: %w", err)
	}

	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return "", fmt.Errorf("no response from model")
	}

	// Extract the text response
	var result string
	for _, part := range resp.Candidates[0].Content.Parts {
		if text, ok := part.(genai.Text); ok {
			result += string(text)
		}
	}

	return result, nil
}

// ProcessConversationWithImage processes a conversation that includes an image
func (p *ImageProcessor) ProcessConversationWithImage(ctx context.Context, messages []message.Message, imageURL, prompt string) (message.Message, error) {
	ctx, span := observability.Tracer().Start(ctx, "ImageProcessor.ProcessConversationWithImage")
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Processing conversation with image",
		slog.String("url", imageURL),
		slog.Int("num_messages", len(messages)),
	)

	// Fetch the image data
	imgData, err := fetchImageFromURL(ctx, imageURL)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to fetch image: %w", err)
	}

	// Convert messages to genai format
	contents, err := convertMessagesToGenAI(messages)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to convert messages: %w", err)
	}

	// Add the image to the last user message
	if len(contents) > 0 {
		// Find the last user message
		lastUserIdx := -1
		for i := len(contents) - 1; i >= 0; i-- {
			if contents[i].Role == "user" {
				lastUserIdx = i
				break
			}
		}

		if lastUserIdx >= 0 {
			// Add the image to this message
			contents[lastUserIdx].Parts = append([]genai.Part{genai.ImageData("image/jpeg", imgData)}, contents[lastUserIdx].Parts...)
		} else {
			// Create a new user message with the image
			userContent := &genai.Content{
				Role: "user",
				Parts: []genai.Part{
					genai.ImageData("image/jpeg", imgData),
				},
			}
			if prompt != "" {
				userContent.Parts = append(userContent.Parts, genai.Text(prompt))
			}
			contents = append(contents, userContent)
		}
	} else {
		// Create a new conversation with just the image
		userContent := &genai.Content{
			Role: "user",
			Parts: []genai.Part{
				genai.ImageData("image/jpeg", imgData),
			},
		}
		if prompt != "" {
			userContent.Parts = append(userContent.Parts, genai.Text(prompt))
		}
		contents = append(contents, userContent)
	}

	// Send the conversation to the model
	resp, err := p.geminiModel.GenerateContent(ctx, contents...)
	if err != nil {
		return message.Message{}, fmt.Errorf("generating content failed: %w", err)
	}

	// Convert the response to a message
	respMsg, err := convertGenAIResponseToMessage(resp)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to convert response: %w", err)
	}

	return respMsg, nil
}

// Close closes the client connection
func (p *ImageProcessor) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

// Helper function to fetch an image from a URL
func fetchImageFromURL(ctx context.Context, url string) ([]byte, error) {
	// Create a request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Execute the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching image: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the image data
	imgData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading image data: %w", err)
	}

	return imgData, nil
}
