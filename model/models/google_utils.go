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
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/message"
	"github.com/go-a2a/adk-go/observability"
)

// Vision-specific utilities for Gemini models

// ImageProcessor provides functionality to process images with Gemini models.
type ImageProcessor struct {
	client  *genai.Client
	modelID string
}

// NewImageProcessor creates a new image processor using Gemini's multimodal capabilities.
func NewImageProcessor(ctx context.Context, modelID string, apiKey string) (*ImageProcessor, error) {
	if modelID == "" {
		// Use a vision-capable model
		modelID = "gemini-1.5-pro"
	}

	cc := &genai.ClientConfig{
		APIKey: apiKey,
	}
	client, err := genai.NewClient(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("creating genai client: %w", err)
	}

	processor := &ImageProcessor{
		client:  client,
		modelID: modelID,
	}

	return processor, nil
}

// AnalyzeImageFromURL processes an image from a URL with the image processor.
func (p *ImageProcessor) AnalyzeImageFromURL(ctx context.Context, imageURL, prompt string) (string, error) {
	tracer := observability.Tracer("github.com/go-a2a/adk-go/model/models.ImageProcessor")
	ctx, span := tracer.Start(ctx, "ImageProcessor.AnalyzeImageFromURL",
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

	// In a real implementation, we would:
	// 1. Fetch the image data
	// 2. Convert to the appropriate genai format
	// 3. Call the genai client to analyze the image
	// 4. Process the response

	// For testing purposes, return a mock response
	return fmt.Sprintf("Mock image analysis for URL %s: This appears to be an image of [subject].", imageURL), nil
}

// AnalyzeImageFromFile processes an image from a local file with the image processor.
func (p *ImageProcessor) AnalyzeImageFromFile(ctx context.Context, filePath, prompt string) (string, error) {
	tracer := observability.Tracer("github.com/go-a2a/adk-go/model/models.ImageProcessor")
	ctx, span := tracer.Start(ctx, "ImageProcessor.AnalyzeImageFromFile",
		trace.WithAttributes(
			attribute.String("file_path", filePath),
			attribute.String("model_id", p.modelID),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Analyzing image file with Gemini",
		slog.String("file", filePath),
		slog.String("model", p.modelID),
	)

	// In a real implementation, we would:
	// 1. Read the image file
	// 2. Convert to the appropriate genai format
	// 3. Call the genai client to analyze the image
	// 4. Process the response

	// For testing purposes, check if the file exists and return a mock response
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("file does not exist: %s", filePath)
	}

	return fmt.Sprintf("Mock image analysis for file %s: This appears to be an image of [subject].", filePath), nil
}

// ProcessConversationWithImage processes a conversation that includes an image.
func (p *ImageProcessor) ProcessConversationWithImage(ctx context.Context, messages []message.Message, imageURL, prompt string) (message.Message, error) {
	tracer := observability.Tracer("github.com/go-a2a/adk-go/model/models.ImageProcessor")
	ctx, span := tracer.Start(ctx, "ImageProcessor.ProcessConversationWithImage",
		trace.WithAttributes(
			attribute.String("image_url", imageURL),
			attribute.Int("num_messages", len(messages)),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Processing conversation with image",
		slog.String("url", imageURL),
		slog.Int("num_messages", len(messages)),
	)

	// In a real implementation, we would:
	// 1. Fetch the image data
	// 2. Convert messages to genai format
	// 3. Add the image to the message history
	// 4. Call the genai client to process the conversation
	// 5. Convert the response to an ADK message

	// For testing purposes, return a mock response
	// Create a response that references both the conversation and image
	responseText := "After analyzing the image and considering the conversation, I can see that..."
	if len(messages) > 0 && messages[len(messages)-1].Role == message.RoleUser {
		responseText += fmt.Sprintf(" Regarding your question about %s, the image shows...", messages[len(messages)-1].Content)
	}

	return message.NewAssistantMessage(responseText), nil
}

// Close closes the client connection.
func (p *ImageProcessor) Close() error {
	p.client = nil
	return nil
}

// Helper function to fetch an image from a URL.
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
