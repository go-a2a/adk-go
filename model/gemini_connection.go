// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"iter"
	"sync"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// GeminiConnection implements [BaseConnection] for Google [Gemini] models.
type GeminiConnection struct {
	model      string
	client     *genai.Client
	history    []*genai.Content
	responseCh chan *types.LLMResponse
	mu         sync.Mutex
	closed     bool
}

var _ BaseConnection = (*GeminiConnection)(nil)

// newGeminiConnection creates a new [GeminiConnection].
func newGeminiConnection(model string, client *genai.Client) *GeminiConnection {
	return &GeminiConnection{
		model:      model,
		client:     client,
		history:    []*genai.Content{},
		responseCh: make(chan *types.LLMResponse, 10), // Buffer for responses
	}
}

// SendHistory sends the conversation history to the model.
func (c *GeminiConnection) SendHistory(ctx context.Context, history []*genai.Content) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection is closed")
	}

	// Store the history
	c.history = make([]*genai.Content, len(history))
	copy(c.history, history)

	// Check if the last message is from the user
	if len(history) > 0 && history[len(history)-1].Role == RoleUser {
		// Start generating in a goroutine
		go c.startGenerating(ctx)
	}

	return nil
}

// SendContent sends a user content to the model.
func (c *GeminiConnection) SendContent(ctx context.Context, content *genai.Content) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection is closed")
	}

	// Add the content to history
	c.history = append(c.history, content)

	// If it's a user message, start generating
	if content.Role == "user" {
		go c.startGenerating(ctx)
	}

	return nil
}

// SendRealtime sends a chunk of audio or a frame of video to the model in realtime.
// Note: Gemini API may not directly support realtime streaming for all content types.
// This method provides a placeholder implementation.
func (c *GeminiConnection) SendRealtime(ctx context.Context, blob []byte, mimeType string) error {
	// Not all Gemini models support direct realtime streaming
	// This is a simplified implementation
	return fmt.Errorf("realtime streaming not implemented for Gemini models")
}

// Receive returns a channel that yields model responses.
func (c *GeminiConnection) Receive(ctx context.Context) (<-chan *types.LLMResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, fmt.Errorf("connection is closed")
	}

	return c.responseCh, nil
}

// Close terminates the connection to the model.
func (c *GeminiConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil // Already closed
	}

	c.closed = true
	close(c.responseCh)
	return nil
}

// startGenerating starts generating content based on the history.
func (c *GeminiConnection) startGenerating(ctx context.Context) {
	// Create a copy of the history to avoid data races
	history := make([]*genai.Content, len(c.history))
	copy(history, c.history)

	// Get access to the Models service
	models := c.client.Models

	// Stream generate content from the model
	stream := models.GenerateContentStream(ctx, c.model, history, nil)

	// Process the stream
	c.processStream(ctx, stream)
}

// processStream processes the content stream and sends responses through the channel.
func (c *GeminiConnection) processStream(_ context.Context, stream iter.Seq2[*genai.GenerateContentResponse, error]) {
	// Type assert the stream to get access to HasNext and Next methods
	// We use a type assertion pattern that works with the genai iterator without directly importing it

	for resp, err := range stream {
		if err != nil {
			c.sendErrorResponse(err)
			return
		}

		// Convert genai response to LLMResponse
		llmResp := types.CreateLLMResponse(resp)

		// Mark as partial (not the end of the stream)
		llmResp.WithPartial(true)

		// Send to channel if not closed
		c.mu.Lock()
		if !c.closed {
			c.responseCh <- llmResp
		}
		c.mu.Unlock()
	}

	// Send a final response with TurnComplete set to true
	finalResp := &types.LLMResponse{}
	finalResp.WithTurnComplete(true)
	finalResp.WithPartial(false)

	c.mu.Lock()
	if !c.closed {
		c.responseCh <- finalResp
	}
	c.mu.Unlock()
}

// sendErrorResponse sends an error response through the channel.
func (c *GeminiConnection) sendErrorResponse(err error) {
	resp := &types.LLMResponse{}
	resp.ErrorCode = "GENERATION_ERROR"
	resp.ErrorMessage = err.Error()

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.responseCh <- resp
	}
}
