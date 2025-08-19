// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"sync"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/internal/xiter"
	"github.com/go-a2a/adk-go/types"
)

// GeminiConnection implements [types.ModelConnection] for Google [Gemini] models.
type GeminiConnection struct {
	model      string
	client     *genai.Client
	history    []*genai.Content
	responseCh chan *types.LLMResponse
	mu         sync.Mutex
	closed     bool

	session *genai.Session
	logger  *slog.Logger
}

var _ types.ModelConnection = (*GeminiConnection)(nil)

// newGeminiConnection creates a new [GeminiConnection].
func newGeminiConnection(ctx context.Context, model string, client *genai.Client, request *types.LLMRequest) (*GeminiConnection, error) {
	conn := &GeminiConnection{
		logger:     slog.Default(),
		model:      model,
		client:     client,
		responseCh: make(chan *types.LLMResponse, 10), // Buffer for responses
	}

	session, err := client.Live.Connect(ctx, model, &genai.LiveConnectConfig{
		SystemInstruction: request.Config.SystemInstruction,
	})
	if err != nil {
		return nil, err
	}
	conn.session = session

	return conn, nil
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

// buildFullTextResponse Builds a full text response.
//
// The text should not partial and the returned LlmResponse is not be
// partial.
func (c *GeminiConnection) buildFullTextResponse(text string) *types.LLMResponse {
	return &types.LLMResponse{
		Content: genai.NewContentFromText(text, genai.Role(RoleModel)),
	}
}

// Receive returns a channel that yields model responses.
func (c *GeminiConnection) Receive(ctx context.Context) iter.Seq2[*types.LLMResponse, error] {
	c.mu.Lock()
	defer c.mu.Unlock()

	text := ""
	return func(yield func(*types.LLMResponse, error) bool) {
		message, err := c.session.Receive()
		if err != nil {
			xiter.EndError[*types.LLMResponse](err)
			return
		}
		c.logger.DebugContext(ctx, "get LLM Live message", slog.Any("message", message))

		if message.ServerContent != nil {
			content := message.ServerContent.ModelTurn
			if content != nil && len(content.Parts) > 0 {
				llmResponse := &types.LLMResponse{
					Content:     content,
					Interrupted: message.ServerContent.Interrupted,
				}

				if content.Parts[0].Text != "" {
					text += content.Parts[0].Text
					llmResponse.Partial = true
					// don't yield the merged text event when receiving audio data
				} else if text == "" && content.Parts[0].InlineData != nil {
					if !yield(c.buildFullTextResponse(text), nil) {
						return
					}
					text = ""
				}
				if !yield(llmResponse, nil) {
					return
				}
			}

			if inputTranscription := message.ServerContent.InputTranscription; inputTranscription != nil && inputTranscription.Text != "" {
				userText := inputTranscription.Text
				llmResponse := &types.LLMResponse{
					Content: genai.NewContentFromText(userText, genai.Role(RoleUser)),
				}
				if !yield(llmResponse, nil) {
					return
				}
			}

			if outputTranscription := message.ServerContent.OutputTranscription; outputTranscription != nil && outputTranscription.Text != "" {
				// TODO(adk-python): Right now, we just support output_transcription without
				// changing interface and data protocol. Later, we can consider to
				// support output_transcription as a separate field in LlmResponse.

				// Transcription is always considered as partial event
				// We rely on other control signals to determine when to yield the
				// full text response(turn_complete, interrupted, or tool_call).
				text += outputTranscription.Text
				llmResponse := &types.LLMResponse{
					Content: genai.NewContentFromText(outputTranscription.Text, genai.Role(RoleModel)),
				}
				if !yield(llmResponse, nil) {
					return
				}
			}

			if message.ServerContent.TurnComplete {
				if text != "" {
					if !yield(c.buildFullTextResponse(text), nil) {
						return
					}
					text = ""
				}
				if !yield(&types.LLMResponse{
					TurnComplete: true,
					Interrupted:  message.ServerContent.Interrupted,
				}, nil) {
					return
				}
				return
			}

			// in case of empty content or parts, we sill surface it
			// in case it's an interrupted message, we merge the previous partial
			// text. Other we don't merge. because content can be none when model
			// safety threshold is triggered
			if message.ServerContent.Interrupted && text != "" {
				if !yield(c.buildFullTextResponse(text), nil) {
					return
				}
				text = ""
				if !yield(&types.LLMResponse{
					Interrupted: message.ServerContent.Interrupted,
				}, nil) {
					return
				}
			}
		}

		if message.ToolCall != nil {
			if text != "" {
				if !yield(c.buildFullTextResponse(text), nil) {
					return
				}
				text = ""

				parts := make([]*genai.Part, len(message.ToolCall.FunctionCalls))
				for i, funcCall := range message.ToolCall.FunctionCalls {
					parts[i] = &genai.Part{
						FunctionCall: funcCall,
					}
				}
				if !yield(&types.LLMResponse{
					Content: genai.NewContentFromParts(parts, genai.Role(RoleModel)),
				}, nil) {
					return
				}
			}
		}
	}
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
