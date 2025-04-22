// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"google.golang.org/genai"
)

// BaseLLMConnection defines the interface for a live model connection.
type BaseLLMConnection interface {
	// SendHistory sends the conversation history to the model.
	// The model will respond if the last content is from user, otherwise it will
	// wait for new user input before responding.
	SendHistory(ctx context.Context, history []*genai.Content) error

	// SendContent sends a user content to the model.
	// The model will respond immediately upon receiving the content.
	SendContent(ctx context.Context, content *genai.Content) error

	// SendRealtime sends a chunk of audio or a frame of video to the model in realtime.
	// The model may not respond immediately upon receiving the blob.
	SendRealtime(ctx context.Context, blob []byte, mimeType string) error

	// Receive returns a channel that yields model responses.
	// It should be called after SendHistory, SendContent, or SendRealtime.
	Receive(ctx context.Context) (<-chan *LLMResponse, error)

	// Close terminates the connection to the model.
	// The connection object should not be used after this call.
	Close() error
}
