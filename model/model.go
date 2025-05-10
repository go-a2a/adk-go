// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"iter"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// Role represents the role of a participant in a conversation.
type Role = string

const (
	// RoleSystem is the role of the system.
	RoleSystem Role = "system"

	// RoleAssistant is the role of the assistant.
	RoleAssistant Role = "assistant"

	// RoleUser is the role of the user.
	RoleUser Role = genai.RoleUser

	// RoleModel is the role of the model.
	RoleModel Role = genai.RoleModel
)

// UserContent creates a new user content.
func UserContent(texts ...string) *genai.Content {
	contentParts := make([]*genai.Part, len(texts))
	for i, part := range texts {
		contentParts[i] = &genai.Part{Text: part}
	}
	return &genai.Content{
		Role:  RoleUser,
		Parts: contentParts,
	}
}

// ModelContent creates a new model content.
func ModelContent(texts ...string) *genai.Content {
	contentParts := make([]*genai.Part, len(texts))
	for i, part := range texts {
		contentParts[i] = &genai.Part{Text: part}
	}
	return &genai.Content{
		Role:  RoleModel,
		Parts: contentParts,
	}
}

// BaseConnection defines the interface for a live model connection.
type BaseConnection interface {
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
	Receive(ctx context.Context) (<-chan *types.LLMResponse, error)

	// Close terminates the connection to the model.
	// The connection object should not be used after this call.
	Close() error
}

// Model represents a generative AI model.
type Model interface {
	// Name returns the name of the model.
	Name() string

	// Connect creates a live connection to the model.
	Connect() (BaseConnection, error)

	// GenerateContent generates content from the model.
	GenerateContent(ctx context.Context, request *types.LLMRequest) (*types.LLMResponse, error)

	// StreamGenerateContent streams generated content from the model.
	StreamGenerateContent(ctx context.Context, request *types.LLMRequest) iter.Seq2[*types.LLMResponse, error]
}

type NotImplementedError string

func (err NotImplementedError) Error() string {
	return string(err)
}

// BaseLLM represents a base LLM implementation.
type BaseLLM struct {
	*Config

	// Model represents the specific LLM model name.
	Model string
}

var _ Model = (*BaseLLM)(nil)

func (m *BaseLLM) Name() string {
	return m.Model
}

func (m *BaseLLM) Connect() (BaseConnection, error) {
	return nil, NotImplementedError(fmt.Sprintf("async generation is not supported for %s", m.Model))
}

func (m *BaseLLM) GenerateContent(ctx context.Context, request *types.LLMRequest) (*types.LLMResponse, error) {
}

func (m *BaseLLM) SupportedModels() []string {
	return []string{}
}
