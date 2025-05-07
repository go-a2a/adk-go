// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"fmt"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/types"
)

// BasicFlow is a simple implementation of LLMFlow that just passes content
// to the LLM and returns the response.
type BasicFlow struct {
	*LLMFlow
}

var _ Flow = (*BasicFlow)(nil)

// NewBasicFlow creates a new BasicFlow with the given model and options.
func NewBasicFlow(model model.Model, opts ...FlowOption) (*BasicFlow, error) {
	base, err := NewLLMFlow(model, opts...)
	if err != nil {
		return nil, err
	}

	return &BasicFlow{LLMFlow: base}, nil
}

// Process implements [Flow].
func (f *BasicFlow) Process(ctx context.Context, input any) (any, error) {
	contents, ok := input.([]*genai.Content)
	if !ok {
		return nil, fmt.Errorf("input must be a slice of genai.Content, got %T", input)
	}

	return f.ProcessContent(ctx, contents)
}

// ProcessWithSystemPrompt processes the given contents with a system prompt.
func (f *BasicFlow) ProcessWithSystemPrompt(ctx context.Context, prompt string, contents []*genai.Content) (*types.LLMResponse, error) {
	if prompt == "" {
		return f.ProcessContent(ctx, contents)
	}

	// Create a new slice with the system prompt
	newContents := make([]*genai.Content, 0, len(contents)+1)

	// Add system prompt
	newContents = append(newContents, &genai.Content{
		Role: "system",
		Parts: []*genai.Part{
			genai.NewPartFromText(prompt),
		},
	})

	// Add the rest of the contents
	newContents = append(newContents, contents...)

	return f.ProcessContent(ctx, newContents)
}
