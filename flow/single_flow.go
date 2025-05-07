// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"fmt"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
)

// SingleFlow is a flow that transforms a single text input into a content list
// and processes it through an LLM.
type SingleFlow struct {
	*LLMFlow
	systemPrompt string
}

var _ Flow = (*SingleFlow)(nil)

// NewSingleFlow creates a new SingleFlow with the given model and options.
func NewSingleFlow(model model.Model, opts ...FlowOption) (*SingleFlow, error) {
	base, err := NewLLMFlow(model, opts...)
	if err != nil {
		return nil, err
	}

	flow := &SingleFlow{
		LLMFlow:      base,
		systemPrompt: "",
	}

	// Apply options
	for _, opt := range opts {
		if err := opt.apply(flow); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return flow, nil
}

// Process implements [Flow].
func (f *SingleFlow) Process(ctx context.Context, input any) (any, error) {
	// Convert input to string
	var text string
	switch v := input.(type) {
	case string:
		text = v
	case []byte:
		text = string(v)
	default:
		return nil, fmt.Errorf("input must be a string or []byte, got %T", input)
	}

	// Create content list
	var contents []*genai.Content

	// Add system prompt if provided
	if f.systemPrompt != "" {
		contents = append(contents, &genai.Content{
			Role: "system",
			Parts: []*genai.Part{
				genai.NewPartFromText(f.systemPrompt),
			},
		})
	}

	// Add user content
	contents = append(contents, &genai.Content{
		Role: "user",
		Parts: []*genai.Part{
			genai.NewPartFromText(text),
		},
	})

	return f.ProcessContent(ctx, contents)
}
