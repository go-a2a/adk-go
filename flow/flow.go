// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package flow provides interfaces and implementations for processing content through LLMs.
package flow

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// Flow represents the basic interface that all flows must implement.
type Flow interface {
	// Process processes the input and returns a result.
	Process(ctx context.Context, input any) (any, error)

	// ProcessContent processes the given contents through the LLM.
	ProcessContent(ctx context.Context, contents []*genai.Content) (*types.LLMResponse, error)
}

// FlowOption configures a flow.
type FlowOption interface {
	apply(any) error
}

// optionFunc is a function that implements FlowOption.
type optionFunc func(any) error

func (f optionFunc) apply(target any) error {
	return f(target)
}

// WithLogger returns an option that sets the logger for a flow.
func WithLogger(logger *slog.Logger) FlowOption {
	return optionFunc(func(target any) error {
		if flow, ok := target.(interface{ SetLogger(*slog.Logger) }); ok {
			flow.SetLogger(logger)
			return nil
		}
		return nil // Silently ignore if flow doesn't support SetLogger
	})
}

// WithSystemPrompt sets the system prompt for the flow.
func WithSingleFlowSystemPrompt(prompt string) FlowOption {
	return optionFunc(func(target any) error {
		if flow, ok := target.(*SingleFlow); ok {
			flow.systemPrompt = prompt
			return nil
		}
		return fmt.Errorf("option can only be applied to *SingleFlow, got %T", target)
	})
}
