// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/types"
)

// CodeExecutor defines an interface for executing code.
type CodeExecutor interface {
	// Execute executes the given code in the specified language and returns the result.
	Execute(ctx context.Context, code string, language string) (string, error)
}

// CodeExecutionFlow is a flow that executes code blocks in responses.
type CodeExecutionFlow struct {
	*LLMFlow
	executor CodeExecutor
}

var _ Flow = (*CodeExecutionFlow)(nil)

// NewCodeExecutionFlow creates a new CodeExecutionFlow with the given model, executor, and options.
func NewCodeExecutionFlow(model model.Model, executor CodeExecutor, opts ...FlowOption) (*CodeExecutionFlow, error) {
	if executor == nil {
		return nil, fmt.Errorf("executor cannot be nil")
	}

	base, err := NewLLMFlow(model, opts...)
	if err != nil {
		return nil, err
	}

	return &CodeExecutionFlow{
		LLMFlow:  base,
		executor: executor,
	}, nil
}

// Process implements [Flow].
func (f *CodeExecutionFlow) Process(ctx context.Context, input any) (any, error) {
	contents, ok := input.([]*genai.Content)
	if !ok {
		return nil, fmt.Errorf("input must be a slice of genai.Content, got %T", input)
	}

	// First, get a response from the model
	resp, err := f.ProcessContent(ctx, contents)
	if err != nil {
		return nil, err
	}

	// Extract and execute code blocks
	return f.executeCodeBlocks(ctx, resp)
}

// extractCodeBlocks extracts code blocks from text using a regexp.
func (f *CodeExecutionFlow) extractCodeBlocks(text string) []struct {
	language string
	code     string
} {
	// This regex matches Markdown code blocks: ```language\ncode\n```
	re := regexp.MustCompile("```([a-zA-Z0-9_]+)?\n([\\s\\S]*?)\n```")
	matches := re.FindAllStringSubmatch(text, -1)

	var blocks []struct {
		language string
		code     string
	}

	for _, match := range matches {
		if len(match) >= 3 {
			blocks = append(blocks, struct {
				language string
				code     string
			}{
				language: match[1],
				code:     match[2],
			})
		}
	}

	return blocks
}

// executeCodeBlocks extracts and executes code blocks from the response.
func (f *CodeExecutionFlow) executeCodeBlocks(ctx context.Context, resp *types.LLMResponse) (*types.LLMResponse, error) {
	if resp == nil || resp.Content == nil {
		return resp, nil
	}

	// Process each text part
	for _, part := range resp.Content.Parts {
		if part.Text != "" {
			// Extract code blocks
			blocks := f.extractCodeBlocks(part.Text)

			for _, block := range blocks {
				if block.language == "" {
					continue // Skip blocks without a language
				}

				// Execute the code
				output, err := f.executor.Execute(ctx, block.code, block.language)
				if err != nil {
					f.logger.WarnContext(ctx, "code execution failed",
						slog.String("language", block.language),
						slog.Any("err", err),
					)

					// Add execution result
					resp.Content.Parts = append(resp.Content.Parts, &genai.Part{
						CodeExecutionResult: &genai.CodeExecutionResult{
							Outcome: genai.OutcomeFailed,
							Output:  fmt.Sprintf("Error: %v", err),
						},
					})
				} else {
					// Add execution result
					resp.Content.Parts = append(resp.Content.Parts, &genai.Part{
						CodeExecutionResult: &genai.CodeExecutionResult{
							Output:  output,
							Outcome: genai.OutcomeOK,
						},
					})
				}
			}
		}
	}

	return resp, nil
}
