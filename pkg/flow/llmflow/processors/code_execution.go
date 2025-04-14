// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processors

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// CodeExecutionRequestProcessor processes code execution in requests.
type CodeExecutionRequestProcessor struct {
	*RequestProcessor

	// EnableCodeExecution determines if code execution is enabled.
	EnableCodeExecution bool
}

// NewCodeExecutionRequestProcessor creates a new CodeExecutionRequestProcessor.
func NewCodeExecutionRequestProcessor() *CodeExecutionRequestProcessor {
	return &CodeExecutionRequestProcessor{
		RequestProcessor:    NewRequestProcessor("CodeExecutionRequestProcessor"),
		EnableCodeExecution: true, // Default to enabled
	}
}

// Process implements RequestProcessor.Process.
func (p *CodeExecutionRequestProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
) (<-chan *event.Event, error) {
	// Check if code execution is enabled
	if !p.EnableCodeExecution {
		// If disabled, add a note to the system message
		if req.System != "" {
			req.System += "\n\n"
		}
		req.System += "Code execution is disabled. You can provide code examples, " +
			"but they will not be executed automatically."
	} else {
		// If enabled, add instructions for code execution
		if req.System != "" {
			req.System += "\n\n"
		}
		req.System += "You can execute code by using markdown code blocks with a language tag. " +
			"The code will be executed and the results will be shown below the code."
	}

	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *CodeExecutionRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, req)
	return err
}

// CodeExecutionResponseProcessor processes code execution in responses.
type CodeExecutionResponseProcessor struct {
	*ResponseProcessor

	// EnableCodeExecution determines if code execution is enabled.
	EnableCodeExecution bool

	// CodeExecutor is the interface used to execute code.
	CodeExecutor CodeExecutor
}

// CodeExecutor defines the interface for code execution.
type CodeExecutor interface {
	// ExecuteCode executes the given code and returns the result.
	ExecuteCode(language, code string) (string, error)
}

// NewCodeExecutionResponseProcessor creates a new CodeExecutionResponseProcessor.
func NewCodeExecutionResponseProcessor() *CodeExecutionResponseProcessor {
	return &CodeExecutionResponseProcessor{
		ResponseProcessor:   NewResponseProcessor("CodeExecutionResponseProcessor"),
		EnableCodeExecution: true, // Default to enabled
		CodeExecutor:        nil,  // Will need to be set if used
	}
}

// Process implements ResponseProcessor.Process.
func (p *CodeExecutionResponseProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	resp *flow.LLMResponse,
) (<-chan *event.Event, error) {
	// Return immediately if code execution is disabled or no executor is set
	if !p.EnableCodeExecution || p.CodeExecutor == nil {
		ch := make(chan *event.Event)
		close(ch)
		return ch, nil
	}

	// Find all code blocks in the response
	codeBlocks := extractCodeBlocks(resp.Content)
	if len(codeBlocks) == 0 {
		// No code blocks to execute
		ch := make(chan *event.Event)
		close(ch)
		return ch, nil
	}

	// Execute each code block and append results
	modifiedContent := resp.Content
	for _, block := range codeBlocks {
		// Execute the code
		result, err := p.CodeExecutor.ExecuteCode(block.language, block.code)

		// Format the result
		executionResult := "<code_execution_result>\n"
		if err != nil {
			executionResult += fmt.Sprintf("Error: %s\n", err.Error())
		} else {
			executionResult += result + "\n"
		}
		executionResult += "</code_execution_result>"

		// Append the result after the code block
		blockWithResult := block.original + "\n\n" + executionResult
		modifiedContent = strings.Replace(modifiedContent, block.original, blockWithResult, 1)
	}

	// Update the response content with the executed code
	resp.Content = modifiedContent

	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements ResponseProcessor.ProcessLive.
func (p *CodeExecutionResponseProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	resp *flow.LLMResponse,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, resp)
	return err
}

// CodeBlock represents a code block found in text.
type CodeBlock struct {
	// original is the original code block text including delimiters.
	original string

	// language is the programming language of the code block.
	language string

	// code is the code within the code block.
	code string
}

// extractCodeBlocks extracts all code blocks from the given text.
func extractCodeBlocks(text string) []CodeBlock {
	var blocks []CodeBlock

	// Regular expression to find code blocks with language
	// ```language
	// code
	// ```
	regex := regexp.MustCompile("```([a-zA-Z0-9]+)\\s*\\n([\\s\\S]*?)\\n```")
	matches := regex.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			blocks = append(blocks, CodeBlock{
				original: match[0],
				language: match[1],
				code:     match[2],
			})
		}
	}

	// Also look for generic code blocks without language
	// ```
	// code
	// ```
	genericRegex := regexp.MustCompile("```\\s*\\n([\\s\\S]*?)\\n```")
	genericMatches := genericRegex.FindAllStringSubmatch(text, -1)

	for _, match := range genericMatches {
		if len(match) >= 2 {
			// Check if this block is already captured by the language-specific regex
			isDuplicate := false
			for _, block := range blocks {
				if block.original == match[0] {
					isDuplicate = true
					break
				}
			}

			if !isDuplicate {
				blocks = append(blocks, CodeBlock{
					original: match[0],
					language: "", // No language specified
					code:     match[1],
				})
			}
		}
	}

	return blocks
}
