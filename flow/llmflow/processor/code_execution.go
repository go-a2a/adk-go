// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/go-a2a/adk-go/codeexecutor"
	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/flow"
	"github.com/go-a2a/adk-go/message"
)

// codeBlockRegex matches Markdown code blocks
var codeBlockRegex = regexp.MustCompile("```([a-zA-Z0-9]+)?\\s*([\\s\\S]*?)```")

// CodeExecutionRequestProcessor processes code execution in LLM requests.
type CodeExecutionRequestProcessor struct {
	executor codeexecutor.CodeExecutor
}

// NewCodeExecutionRequestProcessor creates a new CodeExecutionRequestProcessor.
func NewCodeExecutionRequestProcessor() *CodeExecutionRequestProcessor {
	// Default to unsafe local executor for now
	executor := codeexecutor.NewUnsafeLocalExecutor()
	return &CodeExecutionRequestProcessor{
		executor: executor,
	}
}

// SetExecutor sets the code executor to use.
func (p *CodeExecutionRequestProcessor) SetExecutor(executor codeexecutor.CodeExecutor) {
	p.executor = executor
}

// Run processes the LLM request and returns a channel of events.
func (p *CodeExecutionRequestProcessor) Run(ctx *flow.LlmFlowContext, request *flow.LlmRequest) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		slog.InfoContext(ctx.Context, "Processing code execution in LLM request")

		// Process code in the request
		// This is typically a no-op for requests, but could include
		// instructions or special handling for code execution
	}()

	return eventCh, nil
}

// CodeExecutionResponseProcessor processes code execution in LLM responses.
type CodeExecutionResponseProcessor struct {
	executor codeexecutor.CodeExecutor
}

// NewCodeExecutionResponseProcessor creates a new CodeExecutionResponseProcessor.
func NewCodeExecutionResponseProcessor() *CodeExecutionResponseProcessor {
	// Default to unsafe local executor for now
	executor := codeexecutor.NewUnsafeLocalExecutor()
	return &CodeExecutionResponseProcessor{
		executor: executor,
	}
}

// SetExecutor sets the code executor to use.
func (p *CodeExecutionResponseProcessor) SetExecutor(executor codeexecutor.CodeExecutor) {
	p.executor = executor
}

// Run processes the LLM response and returns a channel of events.
func (p *CodeExecutionResponseProcessor) Run(ctx *flow.LlmFlowContext, response *flow.LlmResponse) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		slog.InfoContext(ctx.Context, "Processing code execution in LLM response")

		// Extract code blocks from response
		for _, content := range response.Contents {
			if text, ok := content.Parts()[0].(string); ok {
				matches := codeBlockRegex.FindAllStringSubmatch(text, -1)
				for _, match := range matches {
					if len(match) >= 3 {
						language := strings.TrimSpace(match[1])
						code := strings.TrimSpace(match[2])

						// Execute the code if applicable
						if p.shouldExecuteCode(language) {
							result, err := p.executeCode(ctx, language, code)
							if err != nil {
								errorMessage := fmt.Sprintf("Code execution error: %v", err)
								eventCh <- event.NewMessageEvent(message.NewSystemContent(errorMessage))
								continue
							}

							// Create an event for the execution result
							resultContent := message.NewSystemContent(fmt.Sprintf("Code execution result:\n%s", result))
							eventCh <- event.NewMessageEvent(resultContent)
						}
					}
				}
			}
		}
	}()

	return eventCh, nil
}

// shouldExecuteCode determines if code in a given language should be executed.
func (p *CodeExecutionResponseProcessor) shouldExecuteCode(language string) bool {
	// List of languages that are safe to execute
	// This would need to be customized based on your security requirements
	supportedLanguages := map[string]bool{
		"python": true,
		"py":     true,
		"shell":  true,
		"bash":   true,
		"sh":     true,
	}

	return supportedLanguages[strings.ToLower(language)]
}

// executeCode executes code in the specified language and returns the result.
func (p *CodeExecutionResponseProcessor) executeCode(ctx *flow.LlmFlowContext, language, code string) (string, error) {
	// Map language to execution context
	var execContext *codeexecutor.ExecutorContext

	// For simplicity in this example
	if language == "python" || language == "py" {
		execContext = codeexecutor.NewExecutorContext("python", code)
	} else if language == "shell" || language == "bash" || language == "sh" {
		execContext = codeexecutor.NewExecutorContext("shell", code)
	} else {
		return "", fmt.Errorf("unsupported language: %s", language)
	}

	// Execute the code
	result, err := p.executor.Execute(ctx.Context, execContext)
	if err != nil {
		return "", err
	}

	return result.Output, nil
}
