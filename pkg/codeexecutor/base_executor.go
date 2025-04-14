// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package codeexecutor

import (
	"context"
	"fmt"
)

// BaseCodeExecutor provides the base implementation for code executors.
type BaseCodeExecutor struct {
	OptimizeDataFile        bool                       // Whether to extract/process data files
	Stateful                bool                       // Whether the executor maintains state between executions
	ErrorRetryAttempts      int                        // Number of retry attempts for errors
	CodeBlockDelimiters     []CodeBlockDelimiter       // Delimiters for code blocks
	ExecutionResultDelimits []ExecutionResultDelimiter // Delimiters for execution results
}

// NewBaseCodeExecutor creates a new BaseCodeExecutor with default settings.
func NewBaseCodeExecutor() *BaseCodeExecutor {
	return &BaseCodeExecutor{
		OptimizeDataFile:   false,
		Stateful:           false,
		ErrorRetryAttempts: 2,
		CodeBlockDelimiters: []CodeBlockDelimiter{
			{
				Start: "```python",
				End:   "```",
			},
			{
				Start: "```py",
				End:   "```",
			},
			{
				Start: "```",
				End:   "```",
			},
		},
		ExecutionResultDelimits: []ExecutionResultDelimiter{
			{
				Start: "<code_execution_result>",
				End:   "</code_execution_result>",
			},
		},
	}
}

// ExecuteCode provides a base implementation for code execution with retries.
func (b *BaseCodeExecutor) ExecuteCode(
	ctx context.Context,
	invocationCtx InvocationContext,
	input CodeExecutionInput,
) (CodeExecutionResult, error) {
	return CodeExecutionResult{}, fmt.Errorf("ExecuteCode not implemented")
}

// IsStateful returns whether the executor maintains state between executions.
func (b *BaseCodeExecutor) IsStateful() bool {
	return b.Stateful
}
