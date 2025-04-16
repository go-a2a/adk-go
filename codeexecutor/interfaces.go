// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package codeexecutor

import (
	"context"
	"time"

	"github.com/go-a2a/adk-go/flow"
)

// CodeBlockDelimiter defines how to identify code blocks in generated content.
type CodeBlockDelimiter struct {
	Start string // Start delimiter for code block
	End   string // End delimiter for code block
}

// ExecutionResultDelimiter defines how to format execution results.
type ExecutionResultDelimiter struct {
	Start string // Start delimiter for execution result
	End   string // End delimiter for execution result
}

// CodeExecutionInput contains the code to execute and any additional inputs.
type CodeExecutionInput struct {
	Code        string            // The code to execute
	InputFiles  map[string][]byte // Any input files required for execution
	Environment map[string]string // Environment variables for execution
}

// OutputFile represents a file produced during code execution.
type OutputFile struct {
	Name    string // Name of the output file
	Content []byte // Content of the output file
}

// CodeExecutionResult contains the results of a code execution.
type CodeExecutionResult struct {
	Stdout      string       // Standard output from execution
	Stderr      string       // Standard error from execution
	OutputFiles []OutputFile // Files produced by execution
	Error       string       // Error message if execution failed
	Timestamp   time.Time    // When the code was executed
}

// CodeExecutor defines the interface for executing code.
type CodeExecutor interface {
	// ExecuteCode executes code and returns the execution result.
	ExecuteCode(ctx context.Context, invocationCtx flow.InvocationContext, input CodeExecutionInput) (CodeExecutionResult, error)

	// IsStateful returns whether the executor maintains state between executions.
	IsStateful() bool
}
