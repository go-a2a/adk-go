// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package codeexecutor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// UnsafeLocalCodeExecutor executes code locally with minimal sandboxing.
// This is NOT safe for running untrusted code.
type UnsafeLocalCodeExecutor struct {
	*BaseCodeExecutor
	PythonExecutable string // Path to Python executable
}

// NewUnsafeLocalCodeExecutor creates a new UnsafeLocalCodeExecutor.
func NewUnsafeLocalCodeExecutor(pythonExecutable string) *UnsafeLocalCodeExecutor {
	if pythonExecutable == "" {
		pythonExecutable = "python3"
	}

	base := NewBaseCodeExecutor()
	base.OptimizeDataFile = false
	base.Stateful = false

	return &UnsafeLocalCodeExecutor{
		BaseCodeExecutor: base,
		PythonExecutable: pythonExecutable,
	}
}

// ExecuteCode executes Python code locally and returns the result.
func (e *UnsafeLocalCodeExecutor) ExecuteCode(
	ctx context.Context,
	invocationCtx InvocationContext,
	input CodeExecutionInput,
) (CodeExecutionResult, error) {
	result := CodeExecutionResult{
		Timestamp: time.Now(),
	}

	// Create a command to execute the Python code
	cmd := exec.CommandContext(ctx, e.PythonExecutable, "-c", input.Code)

	// Set environment variables if provided
	if len(input.Environment) > 0 {
		env := cmd.Environ()
		for k, v := range input.Environment {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env
	}

	// Capture stdout and stderr
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Execute the command
	err := cmd.Run()

	// Fill in the result
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	// Handle execution error
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Input files are not processed in this executor
	// Output files are not captured in this executor

	return result, nil
}
