// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package codeexecutor

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestNewCodeExecutor(t *testing.T) {
	tests := []struct {
		name    string
		config  ExecutorConfig
		wantErr bool
	}{
		{
			name: "UnsafeLocalExecutor",
			config: ExecutorConfig{
				Type:             UnsafeLocalExecutor,
				PythonExecutable: "python3",
			},
			wantErr: false,
		},
		{
			name: "ContainerExecutor with image name",
			config: ExecutorConfig{
				Type:      ContainerExecutor,
				ImageName: "adk-code-executor:latest",
			},
			wantErr: false,
		},
		{
			name: "ContainerExecutor without image name or dockerfile",
			config: ExecutorConfig{
				Type: ContainerExecutor,
			},
			wantErr: true,
		},
		{
			name: "UnsupportedExecutor",
			config: ExecutorConfig{
				Type: "unsupported",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCodeExecutor(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCodeExecutor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestUnsafeLocalCodeExecutor_ExecuteCode(t *testing.T) {
	executor := NewUnsafeLocalCodeExecutor("")

	// Skip test if Python3 is not available
	if _, err := executor.ExecuteCode(
		context.Background(),
		InvocationContext{ExecutionID: "test", StartTime: time.Now()},
		CodeExecutionInput{Code: "print('Hello, World!')"}); err != nil {
		t.Skip("Skipping test as Python3 is not available")
	}

	tests := []struct {
		name    string
		code    string
		wantOut string
		wantErr bool
	}{
		{
			name:    "Simple print",
			code:    "print('Hello, World!')",
			wantOut: "Hello, World!\n",
			wantErr: false,
		},
		{
			name:    "Syntax error",
			code:    "print('Hello, World!';",
			wantOut: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := executor.ExecuteCode(
				context.Background(),
				InvocationContext{ExecutionID: "test", StartTime: time.Now()},
				CodeExecutionInput{Code: tt.code},
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExecuteCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result.Stdout != tt.wantOut {
				t.Errorf("ExecuteCode() stdout = %v, want %v", result.Stdout, tt.wantOut)
			}
		})
	}
}

func TestFormatCodeBlock(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		language string
		want     string
	}{
		{
			name:     "Python code",
			code:     "print('Hello, World!')",
			language: "python",
			want:     "```python\nprint('Hello, World!')\n```",
		},
		{
			name:     "No language",
			code:     "print('Hello, World!')",
			language: "",
			want:     "```\nprint('Hello, World!')\n```",
		},
		{
			name:     "Code with trailing newline",
			code:     "print('Hello, World!')\n",
			language: "python",
			want:     "```python\nprint('Hello, World!')\n```",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatCodeBlock(tt.code, tt.language)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("FormatCodeBlock() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
