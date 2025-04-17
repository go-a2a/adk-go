// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package codeexecutor provides functionality for executing code in various environments.
// It supports local execution, containerized execution, and potentially cloud execution.
package codeexecutor

import (
	"errors"
	"fmt"
	"strings"
)

// ExecutorType represents the type of code executor.
type ExecutorType string

const (
	// UnsafeLocalExecutor executes code locally with minimal sandboxing.
	UnsafeLocalExecutor ExecutorType = "unsafe_local"

	// ContainerExecutor executes code in a container for isolation.
	ContainerExecutor ExecutorType = "container"

	// VertexAIExecutor executes code on Google Vertex AI.
	VertexAIExecutor ExecutorType = "vertex_ai"
)

// Errors returned by the package.
var (
	ErrUnsupportedExecutor = errors.New("unsupported executor type")
	ErrInvalidConfig       = errors.New("invalid configuration")
)

// ExecutorConfig contains configuration for creating a code executor.
type ExecutorConfig struct {
	// Type is the type of executor to create.
	Type ExecutorType

	// PythonExecutable is the path to the Python executable for local execution.
	PythonExecutable string

	// ImageName is the Docker image name for container execution.
	ImageName string

	// DockerfilePath is the path to the Dockerfile for building a custom image.
	DockerfilePath string

	// DockerClientBaseURL is the base URL for the Docker client.
	DockerClientBaseURL string

	// VertexAIConfig is the configuration for Vertex AI execution.
	VertexAIConfig map[string]string
}

// NewCodeExecutor creates a new code executor based on the provided configuration.
func NewCodeExecutor(config ExecutorConfig) (CodeExecutor, error) {
	switch config.Type {
	case UnsafeLocalExecutor:
		return NewUnsafeLocalCodeExecutor(config.PythonExecutable), nil

	case ContainerExecutor:
		// Validate required fields before creating options
		if config.ImageName == "" && config.DockerfilePath == "" {
			return nil, fmt.Errorf("%w: either ImageName or DockerfilePath must be provided", ErrInvalidConfig)
		}

		var options []func(*ContainerCodeExecutor)

		if config.ImageName != "" {
			options = append(options, WithImageName(config.ImageName))
		}

		if config.DockerfilePath != "" {
			options = append(options, WithDockerfilePath(config.DockerfilePath))
		}

		if config.DockerClientBaseURL != "" {
			options = append(options, WithDockerClientBaseURL(config.DockerClientBaseURL))
		}

		return NewContainerCodeExecutor(options...)

	case VertexAIExecutor:
		return nil, fmt.Errorf("%w: %s (not implemented yet)", ErrUnsupportedExecutor, config.Type)

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedExecutor, config.Type)
	}
}

// FormatCodeBlock formats code with appropriate delimiters.
func FormatCodeBlock(code, language string) string {
	var sb strings.Builder

	// If no language is specified, use a generic code block
	if language == "" {
		language = ""
	}

	// Format the code block with delimiters
	sb.WriteString(fmt.Sprintf("```%s\n", language))
	sb.WriteString(code)

	// Ensure the code ends with a newline before the closing delimiter
	if !strings.HasSuffix(code, "\n") {
		sb.WriteString("\n")
	} else {
		// Don't add additional newline if there's already one
	}

	sb.WriteString("```")

	return sb.String()
}
