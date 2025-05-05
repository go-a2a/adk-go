// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent provides the Agent Development Kit (ADK) implementation in Go.
package agent

import (
	"context"
	"errors"
	"fmt"
)

// Common errors
var (
	ErrAgentNotInitialized  = errors.New("agent not initialized")
	ErrUnsupportedOperation = errors.New("unsupported operation")
	ErrInvalidInput         = errors.New("invalid input")
	ErrToolNotFound         = errors.New("tool not found")
	ErrExecutionFailed      = errors.New("execution failed")
)

// Agent is the interface that all agents must implement.
type Agent interface {
	// Name returns the agent's name.
	Name() string

	// Execute runs the agent with the given input and context.
	Execute(ctx context.Context, input any, opts ...RunOption) (Response, error)

	// AddTool adds a tool to the agent.
	AddTool(tool Tool) error

	// Tools returns the agent's tools.
	Tools() []Tool

	// IsStreaming returns whether the agent is streaming-capable.
	IsStreaming() bool
}

// Response represents the result of an agent execution.
type Response struct {
	// Content is the text content of the response.
	Content string

	// Data contains structured data if the response is not just text.
	Data any

	// ToolCalls contains any tool calls made during execution.
	ToolCalls []ToolCall

	// ErrorCode contains an error code if the execution failed.
	ErrorCode string

	// ErrorMessage contains an error message if the execution failed.
	ErrorMessage string
}

// ToolCall represents a call to a tool during agent execution.
type ToolCall struct {
	// Name is the name of the tool.
	Name string

	// Input is the input provided to the tool.
	Input any

	// Output is the result from the tool execution.
	Output any

	// Error is set if the tool call failed.
	Error error
}

// IsError returns true if the response contains an error.
func (r *Response) IsError() bool {
	return r.ErrorCode != "" || r.ErrorMessage != ""
}

// Error implements the error interface for Response.
func (r *Response) Error() string {
	if r.ErrorMessage != "" {
		return fmt.Sprintf("%s: %s", r.ErrorCode, r.ErrorMessage)
	}
	return r.ErrorCode
}
