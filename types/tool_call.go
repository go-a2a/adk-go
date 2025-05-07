// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

// ToolCall represents a call to a tool during agent execution.
type ToolCall struct {
	// Name is the name of the tool.
	Name string

	// Input is the input provided to the tool.
	Input map[string]any

	// Output is the result from the tool execution.
	Output map[string]any

	// Error is set if the tool call failed.
	Error error
}
