// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
)

// Agent is the interface that all agents must implement.
type Agent interface {
	// Name returns the agent's name.
	Name() string

	// Execute runs the agent with the given input and context.
	Execute(ctx context.Context, input map[string]any, opts ...RunOption) (*LLMResponse, error)
}
