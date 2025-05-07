// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent provides the Agent Development Kit (ADK) implementation in Go.
package agent

import (
	"errors"
)

// Common errors
var (
	ErrAgentNotInitialized  = errors.New("agent not initialized")
	ErrUnsupportedOperation = errors.New("unsupported operation")
	ErrInvalidInput         = errors.New("invalid input")
	ErrToolNotFound         = errors.New("tool not found")
	ErrExecutionFailed      = errors.New("execution failed")
)
