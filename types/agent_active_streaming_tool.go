// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"sync"
)

// ActiveStreamingTool manages streaming tool related resources during invocation.
// It tracks an active task and a LiveRequestQueue stream for streaming operations.
type ActiveStreamingTool struct {
	// TaskCancel is the cancellation function for the active task
	TaskCancel context.CancelFunc

	// Stream is the active LiveRequestQueue for this tool
	Stream *LiveRequestQueue

	// mu protects concurrent access to fields
	mu sync.Mutex
}

// NewActiveStreamingTool creates a new [ActiveStreamingTool] instance.
func NewActiveStreamingTool() *ActiveStreamingTool {
	return &ActiveStreamingTool{}
}

// SetTaskCancel sets a new task cancellation function.
// If there's an existing task, it will be cancelled before setting the new one.
func (a *ActiveStreamingTool) SetTaskCancel(cancel context.CancelFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Cancel any existing task before setting the new one
	if a.TaskCancel != nil {
		a.TaskCancel()
	}

	a.TaskCancel = cancel
}

// CancelTask cancels the current task if one exists and clears the TaskCancel field.
func (a *ActiveStreamingTool) CancelTask() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.TaskCancel != nil {
		a.TaskCancel()
		a.TaskCancel = nil
	}
}

// SetStream sets the active stream for this tool.
func (a *ActiveStreamingTool) SetStream(stream *LiveRequestQueue) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.Stream = stream
}

// GetStream returns the current stream.
func (a *ActiveStreamingTool) GetStream() *LiveRequestQueue {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.Stream
}

// ClearStream clears the current stream.
func (a *ActiveStreamingTool) ClearStream() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.Stream = nil
}

// IsActive returns true if there is an active task or stream.
func (a *ActiveStreamingTool) IsActive() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.TaskCancel != nil || a.Stream != nil
}
