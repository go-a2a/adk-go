// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"sync"

	"github.com/go-a2a/adk-go/observability"
)

// ActiveStreamingTool manages streaming tool related resources during invocation.
type ActiveStreamingTool struct {
	// The active context cancellation function for this streaming tool.
	cancelFunc context.CancelFunc

	// The wait group for waiting on the tool's goroutine to complete.
	wg sync.WaitGroup

	// The active (input) streams of this streaming tool.
	stream *LiveRequestQueue

	// Mutex for protecting concurrent access.
	mu sync.RWMutex
}

// NewActiveStreamingTool creates a new [ActiveStreamingTool].
func NewActiveStreamingTool(ctx context.Context) *ActiveStreamingTool {
	return &ActiveStreamingTool{
		stream: NewLiveRequestQueue(ctx),
	}
}

// SetStreamingTask starts a new streaming task with the provided function.
// Any existing task will be canceled before starting the new one.
func (a *ActiveStreamingTool) SetStreamingTask(ctx context.Context, taskFn func(context.Context, *LiveRequestQueue)) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Cancel any existing task
	if a.cancelFunc != nil {
		a.cancelFunc()
		a.wg.Wait() // Wait for the previous task to complete
		a.cancelFunc = nil
	}

	// Reset stream if it was closed
	if a.stream == nil || a.stream.IsClosed() {
		a.stream = NewLiveRequestQueue(ctx)
	}

	// Create a new context with cancellation
	taskCtx, cancel := context.WithCancel(ctx)
	a.cancelFunc = cancel

	// Start the new task
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				observability.Logger(ctx).ErrorContext(ctx, "Streaming task panic recovered",
					slog.Any("panic", r))
			}
		}()

		taskFn(taskCtx, a.stream)
	}()
}

// CancelTask cancels the currently running streaming task, if any.
func (a *ActiveStreamingTool) CancelTask() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancelFunc != nil {
		a.cancelFunc()
		a.wg.Wait()
		a.cancelFunc = nil
	}
}

// CloseStream closes the current stream, if any.
func (a *ActiveStreamingTool) CloseStream() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.stream != nil {
		a.stream.Close()
	}
}

// GetStream returns the current stream.
func (a *ActiveStreamingTool) GetStream() *LiveRequestQueue {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stream
}

// IsActive returns whether there is an active streaming task.
func (a *ActiveStreamingTool) IsActive() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cancelFunc != nil
}
