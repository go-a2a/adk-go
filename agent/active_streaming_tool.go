// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ActiveStreamingTool is a tool that can stream data while being executed.
type ActiveStreamingTool struct {
	BaseTool

	// onStreamFunc is called when there is new streaming data.
	onStreamFunc func(data any) error

	// streamInterval is the interval between stream updates.
	streamInterval time.Duration

	// streamTimeout is the maximum time to stream data.
	streamTimeout time.Duration

	// streamActive indicates if streaming is currently active.
	streamActive bool

	// mu is used to protect shared state.
	mu sync.Mutex

	// logger is used for logging.
	logger *slog.Logger
}

// ActiveStreamingToolOption is a function that modifies an ActiveStreamingTool.
type ActiveStreamingToolOption func(*ActiveStreamingTool)

// WithOnStream sets the onStream function for the active streaming tool.
func WithOnStream(onStream func(data any) error) ActiveStreamingToolOption {
	return func(t *ActiveStreamingTool) {
		t.onStreamFunc = onStream
	}
}

// WithStreamInterval sets the stream interval for the active streaming tool.
func WithStreamInterval(interval time.Duration) ActiveStreamingToolOption {
	return func(t *ActiveStreamingTool) {
		t.streamInterval = interval
	}
}

// WithStreamTimeout sets the stream timeout for the active streaming tool.
func WithStreamTimeout(timeout time.Duration) ActiveStreamingToolOption {
	return func(t *ActiveStreamingTool) {
		t.streamTimeout = timeout
	}
}

// WithStreamingLogger sets the logger for the active streaming tool.
func WithStreamingLogger(logger *slog.Logger) ActiveStreamingToolOption {
	return func(t *ActiveStreamingTool) {
		t.logger = logger
	}
}

// NewActiveStreamingTool creates a new active streaming tool with the given options.
func NewActiveStreamingTool(toolOptions []ToolOption, streamingOptions ...ActiveStreamingToolOption) *ActiveStreamingTool {
	baseTool := NewTool(toolOptions...)

	tool := &ActiveStreamingTool{
		BaseTool:       *baseTool,
		streamInterval: 1 * time.Second,
		streamTimeout:  60 * time.Second,
		streamActive:   false,
		logger:         slog.Default(),
	}

	for _, option := range streamingOptions {
		option(tool)
	}

	return tool
}

// Execute executes the tool with the given parameters.
func (t *ActiveStreamingTool) Execute(ctx context.Context, params map[string]any) (any, error) {
	// Check if there's a data generator or execute function
	if t.executeFunc == nil {
		return nil, fmt.Errorf("%w: execute function not set", ErrToolExecutionFailed)
	}

	// Validate parameters
	if err := t.validateParameters(params); err != nil {
		return nil, err
	}

	// Start streaming if not already active
	t.mu.Lock()
	if t.streamActive {
		t.mu.Unlock()
		return nil, errors.New("streaming already active")
	}
	t.streamActive = true
	t.mu.Unlock()

	// Create a context with timeout
	streamCtx, cancel := context.WithTimeout(ctx, t.streamTimeout)
	defer cancel()

	// Channel for the final result
	resultCh := make(chan any, 1)
	errCh := make(chan error, 1)

	// Execute the tool in a goroutine
	go func() {
		result, err := t.executeFunc(streamCtx, params)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	// Process streaming data
	ticker := time.NewTicker(t.streamInterval)
	defer ticker.Stop()

	var result any

	for {
		select {
		case <-ctx.Done():
			// Context was canceled, clean up and return
			t.mu.Lock()
			t.streamActive = false
			t.mu.Unlock()
			return nil, ctx.Err()

		case err := <-errCh:
			// Error occurred during execution
			t.mu.Lock()
			t.streamActive = false
			t.mu.Unlock()
			return nil, err

		case result = <-resultCh:
			// Execution completed successfully
			t.mu.Lock()
			t.streamActive = false
			t.mu.Unlock()
			return result, nil

		case <-ticker.C:
			// Time to send a streaming update
			if t.onStreamFunc != nil {
				// Generate a streaming update
				// This is a placeholder - in a real implementation, you might
				// get partial results from the execution
				streamData := map[string]any{
					"status":    "processing",
					"timestamp": time.Now().UnixNano(),
				}

				if err := t.onStreamFunc(streamData); err != nil {
					t.logger.Error("Error sending stream update", "error", err)
				}
			}
		}
	}
}

// IsStreaming returns true if the tool is currently streaming.
func (t *ActiveStreamingTool) IsStreaming() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streamActive
}

// StopStreaming stops the streaming process.
func (t *ActiveStreamingTool) StopStreaming() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.streamActive = false
}
