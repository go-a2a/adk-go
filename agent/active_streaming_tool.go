// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// StreamSource represents a source of streaming data.
type StreamSource interface {
	io.ReadCloser
	StreamID() string
}

// streamSource is an implementation of StreamSource.
type streamSource struct {
	io.ReadCloser
	id string
}

// StreamID returns the stream ID.
func (s *streamSource) StreamID() string {
	return s.id
}

// ActiveStreamingTool is a tool that can stream data from a source.
type ActiveStreamingTool struct {
	*BaseTool

	streamFunc StreamFunc
	sources    map[string]StreamSource
	mu         sync.Mutex
}

// StreamFunc is the function type that creates a stream source.
type StreamFunc func(ctx context.Context, input any) (io.ReadCloser, error)

// NewActiveStreamingTool creates a new streaming tool with the given options.
func NewActiveStreamingTool(streamFunc StreamFunc, opts ...ToolOption) *ActiveStreamingTool {
	tool := &ActiveStreamingTool{
		BaseTool:   NewTool(opts...),
		streamFunc: streamFunc,
		sources:    make(map[string]StreamSource),
	}

	return tool
}

// Execute starts streaming from a source.
func (t *ActiveStreamingTool) Execute(ctx context.Context, input any) (any, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Generate a unique ID for this stream
	streamID := generateUUID()

	// Create the stream source
	source, err := t.streamFunc(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream source: %w", err)
	}

	// Store the source
	t.sources[streamID] = &streamSource{
		ReadCloser: source,
		id:         streamID,
	}

	// Return the stream ID
	return map[string]string{
		"stream_id": streamID,
	}, nil
}

// GetStream retrieves a stream by ID.
func (t *ActiveStreamingTool) GetStream(streamID string) (StreamSource, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	source, ok := t.sources[streamID]
	if !ok {
		return nil, errors.New("stream not found")
	}

	return source, nil
}

// CloseStream closes a stream.
func (t *ActiveStreamingTool) CloseStream(streamID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	source, ok := t.sources[streamID]
	if !ok {
		return errors.New("stream not found")
	}

	delete(t.sources, streamID)
	return source.Close()
}

// ListStreams returns a list of active stream IDs.
func (t *ActiveStreamingTool) ListStreams() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	ids := make([]string, 0, len(t.sources))
	for id := range t.sources {
		ids = append(ids, id)
	}

	return ids
}

// generateUUID generates a unique ID for a stream.
func generateUUID() string {
	// In a real implementation, use a proper UUID library
	return fmt.Sprintf("stream-%d", time.Now().UnixNano())
}
