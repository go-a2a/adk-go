// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"sync"

	"google.golang.org/genai"
)

// StreamingToolError is a simple error type for streaming tool errors.
type StreamingToolError string

func (e StreamingToolError) Error() string {
	return string(e)
}

var (
	// ErrQueueEmpty is returned when attempting to get from an empty queue.
	ErrQueueEmpty = StreamingToolError("queue is empty")

	// ErrQueueFull is returned when attempting to push to a full queue.
	ErrQueueFull = StreamingToolError("queue is full")

	// ErrQueueClosed is returned when attempting to push to or get from a closed queue.
	ErrQueueClosed = StreamingToolError("queue is closed")
)

// LiveRequest represents a request in the [LiveRequestQueue].
type LiveRequest struct {
	// Content send the content to the model in turn-by-turn mode.
	Content *genai.Content

	// Blob send the blob to the model in realtime mode.
	Blob *genai.Blob

	// Close closes the queue.
	Close bool
}

// LiveRequestQueue is a queue used to send [LiveRequests] in a bidirectional streaming way.
// It supports both turn-by-turn model communication (with Content) and
// realtime mode communication (with Blob).
type LiveRequestQueue struct {
	// queue stores the LiveRequest objects
	queue chan LiveRequest

	// mu protects the closed flag
	mu sync.RWMutex

	// closed indicates whether the queue is closed
	closed bool

	// ctx is the context for the queue
	ctx    context.Context
	cancel context.CancelFunc
}

// NewLiveRequestQueue creates a new [LiveRequestQueue].
func NewLiveRequestQueue(ctx context.Context) *LiveRequestQueue {
	ctx, cancel := context.WithCancel(ctx)
	return &LiveRequestQueue{
		queue:  make(chan LiveRequest, 100), // Buffer size can be adjusted as needed
		closed: false,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Close sends a LiveRequest with Close=true to signal queue termination.
func (q *LiveRequestQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.closed {
		q.closed = true
		q.send(LiveRequest{Close: true})
		q.cancel()
		close(q.queue)
	}
}

// SendContent adds a [LiveRequest] with content for turn-by-turn model communication.
func (q *LiveRequestQueue) SendContent(content *genai.Content) error {
	return q.send(LiveRequest{Content: content})
}

// SendRealtime adds a [LiveRequest] with a blob for realtime mode communication.
func (q *LiveRequestQueue) SendRealtime(blob *genai.Blob) error {
	return q.send(LiveRequest{Blob: blob})
}

// Send adds a generic [LiveRequest] to the queue.
func (q *LiveRequestQueue) Send(req LiveRequest) error {
	return q.send(req)
}

// send internal method to add a request to the queue.
func (q *LiveRequestQueue) send(req LiveRequest) error {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.closed {
		return ErrQueueClosed
	}

	select {
	case <-q.ctx.Done():
		return ErrQueueClosed
	case q.queue <- req:
		return nil
	default:
		return ErrQueueFull
	}
}

// Get retrieves the next request from the queue.
// It blocks until a request is available or the queue is closed.
// Returns an error if the queue is closed.
func (q *LiveRequestQueue) Get() (LiveRequest, error) {
	select {
	case <-q.ctx.Done():
		return LiveRequest{}, ErrQueueClosed
	case req, ok := <-q.queue:
		if !ok {
			return LiveRequest{}, ErrQueueClosed
		}
		return req, nil
	}
}

// TryGet attempts to retrieve the next request from the queue without blocking.
// If no request is available, it returns immediately with an error.
func (q *LiveRequestQueue) TryGet() (LiveRequest, error) {
	select {
	case <-q.ctx.Done():
		return LiveRequest{}, ErrQueueClosed
	case req, ok := <-q.queue:
		if !ok {
			return LiveRequest{}, ErrQueueClosed
		}
		return req, nil
	default:
		return LiveRequest{}, ErrQueueEmpty
	}
}

// IsClosed returns true if the queue is closed.
func (q *LiveRequestQueue) IsClosed() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.closed
}
