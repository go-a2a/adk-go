// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"google.golang.org/genai"
)

// LiveRequest represents a request send to live agents.
type LiveRequest struct {
	Context context.Context

	// Send the content to the model in turn-by-turn mode if set.
	Content *genai.Content

	// Send the blob to the model in realtime mode if set.
	Blob *genai.Blob

	// Whether the closes the queue.
	Close bool

	// ID is the request ID.
	ID string

	// Input is the input to the agent.
	Input map[string]any

	// ResponseChan is the channel to send responses to.
	ResponseChan chan<- *LLMResponse

	// ErrorChan is the channel to send errors to.
	ErrorChan chan<- error

	// RunOpts are the options for running the agent.
	RunOpts []RunOption

	// Timestamp is when the request was created.
	Timestamp time.Time
}

// NewLiveRequest creates a new live request.
func NewLiveRequest(ctx context.Context, id string, input map[string]any, responseChan chan<- *LLMResponse, errorChan chan<- error, opts ...RunOption) *LiveRequest {
	return &LiveRequest{
		ID:           id,
		Input:        input,
		ResponseChan: responseChan,
		ErrorChan:    errorChan,
		RunOpts:      opts,
		Timestamp:    time.Now(),
	}
}

// LiveRequestQueue queue used to send [LiveRequest] in a live(bidirectional streaming) way.
type LiveRequestQueue struct {
	queue      []*LiveRequest
	agent      Agent
	mu         sync.Mutex
	processing bool
	workers    int
	maxWorkers int
	logger     *slog.Logger
}

// NewLiveRequestQueue creates a new live request queue.
func NewLiveRequestQueue(opts ...LiveRequestQueueOption) *LiveRequestQueue {
	queue := &LiveRequestQueue{
		queue:      []*LiveRequest{},
		maxWorkers: 5, // Default
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(queue)
	}

	return queue
}

// LiveRequestQueueOption configures a LiveRequestQueue.
type LiveRequestQueueOption func(*LiveRequestQueue)

// WithMaxWorkers sets the maximum number of workers.
func WithMaxWorkers(maxWorkers int) LiveRequestQueueOption {
	return func(q *LiveRequestQueue) {
		q.maxWorkers = maxWorkers
	}
}

// WithQueueAgent sets the agent for the queue.
func WithQueueAgent(agent Agent) LiveRequestQueueOption {
	return func(q *LiveRequestQueue) {
		q.agent = agent
	}
}

// WithQueueLogger sets the logger for the queue.
func WithQueueLogger(logger *slog.Logger) LiveRequestQueueOption {
	return func(q *LiveRequestQueue) {
		q.logger = logger
	}
}

func (q *LiveRequestQueue) Close() {
	req := &LiveRequest{
		Close: true,
	}
	q.Send(req)
}

func (q *LiveRequestQueue) SendContent(content *genai.Content) {
	req := &LiveRequest{
		Content: content,
	}
	q.Send(req)
}

func (q *LiveRequestQueue) SendRealtime(blob *genai.Blob) {
	req := &LiveRequest{
		Blob: blob,
	}
	q.Send(req)
}

// Send adds a request to the queue.
func (q *LiveRequestQueue) Send(req *LiveRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.queue = append(q.queue, req)

	// Start processing if not already
	if !q.processing && q.workers < q.maxWorkers {
		q.processing = true
		q.workers++
		go q.process()
	}
}

func (q *LiveRequestQueue) Get() *LiveRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	req := q.queue[0]
	q.queue = slices.Delete(q.queue, 0, 1)

	return req
}

// process processes requests in the queue.
func (q *LiveRequestQueue) process() {
	defer func() {
		q.mu.Lock()
		q.workers--
		if q.workers == 0 {
			q.processing = false
		}
		q.mu.Unlock()
	}()

	for {
		// Get next request
		q.mu.Lock()
		if len(q.queue) == 0 {
			q.mu.Unlock()
			return
		}

		request := q.queue[0]
		q.queue = q.queue[1:]
		q.mu.Unlock()

		// Check if context is already done
		if request.Context.Err() != nil {
			q.logger.ErrorContext(request.Context, "request context already done",
				slog.String("request_id", request.ID),
				slog.Any("error", request.Context.Err()),
			)
			request.ErrorChan <- request.Context.Err()
			continue
		}

		// Process request
		q.logger.InfoContext(request.Context, "processing request",
			slog.String("request_id", request.ID),
		)

		response, err := q.agent.Execute(request.Context, request.Input, request.RunOpts...)

		// Send response or error
		if err != nil {
			q.logger.ErrorContext(request.Context, "request failed",
				slog.String("request_id", request.ID),
				slog.Any("error", err),
			)
			request.ErrorChan <- err
			return
		}

		q.logger.InfoContext(request.Context, "request succeeded",
			slog.String("request_id", request.ID),
		)
		request.ResponseChan <- response
	}
}

// Size returns the number of requests in the queue.
func (q *LiveRequestQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.queue)
}

// Cancel cancels a request by ID.
func (q *LiveRequestQueue) Cancel(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i, req := range q.queue {
		if req.ID == id {
			// Remove from queue
			q.queue = slices.Delete(q.queue, i, i+1)
			return nil
		}
	}

	return errors.New("request not found")
}

// Clear empties the queue.
func (q *LiveRequestQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	clear(q.queue)
}
