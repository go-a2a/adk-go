// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// LiveRequest represents a request to an agent.
type LiveRequest struct {
	// ID is the request ID.
	ID string

	// Input is the input to the agent.
	Input any

	// ResponseChan is the channel to send responses to.
	ResponseChan chan<- Response

	// ErrorChan is the channel to send errors to.
	ErrorChan chan<- error

	// Context is the context for the request.
	Context context.Context

	// RunOpts are the options for running the agent.
	RunOpts []RunOption

	// Timestamp is when the request was created.
	Timestamp time.Time
}

// NewLiveRequest creates a new live request.
func NewLiveRequest(id string, input any, responseChan chan<- Response, errorChan chan<- error, ctx context.Context, opts ...RunOption) *LiveRequest {
	return &LiveRequest{
		ID:           id,
		Input:        input,
		ResponseChan: responseChan,
		ErrorChan:    errorChan,
		Context:      ctx,
		RunOpts:      opts,
		Timestamp:    time.Now(),
	}
}

// LiveRequestQueue manages a queue of live requests.
type LiveRequestQueue struct {
	queue      []*LiveRequest
	agent      Agent
	mu         sync.Mutex
	processing bool
	workers    int
	maxWorkers int
	logger     *slog.Logger
}

// LiveRequestQueueOption configures a LiveRequestQueue.
type LiveRequestQueueOption func(*LiveRequestQueue)

// WithMaxWorkers sets the maximum number of workers.
func WithMaxWorkers(max int) LiveRequestQueueOption {
	return func(q *LiveRequestQueue) {
		q.maxWorkers = max
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

// NewLiveRequestQueue creates a new live request queue.
func NewLiveRequestQueue(opts ...LiveRequestQueueOption) *LiveRequestQueue {
	queue := &LiveRequestQueue{
		queue:      make([]*LiveRequest, 0),
		maxWorkers: 5, // Default
		logger:     slog.Default(),
	}

	for _, opt := range opts {
		opt(queue)
	}

	return queue
}

// Add adds a request to the queue.
func (q *LiveRequestQueue) Add(request *LiveRequest) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.queue = append(q.queue, request)

	// Start processing if not already
	if !q.processing && q.workers < q.maxWorkers {
		q.processing = true
		q.workers++
		go q.process()
	}
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
			q.logger.WarnContext(request.Context, "request context already done",
				"request_id", request.ID,
				"error", request.Context.Err())
			request.ErrorChan <- request.Context.Err()
			continue
		}

		// Process request
		q.logger.InfoContext(request.Context, "processing request",
			"request_id", request.ID)

		response, err := q.agent.Execute(request.Context, request.Input, request.RunOpts...)

		// Send response or error
		if err != nil {
			q.logger.ErrorContext(request.Context, "request failed",
				"request_id", request.ID,
				"error", err)
			request.ErrorChan <- err
		} else {
			q.logger.InfoContext(request.Context, "request succeeded",
				"request_id", request.ID)
			request.ResponseChan <- response
		}
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

	for i, request := range q.queue {
		if request.ID == id {
			// Remove from queue
			q.queue = append(q.queue[:i], q.queue[i+1:]...)
			return nil
		}
	}

	return errors.New("request not found")
}

// Clear empties the queue.
func (q *LiveRequestQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.queue = make([]*LiveRequest, 0)
}
