// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
)

// RemoteAgent is an agent that communicates with a remote API.
type RemoteAgent struct {
	Agent
	httpClient *http.Client
	endpoint   string
	timeout    time.Duration
	headers    map[string]string
	logger     *slog.Logger
}

// RemoteAgentOption is a function that modifies a RemoteAgent.
type RemoteAgentOption func(*RemoteAgent)

// WithEndpoint sets the endpoint for the remote agent.
func WithEndpoint(endpoint string) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.endpoint = endpoint
	}
}

// WithHTTPClient sets the HTTP client for the remote agent.
func WithHTTPClient(client *http.Client) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.httpClient = client
	}
}

// WithRemoteTimeout sets the timeout for the remote agent.
func WithRemoteTimeout(timeout time.Duration) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.timeout = timeout
	}
}

// WithHeaders sets the headers for the remote agent.
func WithHeaders(headers map[string]string) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.headers = headers
	}
}

// WithRemoteLogger sets the logger for the remote agent.
func WithRemoteLogger(logger *slog.Logger) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.logger = logger
	}
}

// NewRemoteAgent creates a new remote agent with the given options.
func NewRemoteAgent(options ...RemoteAgentOption) *RemoteAgent {
	agent := &RemoteAgent{
		Agent:      *NewAgent(),
		httpClient: http.DefaultClient,
		timeout:    30 * time.Second,
		headers:    make(map[string]string),
		logger:     slog.Default(),
	}

	for _, option := range options {
		option(agent)
	}

	return agent
}

// InvokeAsync invokes the remote agent and returns a stream of responses.
func (a *RemoteAgent) InvokeAsync(ctx context.Context, invocationCtx InvocationContext) iter.Seq2[*genai.Content, error] {
	return func(yield func(*genai.Content, error) bool) {
		// Validate that we have an endpoint
		if a.endpoint == "" {
			yield(nil, errors.New("endpoint not set for remote agent"))
			return
		}

		// Get the history and request from the invocation context
		history := invocationCtx.GetHistory()
		request := invocationCtx.GetRequest()

		// Create callback context for before callbacks
		callbackCtx := NewCallbackContextWithOptions(
			WithHistory(history),
			WithRequest(request),
		)

		// Execute before callbacks
		beforeResult := invocationCtx.ExecuteBeforeCallbacks(callbackCtx)
		if beforeResult != nil {
			// If a before callback returned a result, use it instead of calling the remote
			a.logger.Debug("Using result from before callback")
			yield(beforeResult, nil)
			return
		}

		// Prepare the request payload
		payload := map[string]any{
			"history": history,
		}

		if request != nil {
			payload["request"] = request
		}

		// Marshal the payload to JSON
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			yield(nil, fmt.Errorf("failed to marshal payload: %w", err))
			return
		}

		// Create an HTTP request
		httpReq, err := http.NewRequestWithContext(ctx, "POST", a.endpoint, bytes.NewReader(payloadBytes))
		if err != nil {
			yield(nil, fmt.Errorf("failed to create HTTP request: %w", err))
			return
		}

		// Set headers
		httpReq.Header.Set("Content-Type", "application/json")
		for key, value := range a.headers {
			httpReq.Header.Set(key, value)
		}

		// Set the request body
		// httpReq.Body = http.NoBody // TODO: implement actual streaming

		// TODO: Implement actual streaming with remote endpoints
		// For now, we'll just use a placeholder response

		content := &genai.Content{
			Role: model.RoleAssistant,
			Parts: []*genai.Part{
				genai.NewPartFromText("This is a placeholder response from the remote agent. Implement actual HTTP request handling."),
			},
		}

		if !yield(content, nil) {
			return
		}

		// Create callback context for after callbacks
		callbackCtx = NewCallbackContextWithOptions(
			WithHistory(history),
			WithRequest(request),
			WithContent(content),
		)
		callbackCtx.MarkEnd()

		// Execute after callbacks
		afterResult := invocationCtx.ExecuteAfterCallbacks(callbackCtx)
		if afterResult != nil {
			// If an after callback returned a result, yield it
			a.logger.Debug("Using result from after callback")
			if !yield(afterResult, nil) {
				return
			}
		}
	}
}

// Invoke synchronously invokes the remote agent and returns the final response.
func (a *RemoteAgent) Invoke(ctx context.Context, invocationCtx InvocationContext) (*genai.Content, error) {
	return a.Agent.Invoke(ctx, invocationCtx)
}
