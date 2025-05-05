// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RemoteAgent communicates with a remote agent server.
type RemoteAgent struct {
	*BaseAgent

	endpoint string
	client   *http.Client
	headers  map[string]string
}

// RemoteAgentOption configures a RemoteAgent.
type RemoteAgentOption func(*RemoteAgent)

// WithEndpoint sets the remote agent's endpoint.
func WithEndpoint(endpoint string) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.endpoint = endpoint
	}
}

// WithHttpClient sets the HTTP client for the remote agent.
func WithHttpClient(client *http.Client) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.client = client
	}
}

// WithHeader adds a header to the remote agent's requests.
func WithHeader(key, value string) RemoteAgentOption {
	return func(a *RemoteAgent) {
		a.headers[key] = value
	}
}

// NewRemoteAgent creates a new remote agent with the given name and options.
func NewRemoteAgent(name string, opts ...RemoteAgentOption) *RemoteAgent {
	agent := &RemoteAgent{
		BaseAgent: NewBaseAgent(name),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		headers: make(map[string]string),
	}

	for _, opt := range opts {
		opt(agent)
	}

	return agent
}

// requestPayload represents the payload sent to a remote agent.
type requestPayload struct {
	Input  any        `json:"input"`
	Config *RunConfig `json:"config,omitempty"`
}

// Execute runs the remote agent with the given input.
func (a *RemoteAgent) Execute(ctx context.Context, input any, opts ...RunOption) (Response, error) {
	if a.endpoint == "" {
		return Response{}, errors.New("endpoint not set")
	}

	// Parse run options
	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	// Create callback context
	callbackCtx := NewCallbackContext(a, input, nil)

	// Trigger before execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackBeforeExecution, callbackCtx); err != nil {
		return Response{}, err
	}

	// Create request payload
	payload := requestPayload{
		Input:  input,
		Config: config,
	}

	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	for key, value := range a.headers {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := a.client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return Response{}, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Response{}, fmt.Errorf("failed to parse response: %w", err)
	}

	// Update callback context with response
	callbackCtx.Response = &response

	// Trigger after execution callbacks
	if err := a.TriggerCallbacks(ctx, CallbackAfterExecution, callbackCtx); err != nil {
		a.logger.WarnContext(ctx, "after execution callback error", "error", err)
	}

	return response, nil
}
