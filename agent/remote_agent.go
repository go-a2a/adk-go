// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/message"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/session"
)

// RemoteAgent represents an agent that delegates processing to a remote endpoint.
// This is an experimental implementation and should not be used in production.
type RemoteAgent struct {
	// name is the unique identifier for this agent
	name string

	// description is a brief explanation of the agent's capabilities
	description string

	// url is the endpoint that will handle the agent's requests
	url string

	// httpClient is used to make HTTP requests
	httpClient *http.Client

	// timeout is the maximum duration for HTTP requests
	timeout time.Duration
}

// RemoteAgentConfig contains configuration options for creating a RemoteAgent.
type RemoteAgentConfig struct {
	// Name is the unique identifier for this agent
	Name string

	// Description explains the agent's capabilities
	Description string

	// URL is the endpoint that will handle the agent's requests
	URL string

	// Timeout is the maximum duration for HTTP requests (defaults to 2 minutes)
	Timeout time.Duration

	// HTTPClient is an optional custom HTTP client
	HTTPClient *http.Client
}

// NewRemoteAgent creates a new RemoteAgent with the provided configuration.
func NewRemoteAgent(config RemoteAgentConfig) *RemoteAgent {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute // Default timeout
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: timeout,
		}
	}

	return &RemoteAgent{
		name:        config.Name,
		description: config.Description,
		url:         config.URL,
		httpClient:  httpClient,
		timeout:     timeout,
	}
}

// Name returns the agent's name.
func (ra *RemoteAgent) Name() string {
	return ra.name
}

// Description returns the agent's description.
func (ra *RemoteAgent) Description() string {
	return ra.description
}

// RemoteRequestPayload represents the data sent to the remote endpoint.
type RemoteRequestPayload struct {
	InvocationID string           `json:"invocation_id"`
	Session      *session.Session `json:"session"`
	Message      message.Message  `json:"message"`
}

// Process handles a user message by sending it to a remote endpoint and returning the response.
func (ra *RemoteAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	ctx, span := observability.StartSpan(ctx, "RemoteAgent.Process")
	defer span.End()

	span.SetAttributes(
		attribute.String("agent.name", ra.name),
		attribute.String("agent.url", ra.url),
	)

	logger := observability.Logger(ctx)
	logger.InfoContext(ctx, "Processing message with remote agent",
		slog.String("agent", ra.name),
		slog.String("url", ra.url),
	)

	// Generate a unique invocation ID
	invocationID := uuid.NewString()

	// Create a minimal session for the remote request
	// In a production environment, this would be the actual session from a session service
	sess := session.NewSession(invocationID, "remote_agent_app", "user")

	// Prepare payload
	payload := RemoteRequestPayload{
		InvocationID: invocationID,
		Session:      sess,
		Message:      msg,
	}

	// Serialize payload
	jsonPayload, err := sonic.Marshal(payload)
	if err != nil {
		observability.Error(ctx, err, "Failed to marshal payload")
		return message.Message{}, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ra.url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		observability.Error(ctx, err, "Failed to create HTTP request")
		return message.Message{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ADK-Go/RemoteAgent")

	// Send request
	resp, err := ra.httpClient.Do(req)
	if err != nil {
		observability.Error(ctx, err, "Failed to send request to remote endpoint")
		return message.Message{}, fmt.Errorf("failed to send request to remote endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("remote endpoint returned status %d", resp.StatusCode)
		observability.Error(ctx, err, "Remote endpoint error")
		return message.Message{}, err
	}

	// Parse response
	var events []event.Event
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&events); err != nil {
		observability.Error(ctx, err, "Failed to decode response")
		return message.Message{}, fmt.Errorf("failed to decode response: %w", err)
	}

	// Handle empty response
	if len(events) == 0 {
		err := fmt.Errorf("remote endpoint returned empty event list")
		observability.Error(ctx, err, "Empty response")
		return message.Message{}, err
	}

	// Process events into a message
	// In this simple implementation we just use the content of the first event
	lastEvent := events[len(events)-1]

	// Set the author to this agent's name
	lastEvent.Author = ra.name

	// Convert event to message
	response := message.NewAssistantMessage(lastEvent.Content)

	// Add any function calls to the message
	if len(lastEvent.FunctionCalls) > 0 {
		toolCalls := make([]message.ToolCall, 0, len(lastEvent.FunctionCalls))
		for _, fc := range lastEvent.FunctionCalls {
			// Convert parameters to JSON
			argsJSON, err := sonic.Marshal(fc.Parameters)
			if err != nil {
				logger.WarnContext(ctx, "Failed to marshal function parameters",
					slog.String("function", fc.Name),
					slog.String("error", err.Error()),
				)
				continue
			}

			toolCalls = append(toolCalls, message.ToolCall{
				ID:   fc.ID,
				Name: fc.Name,
				Args: argsJSON,
			})
		}
		response.ToolCalls = toolCalls
	}

	return response, nil
}

// ProcessAsync handles a user message asynchronously and returns a channel for the response.
func (ra *RemoteAgent) ProcessAsync(ctx context.Context, msg message.Message) (<-chan message.ProcessResult, error) {
	resultCh := make(chan message.ProcessResult, 1)

	go func() {
		defer close(resultCh)

		resp, err := ra.Process(ctx, msg)
		resultCh <- message.ProcessResult{
			Message: resp,
			Error:   err,
		}
	}()

	return resultCh, nil
}

