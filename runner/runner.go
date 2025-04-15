// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/go-a2a/adk-go/agent"
	"github.com/go-a2a/adk-go/artifact"
	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/memory"
	"github.com/go-a2a/adk-go/message"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/session"
)

// Runner represents a runner for managing agent execution within a session.
// It handles message processing, event generation, and interaction with services.
type Runner struct {
	// AppName is the name of the application
	AppName string

	// RootAgent is the top-level agent for this runner
	RootAgent *agent.Agent

	// ArtifactService handles storing and retrieving artifacts
	ArtifactService artifact.ArtifactService

	// SessionService manages user sessions
	SessionService session.SessionService

	// MemoryService provides memory capabilities
	MemoryService memory.MemoryService

	// Logger is the structured logger for this runner
	Logger *slog.Logger
}

// RunnerConfig contains all configuration options for creating a new Runner.
type RunnerConfig struct {
	// AppName is the name of the application
	AppName string

	// ArtifactService handles storing and retrieving artifacts
	ArtifactService artifact.ArtifactService

	// SessionService manages user sessions
	SessionService session.SessionService

	// MemoryService provides memory capabilities
	MemoryService memory.MemoryService

	// Logger is the structured logger for this runner
	Logger *slog.Logger
}

// NewRunner creates a new runner with the provided agent and configuration.
func NewRunner(rootAgent *agent.Agent, config RunnerConfig) *Runner {
	// Initialize with sensible defaults if not provided
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return &Runner{
		AppName:         config.AppName,
		RootAgent:       rootAgent,
		ArtifactService: config.ArtifactService,
		SessionService:  config.SessionService,
		MemoryService:   config.MemoryService,
		Logger:          config.Logger,
	}
}

// Run executes the agent with the given user input, creating a new session.
// This is a convenience method for simple single-turn interactions.
func (r *Runner) Run(ctx context.Context, userInput string) (message.Message, error) {
	// Generate a random user ID for this single interaction
	userID := uuid.NewString()

	// Create a new message from the user input
	msg := message.NewUserMessage(userInput)

	// Run with a new session
	return r.RunWithSession(ctx, userID, "", []message.Message{msg})
}

// RunConversation handles a multi-turn conversation with the provided messages.
// This creates a new session for the conversation.
func (r *Runner) RunConversation(ctx context.Context, userID string, messages []message.Message) (message.Message, error) {
	return r.RunWithSession(ctx, userID, "", messages)
}

// RunWithSession executes the agent using an existing or new session.
// If sessionID is empty, a new session will be created.
func (r *Runner) RunWithSession(ctx context.Context, userID, sessionID string, messages []message.Message) (message.Message, error) {
	// Create a trace span for this operation
	ctx, span := observability.StartSpan(ctx, "runner.RunWithSession")
	defer span.End()

	// Ensure we have a valid session
	sess, err := r.getOrCreateSession(ctx, userID, sessionID)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to get or create session: %w", err)
	}

	// Prepare invocation context with the session information
	invocationCtx := &InvocationContext{
		AppName:         r.AppName,
		UserID:          userID,
		SessionID:       sess.ID,
		Session:         sess,
		ArtifactService: r.ArtifactService,
		MemoryService:   r.MemoryService,
		Logger:          r.Logger,
	}

	// Find the appropriate agent to run
	agentToRun := r.findAgentToRun(ctx, sess)

	// If no messages provided, return empty response
	if len(messages) == 0 {
		return message.Message{}, nil
	}

	// Process the last message from the user
	lastMsg := messages[len(messages)-1]

	// Append user message to session and save any artifacts
	if err := r.appendNewMessageToSession(ctx, invocationCtx, lastMsg); err != nil {
		return message.Message{}, fmt.Errorf("failed to append message to session: %w", err)
	}

	// Process the message with the selected agent
	response, err := agentToRun.Process(ctx, lastMsg)
	if err != nil {
		return message.Message{}, fmt.Errorf("agent processing failed: %w", err)
	}

	// Save response to session
	if err := r.appendNewMessageToSession(ctx, invocationCtx, response); err != nil {
		r.Logger.Warn("Failed to save response to session", "error", err)
		// Continue even if saving fails
	}

	return response, nil
}

// RunAsync executes the agent asynchronously and returns a channel for streaming responses.
// This simulates the async behavior from the Python implementation.
func (r *Runner) RunAsync(ctx context.Context, userID, sessionID string, msg message.Message) (<-chan message.Message, <-chan error) {
	responseCh := make(chan message.Message)
	errCh := make(chan error, 1) // Buffered channel for the error

	go func() {
		defer close(responseCh)
		defer close(errCh)

		response, err := r.RunWithSession(ctx, userID, sessionID, []message.Message{msg})
		if err != nil {
			errCh <- err
			return
		}

		// Send the response message
		select {
		case responseCh <- response:
			// Message sent successfully
		case <-ctx.Done():
			// Context was canceled
			errCh <- ctx.Err()
			return
		}
	}()

	return responseCh, errCh
}

// getOrCreateSession retrieves an existing session or creates a new one.
func (r *Runner) getOrCreateSession(ctx context.Context, userID, sessionID string) (*session.Session, error) {
	// If we don't have a session service, create a new in-memory session
	if r.SessionService == nil {
		return session.NewSession(sessionID, r.AppName, userID), nil
	}

	// If sessionID is provided, try to get the existing session
	if sessionID != "" {
		sess, err := r.SessionService.GetSession(ctx, r.AppName, userID, sessionID, 0, nil)
		if err == nil {
			return sess, nil
		}
		// If there's an error, log it and continue to create a new session
		r.Logger.Info("Failed to get existing session, creating new one", "error", err)
	}

	// Create a new session
	return r.SessionService.CreateSession(ctx, r.AppName, userID, "")
}

// findAgentToRun determines which agent should continue the conversation.
// Currently this uses the root agent, but could be extended to support agent transfers.
func (r *Runner) findAgentToRun(ctx context.Context, sess *session.Session) *agent.Agent {
	// In a more complex implementation, we would analyze the session events
	// to determine if a transfer to a sub-agent has occurred
	return r.RootAgent
}

// appendNewMessageToSession adds a new message to the session and saves any artifacts.
func (r *Runner) appendNewMessageToSession(ctx context.Context, invCtx *InvocationContext, msg message.Message) error {
	// If we don't have a session service, nothing to do
	if r.SessionService == nil {
		return nil
	}

	// Create a message event
	msgEvent := event.NewMessageEvent(msg)

	// Save artifacts if this is a user message with artifacts
	if msg.Role == message.RoleUser && r.ArtifactService != nil && len(msg.Artifacts) > 0 {
		for i, artifact := range msg.Artifacts {
			artifactID := fmt.Sprintf("%s-%d", uuid.NewString(), i)
			if err := r.ArtifactService.SaveArtifact(ctx, invCtx.SessionID, artifactID, artifact.Data, artifact.MimeType); err != nil {
				return fmt.Errorf("failed to save artifact: %w", err)
			}
			// Update artifact reference with ID
			msg.Artifacts[i].ID = artifactID
		}
	}

	// Append the event to the session
	return r.SessionService.AppendEvent(ctx, r.AppName, invCtx.UserID, invCtx.SessionID, msgEvent)
}

// InvocationContext contains contextual information for a single agent invocation.
type InvocationContext struct {
	AppName         string
	UserID          string
	SessionID       string
	Session         *session.Session
	ArtifactService artifact.ArtifactService
	MemoryService   memory.MemoryService
	Logger          *slog.Logger
	StartTime       time.Time
}

// NewInMemoryRunner creates a new runner with in-memory services.
func NewInMemoryRunner(appName string, rootAgent *agent.Agent) *Runner {
	return NewRunner(rootAgent, RunnerConfig{
		AppName:         appName,
		ArtifactService: artifact.NewInMemoryArtifactService(),
		SessionService:  session.NewInMemorySessionService(),
		MemoryService:   memory.NewInMemoryMemoryService(),
		Logger:          slog.Default(),
	})
}
