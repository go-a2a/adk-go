// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-a2a/adk-go/artifact"
	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/session"
)

// ErrNoArtifactService is returned when attempting to use artifact functions without a configured artifact service.
var ErrNoArtifactService = errors.New("artifact service not initialized")

// ReadonlyContext provides read-only access to the current session state and event data.
type ReadonlyContext struct {
	// Context is the underlying context.Context for cancellation and values
	ctx context.Context

	// AppName is the name of the application
	appName string

	// UserID is the identifier for the user
	userID string

	// SessionID is the identifier for the session
	sessionID string

	// EventID is the identifier for the current event
	eventID string

	// InitialUserContent is the initial user message content
	initialUserContent string

	// ArtifactService provides access to artifacts
	artifactService artifact.ArtifactService

	// sessionState is a reference to the current session state
	sessionState *session.State
}

// NewReadonlyContext creates a new ReadonlyContext with the provided configuration.
func NewReadonlyContext(ctx context.Context, appName, userID, sessionID, eventID string, initialUserContent string, artifactService artifact.ArtifactService, sessionState *session.State) *ReadonlyContext {
	return &ReadonlyContext{
		ctx:                ctx,
		appName:            appName,
		userID:             userID,
		sessionID:          sessionID,
		eventID:            eventID,
		initialUserContent: initialUserContent,
		artifactService:    artifactService,
		sessionState:       sessionState,
	}
}

// Context returns the underlying context.Context.
func (rc *ReadonlyContext) Context() context.Context {
	return rc.ctx
}

// AppName returns the application name.
func (rc *ReadonlyContext) AppName() string {
	return rc.appName
}

// UserID returns the user identifier.
func (rc *ReadonlyContext) UserID() string {
	return rc.userID
}

// SessionID returns the session identifier.
func (rc *ReadonlyContext) SessionID() string {
	return rc.sessionID
}

// EventID returns the event identifier.
func (rc *ReadonlyContext) EventID() string {
	return rc.eventID
}

// UserContent returns the initial user message content.
func (rc *ReadonlyContext) UserContent() string {
	return rc.initialUserContent
}

// GetState returns the value for a key from the session state.
func (rc *ReadonlyContext) GetState(key string) (any, bool) {
	return rc.sessionState.Get(key)
}

// GetAppState returns all app-specific state values.
func (rc *ReadonlyContext) GetAppState() map[string]any {
	return rc.sessionState.GetAppState()
}

// GetUserState returns all user-specific state values.
func (rc *ReadonlyContext) GetUserState() map[string]any {
	return rc.sessionState.GetUserState()
}

// LoadArtifact loads an artifact from the artifact service.
func (rc *ReadonlyContext) LoadArtifact(filename string, version *int) (*artifact.Part, error) {
	if rc.artifactService == nil {
		return nil, ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(rc.ctx, "ReadonlyContext.LoadArtifact")
	defer span.End()

	observability.Logger(ctx).DebugContext(ctx, "Loading artifact",
		slog.String("filename", filename),
		slog.Any("version", version),
	)

	return rc.artifactService.LoadArtifact(ctx, rc.appName, rc.userID, rc.sessionID, filename, version)
}

// ListArtifactKeys lists all artifact keys for the current session.
func (rc *ReadonlyContext) ListArtifactKeys() ([]string, error) {
	if rc.artifactService == nil {
		return nil, ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(rc.ctx, "ReadonlyContext.ListArtifactKeys")
	defer span.End()

	return rc.artifactService.ListArtifactKeys(ctx, rc.appName, rc.userID, rc.sessionID)
}

// ListVersions lists all versions of an artifact.
func (rc *ReadonlyContext) ListVersions(filename string) ([]int, error) {
	if rc.artifactService == nil {
		return nil, ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(rc.ctx, "ReadonlyContext.ListVersions")
	defer span.End()

	return rc.artifactService.ListVersions(ctx, rc.appName, rc.userID, rc.sessionID, filename)
}

// CallbackContext extends ReadonlyContext with mutation capabilities for agent callbacks.
type CallbackContext struct {
	*ReadonlyContext

	// actions stores the event actions for the callback response
	actions *event.EventActions
}

// NewCallbackContext creates a new CallbackContext with the given parameters.
func NewCallbackContext(readonlyCtx *ReadonlyContext, actions *event.EventActions) *CallbackContext {
	if actions == nil {
		actions = event.NewEventActions()
	}

	return &CallbackContext{
		ReadonlyContext: readonlyCtx,
		actions:         actions,
	}
}

// State returns the session state, allowing direct mutation.
func (cc *CallbackContext) State() *session.State {
	return cc.sessionState
}

// SaveArtifact saves an artifact to the artifact service.
func (cc *CallbackContext) SaveArtifact(filename string, artifact *artifact.Part) (int, error) {
	if cc.artifactService == nil {
		return -1, ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(cc.ctx, "CallbackContext.SaveArtifact")
	defer span.End()

	observability.Logger(ctx).DebugContext(ctx, "Saving artifact",
		slog.String("filename", filename),
		slog.String("mimeType", artifact.MimeType),
		slog.Int("dataSize", len(artifact.Data)),
	)

	version, err := cc.artifactService.SaveArtifact(
		ctx, cc.appName, cc.userID, cc.sessionID, filename, artifact,
	)
	if err != nil {
		return -1, fmt.Errorf("failed to save artifact: %w", err)
	}

	// Record artifact version in the event actions
	cc.actions.AddArtifactDelta(filename, version)

	return version, nil
}

// DeleteArtifact deletes an artifact from the artifact service.
func (cc *CallbackContext) DeleteArtifact(filename string) error {
	if cc.artifactService == nil {
		return ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(cc.ctx, "CallbackContext.DeleteArtifact")
	defer span.End()

	observability.Logger(ctx).DebugContext(ctx, "Deleting artifact",
		slog.String("filename", filename),
	)

	return cc.artifactService.DeleteArtifact(ctx, cc.appName, cc.userID, cc.sessionID, filename)
}

// TransferTo sets the target agent for a transfer.
func (cc *CallbackContext) TransferTo(agentName string) {
	cc.actions.WithTransferToAgent(agentName)
}

// Escalate marks the conversation for escalation.
func (cc *CallbackContext) Escalate() {
	cc.actions.WithEscalate(true)
}

// SkipSummarization controls whether function responses should be summarized.
func (cc *CallbackContext) SkipSummarization(skip bool) {
	cc.actions.WithSkipSummarization(skip)
}

// RequestAuthConfig adds an authentication configuration requirement.
func (cc *CallbackContext) RequestAuthConfig(key string, value any) {
	cc.actions.AddRequestedAuthConfig(key, value)
}

// EventActions returns the current event actions.
func (cc *CallbackContext) EventActions() *event.EventActions {
	return cc.actions
}
