// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/session"
)

// ErrNoArtifactService is returned when attempting to use artifact functions without a configured artifact service.
var ErrNoArtifactService = errors.New("artifact service not initialized")

// CallbackContext extends ReadonlyContext with mutation capabilities for agent callbacks.
type CallbackContext struct {
	*ReadOnlyContext

	// actions stores the event actions for the callback response
	actions *event.EventActions
}

// NewCallbackContext creates a new CallbackContext with the given parameters.
func NewCallbackContext(rctx *ReadOnlyContext, actions *event.EventActions) *CallbackContext {
	if actions == nil {
		actions = event.NewEventActions()
	}

	return &CallbackContext{
		ReadOnlyContext: rctx,
		actions:         actions,
	}
}

// InvocationID returns the current invocation id.
func (cc *CallbackContext) InvocationID() string {
	return cc.ReadOnlyContext.InvocationID()
}

// AgentName returns the name of the agent that is currently running.
func (cc *CallbackContext) AgentName() string {
	return cc.ReadOnlyContext.AgentName()
}

// State returns the session state, allowing direct mutation.
func (cc *CallbackContext) State() *session.State {
	return cc.ReadOnlyContext.Session().State
}

// State returns the session state, allowing direct mutation.
func (cc *CallbackContext) UserContent() *genai.Content {
	return cc.invocationContext.userContent
}

// LoadArtifact loads an artifact to the artifact service.
func (cc *CallbackContext) LoadArtifact(filename string, version int) (*genai.Part, error) {
	if cc.invocationContext.artifactService == nil {
		return nil, ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(cc.ctx, "CallbackContext.SaveArtifact")
	defer span.End()

	observability.Logger(ctx).DebugContext(ctx, "Loading artifact",
		slog.String("filename", filename),
		slog.Int("version", version),
	)

	part, err := cc.invocationContext.artifactService.LoadArtifact(
		ctx, cc.invocationContext.appName, cc.invocationContext.userID, cc.invocationContext.sessionID, filename, &version,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to save artifact: %w", err)
	}

	return part, nil
}

// SaveArtifact saves an artifact to the artifact service.
func (cc *CallbackContext) SaveArtifact(filename string, art *genai.Part) (int, error) {
	if cc.invocationContext.artifactService == nil {
		return -1, ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(cc.ctx, "CallbackContext.SaveArtifact")
	defer span.End()

	observability.Logger(ctx).DebugContext(ctx, "Saving artifact",
		slog.String("filename", filename),
		slog.String("mime_type", art.InlineData.MIMEType),
		slog.Int("data_size", len(art.InlineData.Data)),
	)

	version, err := cc.invocationContext.artifactService.SaveArtifact(
		ctx, cc.invocationContext.appName, cc.invocationContext.userID, cc.invocationContext.sessionID, filename, art,
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
	if cc.invocationContext.artifactService == nil {
		return ErrNoArtifactService
	}

	ctx, span := observability.StartSpan(cc.ctx, "CallbackContext.DeleteArtifact")
	defer span.End()

	observability.Logger(ctx).DebugContext(ctx, "Deleting artifact",
		slog.String("filename", filename),
	)

	return cc.invocationContext.artifactService.DeleteArtifact(ctx, cc.invocationContext.appName, cc.invocationContext.userID, cc.invocationContext.sessionID, filename)
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
