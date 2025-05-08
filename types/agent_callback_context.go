// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"errors"

	"google.golang.org/genai"
)

// CallbackContext provides the context of various callbacks within an agent run.
type CallbackContext struct {
	*ReadOnlyContext

	eventActions *EventActions

	state *State
}

type CallbackContextOption func(*CallbackContext)

func WithEventActions(eventActions *EventActions) CallbackContextOption {
	return func(cc *CallbackContext) {
		cc.eventActions = eventActions
	}
}

// NewCallbackContext creates a new [*CallbackContext] with the given args.
func NewCallbackContext(invocationContext *InvocationContext, opts ...CallbackContextOption) *CallbackContext {
	cc := &CallbackContext{
		ReadOnlyContext: NewReadOnlyContext(invocationContext),
		eventActions:    new(EventActions),
	}
	for _, opt := range opts {
		opt(cc)
	}

	cc.state = NewState(invocationContext.Session.State(), cc.eventActions.StateDelta)

	return cc
}

// State returns the delta-aware state of the current session.
func (cc *CallbackContext) State() *State {
	return cc.state
}

// UserContent returns the user content that started this invocation. READONLY field.
func (cc *CallbackContext) UserContent() *genai.Content {
	return cc.invocationContext.UserContent
}

// LoadArtifact loads an artifact attached to the current session.
func (cc *CallbackContext) LoadArtifact(ctx context.Context, filename string, version int) (*genai.Part, error) {
	artifactSvc := cc.invocationContext.ArtifactService
	if artifactSvc == nil {
		return nil, errors.New("artifact service is not initialized")
	}

	return artifactSvc.LoadArtifact(ctx,
		cc.invocationContext.AppName(),
		cc.invocationContext.UserID(),
		cc.invocationContext.Session.ID(),
		filename,
		version,
	)
}

// SaveArtifact saves an artifact and records it as delta for the current session.
func (cc *CallbackContext) SaveArtifact(ctx context.Context, filename string, artifact *genai.Part) (int, error) {
	artifactSvc := cc.invocationContext.ArtifactService
	if artifactSvc == nil {
		return 0, errors.New("artifact service is not initialized")
	}

	version, err := artifactSvc.SaveArtifact(
		ctx,
		cc.invocationContext.AppName(),
		cc.invocationContext.UserID(),
		cc.invocationContext.Session.ID(),
		filename,
		artifact,
	)
	if err != nil {
		return 0, err
	}

	cc.eventActions.ArtifactDelta[filename] = version
	return version, nil
}
