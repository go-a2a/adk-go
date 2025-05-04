// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/session"
)

// Flow represents a basic flow that can be executed in a session.
type Flow interface {
	// Run executes the flow and returns a channel of events.
	Run(ctx context.Context, sess *session.Session) (<-chan event.Event, error)

	// RunLive executes the flow in streaming mode and returns a channel of events.
	RunLive(ctx context.Context, sess *session.Session) (<-chan event.Event, error)
}
