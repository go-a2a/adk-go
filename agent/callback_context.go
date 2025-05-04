// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"github.com/go-a2a/adk-go/event"
)

// CallbackContext extends [ReadonlyContext] with mutation capabilities for agent callbacks.
type CallbackContext struct {
	*ReadOnlyContext

	// eventActions stores the event eventActions for the callback response.
	eventActions *event.EventActions
}

// NewCallbackContext creates a new [CallbackContext] with the given parameters.
func NewCallbackContext(ic *InvocationContext, actions *event.EventActions) *CallbackContext {
	if actions == nil {
		actions = event.NewEventActions()
	}

	return &CallbackContext{
		ReadOnlyContext: &ReadOnlyContext{
			invocationContext: ic,
		},
		eventActions: actions,
	}
}
