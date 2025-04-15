// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
	"github.com/go-a2a/adk-go/pkg/model/models"
)

// LlmRequestProcessor processes LLM requests before they are sent to the model.
type LlmRequestProcessor interface {
	// Run processes the LLM request and returns a channel of events.
	Run(ctx *flow.LlmFlowContext, request *models.LlmRequest) (<-chan event.Event, error)
}

// LlmResponseProcessor processes LLM responses after they are received from the model.
type LlmResponseProcessor interface {
	// Run processes the LLM response and returns a channel of events.
	Run(ctx *flow.LlmFlowContext, response *models.LlmResponse) (<-chan event.Event, error)
}
