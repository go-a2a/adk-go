// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/flow"
	"github.com/go-a2a/adk-go/flow/llmflow/processor"
)

// SingleFlow is an LLM flow that handles tool calls.
// It is designed for a single agent with tools and does not allow sub-agents.
type SingleFlow struct {
	*BaseLlmFlow
}

var _ flow.Flow = (*SingleFlow)(nil)

// NewSingleFlow creates a new SingleFlow with the specified model ID and options.
func NewSingleFlow(modelID string, config *genai.GenerateContentConfig) *SingleFlow {
	flow := &SingleFlow{
		BaseLlmFlow: NewBaseLlmFlow(modelID, config),
	}

	// Add request processors in specific order
	flow.AddRequestProcessor(processor.NewBasicProcessor())
	flow.AddRequestProcessor(processor.NewIdentityProcessor())
	flow.AddRequestProcessor(processor.NewInstructionsProcessor())
	flow.AddRequestProcessor(processor.NewContentsProcessor())
	flow.AddRequestProcessor(processor.NewCodeExecutionRequestProcessor())

	// Add response processors
	flow.AddResponseProcessor(processor.NewCodeExecutionResponseProcessor())

	return flow
}
