// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"github.com/go-a2a/adk-go/types"
)

// SingleFlow is the LLM flows that handles tools calls.
//
// A single flow only consider an agent itself and tools.
// No sub-agents are allowed for single flow.
type SingleFlow struct {
	*LLMFlow
}

var _ types.Flow = (*SingleFlow)(nil)

// NewSingleFlow creates a new [SingleFlow] with the default [types.LLMRequestProcessor] and [types.LLMResponseProcessor].
func NewSingleFlow() *SingleFlow {
	flow := &SingleFlow{
		LLMFlow: NewLLMFlow(),
	}
	flow.LLMFlow.WithRequestProcessors(SingleRequestProcessor()...)
	flow.LLMFlow.WithResponseProcessors(SingleResponseProcessor()...)

	return flow
}

// SingleRequestProcessor returns the default [types.LLMRequestProcessor] for [SingleFlow].
func SingleRequestProcessor() []types.LLMRequestProcessor {
	return []types.LLMRequestProcessor{
		&BasicLLMRequestProcessor{},
		&AuthLLMRequestProcessor{},
		&InstructionsLlmRequestProcessor{},
		&IdentityLlmRequestProcessor{},
		&ContentLLMRequestProcessor{},
		// Some implementations of NL Planning mark planning contents as thoughts
		// in the post processor. Since these need to be unmarked, NL Planning
		// should be after contents.
		&NLPlanningRequestProcessor{},
		// Code execution should be after the contents as it mutates the contents
		// to optimize data files.
		&CodeExecutionRequestProcessor{},
	}
}

// SingleResponseProcessor returns the default [types.LLMResponseProcessor] for [SingleFlow].
func SingleResponseProcessor() []types.LLMResponseProcessor {
	return []types.LLMResponseProcessor{
		&NLPlanningResponseProcessor{},
		&CodeExecutionResponseProcessor{},
	}
}
