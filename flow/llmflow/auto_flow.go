// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"github.com/go-a2a/adk-go/types"
)

// AutoFlow is [SingleFlow] with agent transfer capability.
//
// Agent transfer is allowed in the following direction:
//
//  1. from parent to sub-agent;
//  2. from sub-agent to parent;
//  3. from sub-agent to its peer agents;
//
// For peer-agent transfers, it's only enabled when all below conditions are met:
//
//   - The parent agent is also of AutoFlow;
//   - `disallow_transfer_to_peer` option of this agent is False (default).
//
// Depending on the target agent flow type, the transfer may be automatically
// reversed. The condition is as below:
//
//   - If the flow type of the tranferee agent is also auto, transfee agent will
//     remain as the active agent. The transfee agent will respond to the user's
//     next message directly.
//   - If the flow type of the transfere agent is not auto, the active agent will
//     be reversed back to previous agent.
//
// TODO(adk-python): allow user to config auto-reverse function.
type AutoFlow struct {
	*LLMFlow
}

var _ types.Flow = (*AutoFlow)(nil)

// NewAutoFlow creates a new [AutoFlow] with the default [types.LLMRequestProcessor] and [types.LLMResponseProcessor].
func NewAutoFlow() *AutoFlow {
	flow := &AutoFlow{
		LLMFlow: NewLLMFlow(),
	}
	flow.LLMFlow.WithRequestProcessors(AutoRequestProcessor()...)
	flow.LLMFlow.WithResponseProcessors(AutoResponseProcessor()...)

	return flow
}

// AutoRequestProcessor returns the default [types.LLMRequestProcessor] for [AutoFlow].
func AutoRequestProcessor() []types.LLMRequestProcessor {
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
		&AgentTransferLlmRequestProcessor{},
	}
}

// AutoResponseProcessor returns the default [types.LLMResponseProcessor] for [AutoFlow].
func AutoResponseProcessor() []types.LLMResponseProcessor {
	return []types.LLMResponseProcessor{
		&NLPlanningResponseProcessor{},
		&CodeExecutionResponseProcessor{},
	}
}
