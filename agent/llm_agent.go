// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/event"
	"github.com/go-a2a/adk-go/memory"
	"github.com/go-a2a/adk-go/model"
)

// ToolContext is the context of the tool.
//
// This class provides the context for a tool invocation, including access to
// the invocation context, function call ID, event actions, and authentication
// response. It also provides methods for requesting credentials, retrieving
// authentication responses, listing artifacts, and searching memory.
type ToolContext struct {
	*CallbackContext

	invocationContext *InvocationContext
	functionCallID    string
}

func NewToolContext(ic *InvocationContext, eventActions *event.EventActions, functionCallID string) *ToolContext {
	return &ToolContext{
		CallbackContext: &CallbackContext{
			eventActions: eventActions,
		},
		invocationContext: ic,
		functionCallID:    functionCallID,
	}
}

func (tc *ToolContext) Actions() *event.EventActions {
	return tc.eventAction
}

func (tc *ToolContext) RequestCredential(authConfig any /* AuthConfig */) {}
func (tc *ToolContext) GetAuthResponse(authConfig any /* AuthConfig */) /* AuthCredential */ any {
	return nil
}
func (tc *ToolContext) ListArtifacts() []string {
	return nil
}
func (tc *ToolContext) SearchMemory(query string) *memory.SearchMemoryResponse {
	return nil
}

type BeforeModelCallback func(cctx *CallbackContext, req model.LLMRequest) model.LLMResponse

type AfterModelCallback func(cctx *CallbackContext, req model.LLMResponse) model.LLMResponse

type BeforeToolCallback func(tool *genai.Tool, m map[string]any, tctx *ToolContext) map[string]any

type AfterToolCallback func(tool *genai.Tool, m map[string]any, tctx *ToolContext, m2 map[string]any) map[string]any

// LLMAgent is the LLM based Agent.
type LLMAgent struct {
	// The model to use for the agent.
	//
	// When not set, the agent will inherit the model from its ancestor.
	Model model.Model

	// Instructions for the LLM model, guiding the agent's behavior.
	Instruction string // Union[str, InstructionProvider] = ''

	// GlobalInstruction instructions for all the agents in the entire agent tree.
	//
	// global_instruction ONLY takes effect in root agent.
	//
	// For example: use global_instruction to make all agents have a stable identity
	// or personality.
	GlobalInstruction string // Union[str, InstructionProvider] = ''

	// Tools available to this agent.
	Tools []*genai.Tool
}
