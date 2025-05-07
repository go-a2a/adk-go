// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/google/uuid"
	"google.golang.org/genai"
)

// InvocationContext an invocation context represents the data of a single invocation of an agent.
//
// An invocation:
//  1. Starts with a user message and ends with a final response.
//  2. Can contain one or multiple agent calls.
//  3. Is handled by runner.run_async().
//
// An invocation runs an agent until it does not request to transfer to another
// agent.
//
// An agent call:
//  1. Is handled by agent.run().
//  2. Ends when agent.run() ends.
//
// An LLM agent call is an agent with a BaseLLMFlow.
// An LLM agent call can contain one or multiple steps.
//
// An LLM agent runs steps in a loop until:
//  1. A final response is generated.
//  2. The agent transfers to another agent.
//  3. The end_invocation is set to true by any callbacks or tools.
//
// A step:
//  1. Calls the LLM only once and yields its response.
//  2. Calls the tools and yields their responses if requested.
//
// The summarization of the function response is considered another step, since
// it is another llm call.
// A step ends when it's done calling llm and tools, or if the end_invocation
// is set to true at any time.
//
//	┌─────────────────────── invocation ──────────────────────────┐
//	┌──────────── llm_agent_call_1 ────────────┐ ┌─ agent_call_2 ─┐
//	┌──── step_1 ────────┐ ┌───── step_2 ──────┐
//	[call_llm] [call_tool] [call_llm] [transfer]
type InvocationContext struct {
	ArtifactService ArtifactService
	SessionService  SessionService
	MemoryService   MemoryService

	// InvocationID is the id of this invocation context. Readonly.
	InvocationID string

	// Branch is the branch of the invocation context.
	//
	// The format is like agent_1.agent_2.agent_3, where agent_1 is the parent of
	// agent_2, and agent_2 is the parent of agent_3.
	//
	// Branch is used when multiple sub-agents shouldn't see their peer agents'
	// conversation history.
	Branch string

	// Agent is the current agent of this invocation context. Readonly.
	Agent Agent

	// UserContent is the user content that started this invocation. Readonly.
	UserContent *genai.Content

	// Session is the current session of this invocation context. Readonly.
	Session Session

	// EndInvocation whether to end this invocation.
	//
	// Set to True in callbacks or tools to terminate this invocation.
	EndInvocation bool

	// LiveRequestQueue is the queue to receive live requests.
	LiveRequestQueue *LiveRequestQueue

	// ActiveStreamingTools is the running streaming tools of this invocation.
	ActiveStreamingTools map[string]*ActiveStreamingTool

	// TranscriptionCache caches necessary, data audio or contents, that are needed by transcription.
	TranscriptionCache []*TranscriptionEntry

	// RunConfig is the Configurations for live agents under this invocation.
	RunConfig *RunConfig

	// Input is the input provided to the agent.
	Input map[string]any

	// Metadata contains additional information.
	Metadata map[string]any
}

// InvocationContextOption is a function that modifies the [InvocationContext].
type InvocationContextOption func(*InvocationContext)

func WithArtifactService(svc ArtifactService) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.ArtifactService = svc
	}
}

func WithSessionService(svc SessionService) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.SessionService = svc
	}
}

func WithMemoryService(svc MemoryService) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.MemoryService = svc
	}
}

func WithBranch(branch string) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.Branch = branch
	}
}

func WithUserContent(content *genai.Content) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.UserContent = content
	}
}

func WithLiveRequestQueue(liveRequestQueue *LiveRequestQueue) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.LiveRequestQueue = liveRequestQueue
	}
}

func WithActiveStreamingTools(activeStreamingTools map[string]*ActiveStreamingTool) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.ActiveStreamingTools = activeStreamingTools
	}
}

func WithTranscriptionCache(entries ...*TranscriptionEntry) InvocationContextOption {
	return func(ic *InvocationContext) {
		ic.TranscriptionCache = entries
	}
}

// NewInvocationContext creates a new [InvocationContext].
func NewInvocationContext(agent Agent, input map[string]any, runConfig *RunConfig, opts ...InvocationContextOption) *InvocationContext {
	if runConfig == nil {
		runConfig = DefaultRunConfig()
	}

	ic := &InvocationContext{
		Agent:     agent,
		Input:     input,
		RunConfig: runConfig,
		Metadata:  make(map[string]any),
	}
	for _, opt := range opts {
		opt(ic)
	}

	return ic
}

func (c *InvocationContext) AppName() string {
	return c.Session.AppName()
}

func (c *InvocationContext) UserID() string {
	return c.Session.UserID()
}

// SetMetadata sets a metadata value.
func (c *InvocationContext) SetMetadata(key string, value any) {
	c.Metadata[key] = value
}

// GetMetadata gets a metadata value.
func (c *InvocationContext) GetMetadata(key string) any {
	return c.Metadata[key]
}

// NewInvocationContextID generates a new invocation context ID.
func NewInvocationContextID() string {
	return "e-" + uuid.NewString()
}
