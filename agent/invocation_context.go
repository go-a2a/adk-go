// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/artifact"
	"github.com/go-a2a/adk-go/memory"
	"github.com/go-a2a/adk-go/session"
)

// ErrLLMCallsLimitExceeded error thrown when the number of LLM calls exceed the limit.
var ErrLLMCallsLimitExceeded = errors.New("number of LLM calls exceed the limit")

// InvocationCostManager is a container to keep track of the cost of invocation.
//
// While we don't expected the metrics captured here to be a direct
// representatative of monetary cost incurred in executing the current
// invocation, but they, in someways have an indirect affect.
type InvocationCostManager struct {
	numberOfLLMCalls int
}

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
	artifactService artifact.ArtifactService
	sessionService  session.SessionService
	memoryService   memory.MemoryService

	// InvocationID is the id of this invocation context. Readonly.
	InvocationID string

	// Branch is the Branch of the invocation context.
	//
	// The format is like agent_1.agent_2.agent_3, where agent_1 is the parent of
	// agent_2, and agent_2 is the parent of agent_3.
	//
	// Branch is used when multiple sub-agents shouldn't see their peer agents'
	// conversation history.
	Branch string

	// Agent is the current Agent of this invocation context. Readonly.
	Agent any // BaseAgent

	// UserContent is the user content that started this invocation. Readonly.
	UserContent *genai.Content

	// Session is the current session of this invocation context. Readonly.
	session *session.Session

	// EndInvocation whether to end this invocation.
	//
	// Set to True in callbacks or tools to terminate this invocation.
	EndInvocation bool

	// LiveRequestQueue is the queue to receive live requests.
	LiveRequestQueue *LiveRequestQueue

	// ActiveStreamingTools is the running streaming tools of this invocation.
	ActiveStreamingTools map[string]ActiveStreamingTool

	// TranscriptionCache caches necessary, data audio or contents, that are needed by transcription.
	TranscriptionCache any // []TranscriptionEntry

	// RunConfig configurations for live agents under this invocation.
	RunConfig RunConfig

	// InvocationCostManager a container to keep track of different kinds of costs incurred as a part
	// of this invocation.
	InvocationCostManager InvocationCostManager

	appName   string
	userID    string
	sessionID string
	startTime time.Time
}

// NewInvocationContext creates a new InvocationContext.
func NewInvocationContext(ctx context.Context, appName string, sess *session.Session) *InvocationContext {
	ictx := &InvocationContext{
		appName: appName,
		session: sess,
		// artifactService: artifact.NewInMemoryArtifactService(),
		// sessionService:  session.NewInMemorySessionService(),
		memoryService: memory.NewInMemoryMemoryService(),
	}

	// for _, o := range opts {
	// 	ictx = o.apply(ictx)
	// }

	return ictx
}

// AppName returns the name of the application associated with this invocation context.
func (ic *InvocationContext) AppName() string {
	return ic.appName
}

// UserID returns the name of the application associated with this invocation context.
func (ic *InvocationContext) UserID() string {
	return ic.userID
}

// Session returns the session associated with this invocation context.
func (ictx *InvocationContext) Session() *session.Session {
	return ictx.session
}

// ArtifactService returns the [artifact.ArtifactService] associated with this invocation context.
func (ictx *InvocationContext) ArtifactService() artifact.ArtifactService {
	return ictx.artifactService
}

// SessionService returns the [session.SessionService] associated with this invocation context.
func (ictx *InvocationContext) SessionService() session.SessionService {
	return ictx.sessionService
}

// MemoryService returns the [memory.MemoryService] associated with this invocation context.
func (ictx *InvocationContext) MemoryService() memory.MemoryService {
	return ictx.memoryService
}

// IncrementLLMCallCount tracks number of llm calls made.
//
// Raises:
// LlmCallsLimitExceededError: If number of llm calls made exceed the set threshold.
func (ic *InvocationContext) IncrementLLMCallCount() {
	// self._invocation_cost_manager.increment_and_enforce_llm_calls_limit(
	//     self.run_config
	// )
}

func NewInvocationContextID() string {
	return "e-" + uuid.NewString()
}
