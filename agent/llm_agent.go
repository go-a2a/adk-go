// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"strings"

	"github.com/go-json-experiment/json"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/flow/llmflow"
	"github.com/go-a2a/adk-go/internal/pool"
	"github.com/go-a2a/adk-go/internal/xiter"
	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/tool/tools"
	"github.com/go-a2a/adk-go/types"
)

// LLMAgent represents an agent powered by a Large Language Model.
type LLMAgent struct {
	base *types.BaseAgent

	// The model to use for the agent.
	//
	// When not set, the agent will inherit the model from its ancestor.
	model any // string | [*model.BaseLLM]

	// Instructions for the LLM model, guiding the agent's behavior.
	instruction any // string | [InstructionProvider]

	// Instructions for all the agents in the entire agent tree.
	//
	// global_instruction ONLY takes effect in root agent.
	//
	// For example: use global_instruction to make all agents have a stable identity
	// or personality.
	globalInstruction any // string | [InstructionProvider]

	// Tools available to this agent.
	tools []any // [tools.Function] | [Tool] | [Toolset]

	// generateContentConfig is the additional content generation configurations.
	//
	// NOTE(adk): not all fields are usable, e.g. tools must be configured via `tools`,
	// thinking_config must be configured via [planner] in [LLMAgent].
	//
	// For example: use this config to adjust model temperature, configure safety
	// settings, etc.
	generateContentConfig *genai.GenerateContentConfig

	// Disallows LLM-controlled transferring to the parent agent.
	disallowTransferToParent bool

	// Disallows LLM-controlled transferring to the peer agents.
	disallowTransferToPeers bool

	// includeContents whether to include contents in the model request.
	//
	// When set to 'none', the model request will not include any contents, such as
	// user messages, tool results, etc.
	includeContents types.IncludeContents

	// The input schema when agent is used as a tool.
	inputSchema *genai.Schema

	// The output schema when agent replies.
	//
	// NOTE: when this is set, agent can ONLY reply and CANNOT use any tools, such as
	// function tools, RAGs, agent transfer, etc.
	outputSchema *genai.Schema

	// The key in session state to store the output of the agent.
	//
	// Typically use cases:
	// - Extracts agent reply for later use, such as in tools, callbacks, etc.
	// - Connects agents to coordinate with each other.
	outputKey string

	// Instructs the agent to make a plan and execute it step by step.
	//
	// NOTE: to use model's built-in thinking features, set the `thinking_config`
	// field in `google.adk.planners.built_in_planner`.
	planner types.Planner

	// Allow agent to execute code blocks from model responses using the provided
	// CodeExecutor.
	//
	// Check out available code executions in `codeexecutor` package.
	//
	// NOTE: to use model's built-in code executor, don't set this field, add
	// `google.adk.tools.built_in_code_execution` to tools instead.
	codeExecutor types.CodeExecutor

	// TODO(adk-python): remove below fields after migration.
	// These fields are added back for easier migration.
	examples any // Optional[ExamplesUnion] = None

	// Callback or list of callbacks to be called before calling the LLM.
	//
	// When a list of callbacks is provided, the callbacks will be called in the
	// order they are listed until a callback does not return None.
	beforeModelCallbacks []types.BeforeModelCallback

	// Callback or list of callbacks to be called after calling the LLM.
	//
	// When a list of callbacks is provided, the callbacks will be called in the
	// order they are listed until a callback does not return None.
	afterModelCallbacks []types.AfterModelCallback

	// Callback or list of callbacks to be called before calling the tool.
	//
	// When a list of callbacks is provided, the callbacks will be called in the
	// order they are listed until a callback does not return None.
	beforeToolCallbacks []types.BeforeToolCallback

	// Callback or list of callbacks to be called after calling the tool.
	//
	// When a list of callbacks is provided, the callbacks will be called in the
	// order they are listed until a callback does not return None.
	afterToolCallbacks []types.AfterToolCallback
}

var _ types.Agent = (*LLMAgent)(nil)

// AsLLMAgent implements [types.Agent].
func (a *LLMAgent) AsLLMAgent() (types.LLMAgent, bool) {
	return a, true
}

// LLMAgentOption configures an [LLMAgent].
type LLMAgentOption func(*LLMAgent)

// WithModelString sets the model to use.
func WithModelString(model string) LLMAgentOption {
	return func(a *LLMAgent) {
		a.model = model
	}
}

// WithModel sets the model to use.
func WithModel(model types.Model) LLMAgentOption {
	return func(a *LLMAgent) {
		a.model = model
	}
}

// WithInstruction sets the instruction for the agent.
func WithInstruction[T string | types.InstructionProvider](instruction T) LLMAgentOption {
	return func(a *LLMAgent) {
		a.instruction = instruction
	}
}

// WithGlobalInstruction sets the global instruction for the agent.
func WithGlobalInstruction[T string | types.InstructionProvider](instruction T) LLMAgentOption {
	return func(a *LLMAgent) {
		a.globalInstruction = instruction
	}
}

// WithTools sets the [tools.function] for the agent.
func WithFunctionTools(tools ...tools.Function) LLMAgentOption {
	return func(a *LLMAgent) {
		a.tools = []any{tools}
	}
}

// WithTools sets the [Tool] for the agent.
func WithTools(tools ...types.Tool) LLMAgentOption {
	return func(a *LLMAgent) {
		a.tools = []any{tools}
	}
}

// WithToolset sets the [Toolset] for the agent.
func WithToolset(tools ...types.Toolset) LLMAgentOption {
	return func(a *LLMAgent) {
		a.tools = []any{tools}
	}
}

// WithGenerateContentConfig sets the [genai.GenerateContentConfig] for the agent.
func WithGenerateContentConfig(config *genai.GenerateContentConfig) LLMAgentOption {
	return func(a *LLMAgent) {
		a.generateContentConfig = config
	}
}

// WithDisallowTransferToParent prevents transferring control to parent.
func WithDisallowTransferToParent(disallow bool) LLMAgentOption {
	return func(a *LLMAgent) {
		a.disallowTransferToParent = disallow
	}
}

// WithDisallowTransferToPeers prevents transferring control to peers.
func WithDisallowTransferToPeers(disallow bool) LLMAgentOption {
	return func(a *LLMAgent) {
		a.disallowTransferToPeers = disallow
	}
}

// WithIncludeContents sets the [IncludeContents] for the agent.
func WithIncludeContents(includeContents types.IncludeContents) LLMAgentOption {
	return func(a *LLMAgent) {
		a.includeContents = includeContents
	}
}

// WithInputSchema sets the input schema for structured input.
func WithInputSchema(schema *genai.Schema) LLMAgentOption {
	return func(a *LLMAgent) {
		a.inputSchema = schema
	}
}

// WithOutputSchema sets the output schema for structured output.
func WithOutputSchema(schema *genai.Schema) LLMAgentOption {
	return func(a *LLMAgent) {
		a.outputSchema = schema
	}
}

// WithOutputKey sets the key where to store model output in state.
func WithOutputKey(key string) LLMAgentOption {
	return func(a *LLMAgent) {
		a.outputKey = key
	}
}

// WithPlanner sets the planner for the agent.
func WithPlanner(plan types.Planner) LLMAgentOption {
	return func(a *LLMAgent) {
		a.planner = plan
	}
}

// WithCodeExecutor sets the codeExecutor for the agent.
func WithCodeExecutor(codeExecutor types.CodeExecutor) LLMAgentOption {
	return func(a *LLMAgent) {
		a.codeExecutor = codeExecutor
	}
}

// WithExamples sets the examples for the agent.
func WithExamples(examples any) LLMAgentOption {
	return func(a *LLMAgent) {
		a.examples = examples
	}
}

// WithBeforeModelCallback adds a callback to run before sending a request to the model.
func WithBeforeModelCallback(callback types.BeforeModelCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.beforeModelCallbacks = append(a.beforeModelCallbacks, callback)
	}
}

// WithAfterModelCallback adds a callback to run after receiving a response from the model.
func WithAfterModelCallback(callback types.AfterModelCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.afterModelCallbacks = append(a.afterModelCallbacks, callback)
	}
}

// WithBeforeToolCallback adds a callback to run before executing a tool.
func WithBeforeToolCallback(callback types.BeforeToolCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.beforeToolCallbacks = append(a.beforeToolCallbacks, callback)
	}
}

// WithAfterToolCallback adds a callback to run after executing a tool.
func WithAfterToolCallback(callback types.AfterToolCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.afterToolCallbacks = append(a.afterToolCallbacks, callback)
	}
}

// NewLLMAgent creates a new [LLMAgent] with the given name and options.
func NewLLMAgent(ctx context.Context, name string, opts ...LLMAgentOption) (*LLMAgent, error) {
	agent := &LLMAgent{
		base: types.NewBaseAgent(name),
	}
	for _, opt := range opts {
		opt(agent)
	}

	// Validate configuration
	if err := agent.validateConfig(ctx); err != nil {
		return nil, fmt.Errorf("invalid agent configuration: %w", err)
	}

	return agent, nil
}

// Name implements [types.Agent].
func (a *LLMAgent) Name() string {
	return a.base.Name()
}

// Description implements [types.Agent].
func (a *LLMAgent) Description() string {
	return a.base.Description()
}

// ParentAgent implements [types.Agent].
func (a *LLMAgent) ParentAgent() types.Agent {
	return a.base.ParentAgent()
}

// SubAgents implements [types.Agent].
func (a *LLMAgent) SubAgents() []types.Agent {
	return a.base.SubAgents()
}

// BeforeAgentCallbacks implements [types.Agent].
func (a *LLMAgent) BeforeAgentCallbacks() []types.AgentCallback {
	return a.base.BeforeAgentCallbacks()
}

// AfterAgentCallbacks implements [types.Agent].
func (a *LLMAgent) AfterAgentCallbacks() []types.AgentCallback {
	return a.base.AfterAgentCallbacks()
}

// CanonicalModel returns the resolved model field as [model.Model].
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) CanonicalModel(ctx context.Context) (types.Model, error) {
	switch m := a.model.(type) {
	case types.Model:
		return m, nil
	case string:
		model.GetRegistry().NewLLM(ctx, m)
	}

	ancestorAgent := a.base.ParentAgent()
	for {
		if llmAgent, ok := ancestorAgent.(*LLMAgent); ok {
			return llmAgent.CanonicalModel(ctx)
		}
		ancestorAgent = ancestorAgent.ParentAgent()
		if ancestorAgent == nil {
			break
		}
	}

	return nil, fmt.Errorf("no model found for %s", a.model)
}

// CanonicalInstructions returns the resolved self.instruction field to construct instruction for this agent.
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) CanonicalInstructions(rctx *types.ReadOnlyContext) string {
	switch inst := a.instruction.(type) {
	case string:
		return inst
	case types.InstructionProvider:
		return inst(rctx)
	default:
		return ""
	}
}

// CanonicalGlobalInstruction returns the resolved self.instruction field to construct global instruction.
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) CanonicalGlobalInstruction(rctx *types.ReadOnlyContext) (string, bool) {
	switch ginst := a.globalInstruction.(type) {
	case string:
		return ginst, false
	case types.InstructionProvider:
		return ginst(rctx), true
	default:
		return "", false
	}
}

// CanonicalTool returns the resolved tools field as a list of [Tool] based on the context.
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) CanonicalTool(rctx *types.ReadOnlyContext) []types.Tool {
	resolvedTools := []types.Tool{}
	for _, tool := range a.tools {
		resolvedTools = append(resolvedTools, a.parseTool(tool, rctx)...)
	}
	return resolvedTools
}

// parseTool parses the tool arg type and returns a list of [Tool].
func (a *LLMAgent) parseTool(tool any, rctx *types.ReadOnlyContext) []types.Tool {
	switch tool := tool.(type) {
	case types.Tool:
		return []types.Tool{tool}
	case tools.Function:
		return []types.Tool{tools.NewFunctionTool(tool)}
	case types.Toolset:
		return tool.GetTools(rctx)
	}
	return nil
}

func (a *LLMAgent) llmFlow() types.Flow {
	if a.disallowTransferToParent && a.disallowTransferToPeers && len(a.base.SubAgents()) == 0 {
		return llmflow.NewSingleFlow()
	}
	return llmflow.NewAutoFlow()
}

// saveOutputToState saves the model output to state if needed.
func (a *LLMAgent) saveOutputToState(event *types.Event) error {
	if a.outputKey != "" && event.IsFinalResponse() && event.Content != nil && len(event.Content.Parts) > 0 {
		texts := make([]string, 0, len(event.Content.Parts))
		for _, part := range event.Content.Parts {
			if part.Text != "" {
				texts = append(texts, part.Text)
			}
		}

		result := strings.Join(texts, "")
		if a.outputSchema != nil {
			sb := pool.String.Get()
			if err := json.MarshalWrite(sb, a.outputSchema, json.DefaultOptionsV2()); err != nil {
				return err
			}
			result = sb.String()
			pool.String.Put(sb)
		}
		event.Actions.StateDelta[a.outputKey] = result
	}

	return nil
}

// GenerateContentConfig returns the [*genai.GenerateContentConfig] for [LLMAgent] agent.
func (a *LLMAgent) GenerateContentConfig() *genai.GenerateContentConfig {
	return a.generateContentConfig
}

// DisallowTransferToParent reports whether teh disallows LLM-controlled transferring to the parent agent.
func (a *LLMAgent) DisallowTransferToParent() bool {
	return a.disallowTransferToParent
}

// DisallowTransferToPeers reports whether teh disallows LLM-controlled transferring to the peer agents.
func (a *LLMAgent) DisallowTransferToPeers() bool {
	return a.disallowTransferToPeers
}

// IncludeContents returns the mode of include contents in the model request.
func (a *LLMAgent) IncludeContents() types.IncludeContents {
	return a.includeContents
}

// InputSchema returns the structured input.
func (a *LLMAgent) InputSchema() *genai.Schema {
	return a.inputSchema
}

// OutputSchema returns the structured output.
func (a *LLMAgent) OutputSchema() *genai.Schema {
	return a.outputSchema
}

// OutputKey returns the key in session state to store the output of the agent.
func (a *LLMAgent) OutputKey() string {
	return a.outputKey
}

// Planner returns the instructs the agent to make a plan and execute it step by step.
func (a *LLMAgent) Planner() types.Planner {
	return a.planner
}

// CodeExecutor returns the code executor for the agent.
func (a *LLMAgent) CodeExecutor() types.CodeExecutor {
	return a.codeExecutor
}

// BeforeModelCallbacks returns the resolved self.before_model_callback field as a list of _SingleBeforeModelCallback.
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) BeforeModelCallbacks() []types.BeforeModelCallback {
	return a.beforeModelCallbacks
}

// AfterModelCallbacks returns the resolved self.before_tool_callback field as a list of BeforeToolCallback.
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) AfterModelCallbacks() []types.AfterModelCallback {
	return a.afterModelCallbacks
}

// BeforeToolCallbacks returns the resolved self.before_tool_callback field as a list of BeforeToolCallback.
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) BeforeToolCallback() []types.BeforeToolCallback {
	return a.beforeToolCallbacks
}

// AfterToolCallbacks returns the resolved self.after_tool_callback field as a list of AfterToolCallback.
//
// This method is only for use by Agent Development Kit.
func (a *LLMAgent) AfterToolCallbacks() []types.AfterToolCallback {
	return a.afterToolCallbacks
}

// Execute implements [types.Agent].
func (a *LLMAgent) Execute(ctx context.Context, ictx *types.InvocationContext) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		for event, err := range a.llmFlow().Run(ctx, ictx) {
			if err != nil {
				xiter.Error[types.Event](err)
				return
			}
			if err := a.saveOutputToState(event); err != nil {
				if !yield(nil, err) {
					return
				}
			}

			if !yield(event, nil) {
				return
			}
		}
	}
}

// ExecuteLive implements [types.Agent].
func (a *LLMAgent) ExecuteLive(ctx context.Context, ictx *types.InvocationContext) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		for event, err := range a.llmFlow().RunLive(ctx, ictx) {
			if err != nil {
				xiter.Error[types.Event](err)
				return
			}
			if err := a.saveOutputToState(event); err != nil {
				if !yield(nil, err) {
					return
				}
			}

			if !yield(event, nil) {
				return
			}
		}

		if ictx.EndInvocation {
			return
		}
	}
}

// Run implements [types.Agent].
func (a *LLMAgent) Run(ctx context.Context, parentContext *types.InvocationContext) iter.Seq2[*types.Event, error] {
	return a.base.Run(ctx, parentContext)
}

// RunLive implements [types.Agent].
func (a *LLMAgent) RunLive(ctx context.Context, parentContext *types.InvocationContext) iter.Seq2[*types.Event, error] {
	return a.base.RunLive(ctx, parentContext)
}

// RootAgent implements [types.Agent].
func (a *LLMAgent) RootAgent() types.Agent {
	return a.base.RootAgent()
}

// FindAgent implements [types.Agent].
func (a *LLMAgent) FindAgent(name string) types.Agent {
	return a.base.FindAgent(name)
}

// FindSubAgent implements [types.Agent].
func (a *LLMAgent) FindSubAgent(name string) types.Agent {
	return a.base.FindSubAgent(name)
}

// validateConfig validates the agent configuration.
func (a *LLMAgent) validateConfig(ctx context.Context) error {
	// Check output schema compatibility
	if a.outputSchema != nil {
		// Output schema cannot coexist with agent transfer configurations
		if !a.disallowTransferToParent || !a.disallowTransferToPeers {
			a.base.Logger().WarnContext(ctx, "invalid config: outputSchema cannot co-exist with agent transfer configurations",
				slog.Bool("disallowTransferToParent", a.disallowTransferToParent),
				slog.Bool("disallowTransferToPeers", a.disallowTransferToPeers),
			)
			a.disallowTransferToParent = true
			a.disallowTransferToPeers = true
		}

		// Output schema requires no tools
		if len(a.tools) > 0 {
			return errors.New("invalid config: if output_schema is set, tools must be empty")
		}

		// Output schema requires no sub agents
		if len(a.base.SubAgents()) > 0 {
			return errors.New("invalid config: if output_schema is set, sub_agents must be empty to disable agent transfer")
		}
	}

	return nil
}
