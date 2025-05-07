// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"maps"

	"github.com/bytedance/sonic"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/planner"
	"github.com/go-a2a/adk-go/types"
)

// InstructionProvider is a function that provides instructions based on context.
type InstructionProvider func(*types.ReadOnlyContext) string

// BeforeModelCallback is called before sending a request to the model.
type BeforeModelCallback func(*types.CallbackContext, *types.LLMRequest) (*types.LLMResponse, error)

// AfterModelCallback is called after receiving a response from the model.
type AfterModelCallback func(*types.CallbackContext, *types.LLMResponse) (*types.LLMResponse, error)

// BeforeToolCallback is called before executing a tool.
type BeforeToolCallback func(types.Tool, map[string]any, *types.ToolContext) (map[string]any, error)

// AfterToolCallback is called after executing a tool.
type AfterToolCallback func(types.Tool, map[string]any, *types.ToolContext, map[string]any) (map[string]any, error)

// IncludeContents whether to include contents in the model request.
type IncludeContents string

const (
	IncludeContentsNone    IncludeContents = "none"
	IncludeContentsDefault IncludeContents = "default"
)

// LLMAgent represents an agent powered by a Large Language Model.
type LLMAgent struct {
	*Config

	// model represents the LLM to use (string or Model).
	model model.Model

	// instruction provides guidance to the LLM (string or InstructionProvider).
	instruction any

	// globalInstruction provides guidance to all agents in the tree (string or InstructionProvider).
	globalInstruction any

	// generateContentConfig is the additional content generation configurations.
	//
	// NOTE: not all fields are usable, e.g. tools must be configured via `tools`,
	// thinking_config must be configured via `planner` in [LLMAgent].
	//
	// For example: use this config to adjust model temperature, configure safety
	// settings, etc.
	generateContentConfig *genai.GenerateContentConfig

	// disallowTransferToParent prevents transferring control to parent.
	disallowTransferToParent bool

	// disallowTransferToPeers prevents transferring control to peers.
	disallowTransferToPeers bool

	// includeContents whether to include contents in the model request.
	//
	// When set to 'none', the model request will not include any contents, such as
	// user messages, tool results, etc.
	includeContents IncludeContents

	// inputSchema for structured input.
	inputSchema *genai.Schema

	// outputSchema for structured output.
	outputSchema *genai.Schema

	// outputKey where to store model output in state.
	outputKey string

	// planner instructs the agent to make a plan and execute it step by step.
	//
	// NOTE: to use model's built-in thinking features, set the `thinking_config`
	// field in `google.adk.planners.built_in_planner`.
	planner planner.Planner

	// codeExecutor allow agent to execute code blocks from model responses using the provided
	// CodeExecutor.
	//
	// Check out available code executions in `google.adk.code_executor` package.
	//
	// NOTE: to use model's built-in code executor, don't set this field, add
	// `google.adk.tools.built_in_code_execution` to tools instead.
	codeExecutor any // Optional[BaseCodeExecutor] = None

	examples any // Optional[ExamplesUnion] = None

	// beforeModelCallbacks are called before sending a request to the model.
	beforeModelCallbacks []BeforeModelCallback

	// afterModelCallbacks are called after receiving a response from the model.
	afterModelCallbacks []AfterModelCallback

	// beforeToolCallbacks are called before executing a tool.
	beforeToolCallbacks []BeforeToolCallback

	// afterToolCallbacks are called after executing a tool.
	afterToolCallbacks []AfterToolCallback
}

var _ types.Agent = (*LLMAgent)(nil)

// LLMAgentOption configures an [LLMAgent].
type LLMAgentOption func(*LLMAgent)

// WithModel sets the model to use.
func WithModel(model model.Model) LLMAgentOption {
	return func(a *LLMAgent) {
		a.model = model
	}
}

// WithInstruction sets the instruction for the agent.
func WithInstruction[T string | InstructionProvider](instruction T) LLMAgentOption {
	return func(a *LLMAgent) {
		a.instruction = instruction
	}
}

// WithGlobalInstruction sets the global instruction for all agents.
func WithGlobalInstruction[T string | InstructionProvider](instruction T) LLMAgentOption {
	return func(a *LLMAgent) {
		a.globalInstruction = instruction
	}
}

// WithGenerateContentConfig sets the [genai.GenerateContentConfig] for all agents.
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
func WithPlanner(planner planner.Planner) LLMAgentOption {
	return func(a *LLMAgent) {
		a.planner = planner
	}
}

// WithBeforeModelCallback adds a callback to run before sending a request to the model.
func WithBeforeModelCallback(callback BeforeModelCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.beforeModelCallbacks = append(a.beforeModelCallbacks, callback)
	}
}

// WithAfterModelCallback adds a callback to run after receiving a response from the model.
func WithAfterModelCallback(callback AfterModelCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.afterModelCallbacks = append(a.afterModelCallbacks, callback)
	}
}

// WithBeforeToolCallback adds a callback to run before executing a tool.
func WithBeforeToolCallback(callback BeforeToolCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.beforeToolCallbacks = append(a.beforeToolCallbacks, callback)
	}
}

// WithAfterToolCallback adds a callback to run after executing a tool.
func WithAfterToolCallback(callback AfterToolCallback) LLMAgentOption {
	return func(a *LLMAgent) {
		a.afterToolCallbacks = append(a.afterToolCallbacks, callback)
	}
}

// NewLLMAgent creates a new [LLMAgent] with the given name and options.
func NewLLMAgent(name string, opts ...LLMAgentOption) (*LLMAgent, error) {
	agent := &LLMAgent{
		Config: NewConfig(name),
	}
	for _, opt := range opts {
		opt(agent)
	}

	// Validate configuration
	if err := agent.validateConfig(); err != nil {
		return nil, fmt.Errorf("invalid agent configuration: %w", err)
	}

	return agent, nil
}

// Name implements [types.Agent].
func (a *LLMAgent) Name() string {
	return a.name
}

// Execute runs the agent with the given input and context.
func (a *LLMAgent) Execute(ctx context.Context, input map[string]any, opts ...types.RunOption) (*types.LLMResponse, error) {
	// Create a run config with default values
	runConfig := types.DefaultRunConfig()

	// Apply provided options
	for _, opt := range opts {
		opt(runConfig)
	}

	// Create invocation context
	invocationCtx := types.NewInvocationContext(a, input, runConfig)

	// Create a new LLM request
	request, err := a.createLLMRequest(ctx, invocationCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM request: %w", err)
	}

	// Call before model callbacks
	response, err := a.runBeforeModelCallbacks(invocationCtx, request)
	if err != nil {
		return nil, fmt.Errorf("before model callback error: %w", err)
	}

	// If a callback provided a response, use it instead of calling the model
	if response != nil {
		return a.processModelResponse(ctx, invocationCtx, response)
	}

	// Call the LLM model
	var llmResponse *types.LLMResponse
	if runConfig.StreamingEnabled {
		llmResponse, err = a.streamFromModel(ctx, a.model, request)
	} else {
		llmResponse, err = a.model.GenerateContent(ctx, request)
	}
	if err != nil {
		return nil, fmt.Errorf("model generation error: %w", err)
	}

	// Process the response
	return a.processModelResponse(ctx, invocationCtx, llmResponse)
}

// createLLMRequest creates a new [model.LLMRequest] with the given context.
func (a *LLMAgent) createLLMRequest(ctx context.Context, invocationCtx *types.InvocationContext) (*types.LLMRequest, error) {
	// Create the contents
	var contents []*genai.Content

	// Add input content
	if userInput, ok := invocationCtx.Input["input"].(string); ok && userInput != "" {
		contents = append(contents, &genai.Content{
			Role:  model.RoleUser,
			Parts: []*genai.Part{{Text: userInput}},
		})
	}

	// Build the config
	config := &genai.GenerateContentConfig{
		MaxOutputTokens: int32(invocationCtx.RunConfig.MaxTokens),
		Temperature:     genai.Ptr(float32(invocationCtx.RunConfig.Temperature)),
	}

	request := types.NewLLMRequest(a.model.Name(), contents,
		types.WithGenerationConfig(config),
	)

	// Get the instructions
	systemInstruction, err := a.getInstruction(ctx, invocationCtx)
	if err != nil {
		return nil, err
	}
	if systemInstruction != "" {
		request.AppendInstructions(systemInstruction)
	}

	// Add tools to the config if available
	if len(a.tools) > 0 {
		request.AppendTools(a.tools...)
	}

	// Add output schema if available
	if a.outputSchema != nil {
		request.SetOutputSchema(a.outputSchema)
	}

	return request, nil
}

// getInstruction gets the instruction for the agent.
func (a *LLMAgent) getInstruction(ctx context.Context, invocationCtx *types.InvocationContext) (string, error) {
	var instruction string

	// Handle global instruction if this is the root agent
	if a.isRootAgent() && a.globalInstruction != nil {
		switch inst := a.globalInstruction.(type) {
		case string:
			instruction = inst

		case InstructionProvider:
			readonlyCtx := &types.ReadOnlyContext{
				Agent:    a,
				Input:    invocationCtx.Input,
				Metadata: make(map[string]any),
			}
			// Add any context-specific metadata
			maps.Copy(readonlyCtx.Metadata, invocationCtx.RunConfig.Metadata)
			instruction = inst(readonlyCtx)

		default:
			return "", fmt.Errorf("unsupported global instruction type: %T", a.globalInstruction)
		}
	}

	// Handle local instruction
	if a.instruction != nil {
		var localInstruction string
		switch inst := a.instruction.(type) {
		case string:
			localInstruction = inst

		case InstructionProvider:
			readonlyCtx := &types.ReadOnlyContext{
				Agent:    a,
				Input:    invocationCtx.Input,
				Metadata: make(map[string]any),
			}
			// Add any context-specific metadata
			maps.Copy(readonlyCtx.Metadata, invocationCtx.RunConfig.Metadata)
			localInstruction = inst(readonlyCtx)

		default:
			return "", fmt.Errorf("unsupported instruction type: %T", a.instruction)
		}

		if instruction != "" {
			instruction += "\n\n"
		}
		instruction += localInstruction
	}

	a.logger.DebugContext(ctx, "Generated instruction", "instruction", instruction)
	return instruction, nil
}

// isRootAgent checks if this agent is the root agent.
func (a *LLMAgent) isRootAgent() bool {
	// Implementation depends on how agent hierarchy is tracked
	// For simplicity, we'll assume it's the root if it has no parent
	return true
}

// runBeforeModelCallbacks runs all before model callbacks.
func (a *LLMAgent) runBeforeModelCallbacks(invocationCtx *types.InvocationContext, request *types.LLMRequest) (*types.LLMResponse, error) {
	if len(a.beforeModelCallbacks) == 0 {
		return nil, nil
	}

	callbackCtx := types.NewCallbackContext(a, invocationCtx.Input)
	for _, callback := range a.beforeModelCallbacks {
		response, err := callback(callbackCtx, request)
		if err != nil {
			return nil, err
		}
		// If a callback returns a response, short-circuit and use it
		if response != nil {
			return response, nil
		}
	}

	return nil, nil
}

// processModelResponse processes the response from the model.
func (a *LLMAgent) processModelResponse(ctx context.Context, invocationCtx *types.InvocationContext, response *types.LLMResponse) (*types.LLMResponse, error) {
	// Run after model callbacks
	modifiedResponse, err := a.runAfterModelCallbacks(invocationCtx, response)
	if err != nil {
		return nil, fmt.Errorf("after model callback error: %w", err)
	}

	// Use the potentially modified response
	if modifiedResponse != nil {
		response = modifiedResponse
	}

	// Handle function calls if present
	if len(a.tools) > 0 {
		response, err = a.handleFunctionCalls(ctx, invocationCtx, response)
		if err != nil {
			return nil, fmt.Errorf("function call handling error: %w", err)
		}
	}

	// Save output to state if needed
	if a.outputKey != "" && response.Content != nil {
		// TODO(zchee): use returned value
		_ = a.saveOutputToState(ctx, response)
	}

	// Trigger callbacks
	if err := a.TriggerCallbacks(ctx, types.CallbackAfterExecution, types.NewCallbackContext(a, invocationCtx.Input, types.WithResponse(response))); err != nil {
		return nil, fmt.Errorf("callback error: %w", err)
	}

	return response, nil
}

// runAfterModelCallbacks runs all after model callbacks.
func (a *LLMAgent) runAfterModelCallbacks(invocationCtx *types.InvocationContext, response *types.LLMResponse) (*types.LLMResponse, error) {
	if len(a.afterModelCallbacks) == 0 {
		return nil, nil
	}

	callbackCtx := types.NewCallbackContext(a, invocationCtx.Input, types.WithResponse(response))
	for _, callback := range a.afterModelCallbacks {
		modifiedResponse, err := callback(callbackCtx, response)
		if err != nil {
			return nil, err
		}
		// Use the modified response for subsequent callbacks
		if modifiedResponse != nil {
			response = modifiedResponse
		}
	}

	return response, nil
}

// handleFunctionCalls processes function calls in the response.
func (a *LLMAgent) handleFunctionCalls(ctx context.Context, invocationCtx *types.InvocationContext, response *types.LLMResponse) (*types.LLMResponse, error) {
	// Use the Event helper to extract function calls
	evt := &types.Event{LLMResponse: response}
	functionCalls := evt.GetFunctionCalls()
	if len(functionCalls) == 0 {
		return response, nil
	}

	// Process each function call
	for _, functionCall := range functionCalls {
		// Find the appropriate tool
		var selectedTool types.Tool
		for _, t := range a.tools {
			if t.Name() == functionCall.Name {
				selectedTool = t
				break
			}
		}

		if selectedTool == nil {
			return nil, fmt.Errorf("unknown function called: %s", functionCall.Name)
		}

		// Create tool context
		toolCtx := &types.ToolContext{
			CallbackContext:   types.NewCallbackContext(a, invocationCtx.Input, types.WithResponse(response)),
			InvocationContext: invocationCtx,
			FunctionCallID:    functionCall.Name,
			EventActions: &types.EventActions{
				StateDelta: make(map[string]any),
			},
		}

		// Run before tool callbacks
		modifiedArgs, err := a.runBeforeToolCallbacks(selectedTool, functionCall.Args, toolCtx)
		if err != nil {
			return nil, err
		}
		if modifiedArgs != nil {
			functionCall.Args = modifiedArgs
		}

		// Execute the tool
		result, err := selectedTool.Execute(ctx, functionCall.Args, toolCtx)
		if err != nil {
			return nil, fmt.Errorf("tool execution error: %w", err)
		}

		m := result.(map[string]any)

		// Run after tool callbacks
		modifiedResult, err := a.runAfterToolCallbacks(selectedTool, functionCall.Args, toolCtx, m)
		if err != nil {
			return nil, err
		}
		if modifiedResult != nil {
			result = modifiedResult
		}

		functionResponse := &genai.FunctionResponse{
			Name:     functionCall.Name,
			Response: m,
		}

		// Append the function response to the content parts
		if response.Content == nil {
			response.Content = &genai.Content{
				Role: model.RoleAssistant,
			}
		}

		response.Content.Parts = append(response.Content.Parts, &genai.Part{
			FunctionResponse: functionResponse,
		})
	}

	return response, nil
}

// runBeforeToolCallbacks runs all before tool callbacks.
func (a *LLMAgent) runBeforeToolCallbacks(tool types.Tool, args map[string]any, toolCtx *types.ToolContext) (map[string]any, error) {
	if len(a.beforeToolCallbacks) == 0 {
		return nil, nil
	}

	for _, callback := range a.beforeToolCallbacks {
		modifiedArgs, err := callback(tool, args, toolCtx)
		if err != nil {
			return nil, err
		}
		// Use the modified args for subsequent callbacks
		if modifiedArgs != nil {
			args = modifiedArgs
		}
	}

	return args, nil
}

// runAfterToolCallbacks runs all after tool callbacks.
func (a *LLMAgent) runAfterToolCallbacks(tool types.Tool, args map[string]any, toolCtx *types.ToolContext, result map[string]any) (map[string]any, error) {
	if len(a.afterToolCallbacks) == 0 {
		return nil, nil
	}

	for _, callback := range a.afterToolCallbacks {
		modifiedResult, err := callback(tool, args, toolCtx, result)
		if err != nil {
			return nil, err
		}
		// Use the modified result for subsequent callbacks
		if modifiedResult != nil {
			result = modifiedResult
		}
	}
	return result, nil
}

// streamFromModel streams content from the model.
func (a *LLMAgent) streamFromModel(ctx context.Context, llm model.Model, request *types.LLMRequest) (*types.LLMResponse, error) {
	// Create an aggregated response
	aggregatedResponse := &types.LLMResponse{
		Content: &genai.Content{
			Role:  model.RoleAssistant,
			Parts: []*genai.Part{},
		},
	}

	// Get a connection for streaming
	conn, err := llm.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to model: %w", err)
	}

	// Send the history/request to the model
	if err := conn.SendHistory(ctx, request.Contents); err != nil {
		return nil, fmt.Errorf("failed to send history to model: %w", err)
	}

	// Process streaming responses using the response channel
	responseCh := make(chan *types.LLMResponse)
	go func() {
		defer close(responseCh)
		for {
			resp, err := conn.Receive(ctx)
			if err != nil {
				return
			}
			responseCh <- <-resp
		}
	}()

	// Collect all streaming responses
	for resp := range responseCh {
		// Merge content with aggregated response
		if resp.Content != nil && len(resp.Content.Parts) > 0 {
			for _, part := range resp.Content.Parts {
				aggregatedResponse.Content.Parts = append(aggregatedResponse.Content.Parts, part)
			}
		}

		// If this is the final response, we're done
		if !resp.Partial {
			break
		}
	}

	return aggregatedResponse, nil
}

// saveOutputToState saves the model output to the state.
func (a *LLMAgent) saveOutputToState(ctx context.Context, response *types.LLMResponse) *types.Event {
	if response.Content == nil || len(response.Content.Parts) == 0 {
		return nil
	}

	// Extract text from parts
	var text bytes.Buffer
	for _, part := range response.Content.Parts {
		if part.Text != "" {
			text.WriteString(part.Text)
		}
	}

	result := text.String()

	// Parse as JSON if output schema is defined
	if a.outputSchema != nil {
		var parsed string
		if err := sonic.ConfigFastest.Unmarshal([]byte(result), &parsed); err != nil {
			a.logger.Error("Failed to parse output as JSON", slog.String("text", result), slog.Any("error", err))
			return nil
		}

		// Use parsed result
		result = parsed
	}

	// Create event with state delta
	evt := &types.Event{
		LLMResponse:  response,
		InvocationID: "", // Would be set in a real implementation
		Author:       a.Name(),
		Actions: &types.EventActions{
			StateDelta: map[string]any{
				a.outputKey: result,
			},
		},
	}

	a.logger.InfoContext(ctx, "Saved output to state", "key", a.outputKey)

	return evt
}

// validateConfig validates the agent configuration.
func (a *LLMAgent) validateConfig() error {
	// Check output schema compatibility
	if a.outputSchema != nil {
		// Output schema cannot coexist with agent transfer configurations
		if !a.disallowTransferToParent || !a.disallowTransferToPeers {
			a.logger.Warn("Invalid config: output_schema cannot co-exist with agent transfer configurations",
				slog.Bool("disallowTransferToParent", a.disallowTransferToParent),
				slog.Bool("disallowTransferToPeers", a.disallowTransferToPeers),
			)
			a.disallowTransferToParent = true
			a.disallowTransferToPeers = true
		}

		// Output schema requires no tools
		if len(a.tools) > 0 {
			return fmt.Errorf("invalid config: if output_schema is set, tools must be empty")
		}

		// Output schema requires no sub agents
		if len(a.subAgents) > 0 {
			return fmt.Errorf("invalid config: if output_schema is set, sub_agents must be empty to disable agent transfer")
		}
	}

	return nil
}

// ConvertFunctionToTool converts a function to a Tool.
//
// This would be implemented based on your function tool wrapper pattern.
func ConvertFunctionToTool(fn any) (types.Tool, error) {
	// Example implementation - adapt to your actual tool system
	return nil, fmt.Errorf("not implemented")
}
