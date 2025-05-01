// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package base provides the core agent implementation for the ADK.
package base

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/go-a2a/adk-go/agent/events"
	"github.com/go-a2a/adk-go/agent/state"
	"github.com/go-a2a/adk-go/agent/tools"
	"github.com/go-a2a/adk-go/internal/jsonschema"
	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

// EventHandlerFunc processes an event and returns a response event.
type EventHandlerFunc func(context.Context, *events.Event) (*events.Event, error)

// AgentOption is a function that configures an Agent.
type AgentOption func(*Agent)

// Agent represents the base implementation of an agent.
type Agent struct {
	// Agent identity
	id          string
	name        string
	description string
	sessionID   string

	// LLM configuration
	model           model.Model
	systemPrompt    string
	modelConnection model.BaseConnection

	// Components
	toolRegistry *tools.Registry
	stateManager *state.StateManager

	// Event handling
	eventHandlers map[events.EventType][]EventHandlerFunc
	eventEmitter  func(*events.Event) error

	// Runtime state
	history   []*genai.Content
	historyMu sync.RWMutex

	// Child agents
	childAgents   map[string]*Agent
	childAgentsMu sync.RWMutex
}

// WithID sets the ID of the agent.
func WithID(id string) AgentOption {
	return func(a *Agent) {
		a.id = id
	}
}

// WithName sets the name of the agent.
func WithName(name string) AgentOption {
	return func(a *Agent) {
		a.name = name
	}
}

// WithDescription sets the description of the agent.
func WithDescription(description string) AgentOption {
	return func(a *Agent) {
		a.description = description
	}
}

// WithSessionID sets the session ID for the agent.
func WithSessionID(sessionID string) AgentOption {
	return func(a *Agent) {
		a.sessionID = sessionID
	}
}

// WithModel sets the LLM model for the agent.
func WithModel(m model.Model) AgentOption {
	return func(a *Agent) {
		a.model = m
	}
}

// WithSystemPrompt sets the system prompt for the agent.
func WithSystemPrompt(prompt string) AgentOption {
	return func(a *Agent) {
		a.systemPrompt = prompt
	}
}

// WithToolRegistry sets the tool registry for the agent.
func WithToolRegistry(registry *tools.Registry) AgentOption {
	return func(a *Agent) {
		a.toolRegistry = registry
	}
}

// WithStateManager sets the state manager for the agent.
func WithStateManager(manager *state.StateManager) AgentOption {
	return func(a *Agent) {
		a.stateManager = manager
	}
}

// WithEventEmitter sets the event emitter function for the agent.
func WithEventEmitter(emitter func(*events.Event) error) AgentOption {
	return func(a *Agent) {
		a.eventEmitter = emitter
	}
}

// NewAgent creates a new Agent with the given options.
func NewAgent(opts ...AgentOption) *Agent {
	agent := &Agent{
		id:            generateID(),
		eventHandlers: make(map[events.EventType][]EventHandlerFunc),
		childAgents:   make(map[string]*Agent),
		history:       make([]*genai.Content, 0),
	}

	for _, opt := range opts {
		opt(agent)
	}

	// Create default components if not provided
	if agent.toolRegistry == nil {
		agent.toolRegistry = tools.NewRegistry()
	}

	if agent.stateManager == nil && agent.sessionID != "" {
		agent.stateManager = state.NewStateManager(
			state.NewMemoryStateLayer(),
			agent.sessionID,
			agent.id,
			agent.emitEvent,
		)
	}

	if agent.eventEmitter == nil {
		agent.eventEmitter = func(event *events.Event) error {
			// Default implementation just processes the event internally
			return agent.processEvent(context.Background(), event)
		}
	}

	// Register default event handlers
	agent.RegisterEventHandler(events.EventTypeUserMessage, agent.handleUserMessage)
	agent.RegisterEventHandler(events.EventTypeToolResponse, agent.handleToolResponse)

	return agent
}

// ID returns the ID of the agent.
func (a *Agent) ID() string {
	return a.id
}

// Name returns the name of the agent.
func (a *Agent) Name() string {
	return a.name
}

// Description returns the description of the agent.
func (a *Agent) Description() string {
	return a.description
}

// AddTool adds a tool to the agent's tool registry.
func (a *Agent) AddTool(tool tools.Tool) error {
	return a.toolRegistry.RegisterTool(tool)
}

// RegisterEventHandler registers a handler for a specific event type.
func (a *Agent) RegisterEventHandler(eventType events.EventType, handler EventHandlerFunc) {
	if _, exists := a.eventHandlers[eventType]; !exists {
		a.eventHandlers[eventType] = make([]EventHandlerFunc, 0)
	}
	a.eventHandlers[eventType] = append(a.eventHandlers[eventType], handler)
}

// AddChildAgent adds a child agent that can be invoked by this agent.
func (a *Agent) AddChildAgent(agent *Agent) {
	a.childAgentsMu.Lock()
	defer a.childAgentsMu.Unlock()
	a.childAgents[agent.ID()] = agent

	// Create a tool that invokes the child agent
	agentTool := a.createAgentTool(agent)
	a.AddTool(agentTool)
}

// createAgentTool creates a tool that invokes a child agent.
func (a *Agent) createAgentTool(childAgent *Agent) tools.Tool {
	return tools.NewBaseTool(
		tools.WithName("agent:"+childAgent.ID()),
		tools.WithDescription(fmt.Sprintf("Invokes the %s agent: %s", childAgent.Name(), childAgent.Description())),
		tools.WithInputSchema(&jsonschema.Schema{
			Type: "object",
			Properties: map[string]*jsonschema.Schema{
				"input": {
					Type:        "string",
					Description: "The input to send to the agent",
				},
			},
			Required: []string{"input"},
		}),
		tools.WithExecuteFunc(func(ctx context.Context, params map[string]any) (any, error) {
			input, _ := params["input"].(string)

			// Create a user message event for the child agent
			content := &genai.Content{
				Role: model.RoleUser,
				Parts: []*genai.Part{
					{Text: input},
				},
			}

			event, err := events.NewUserMessageEvent(a.sessionID, content)
			if err != nil {
				return nil, err
			}

			// Set the agent ID for the child agent
			event.AgentID = childAgent.ID()

			// Process the event in the child agent
			response, err := childAgent.ProcessEvent(ctx, event)
			if err != nil {
				return nil, err
			}

			// Extract the agent response content
			content, err = response.GetAgentResponseContent()
			if err != nil {
				return nil, err
			}

			return content.Response, nil
		}),
	)
}

// ProcessEvent processes an event and returns any response events.
func (a *Agent) ProcessEvent(ctx context.Context, event *events.Event) (*events.Event, error) {
	// Set the agent ID if not already set
	if event.AgentID == "" {
		event.AgentID = a.id
	}

	// Check if we have handlers for this event type
	handlers, exists := a.eventHandlers[event.Type]
	if !exists || len(handlers) == 0 {
		return nil, fmt.Errorf("no handlers registered for event type: %s", event.Type)
	}

	// Call each handler in sequence
	var lastResponse *events.Event
	var lastErr error

	for _, handler := range handlers {
		response, err := handler(ctx, event)
		if err != nil {
			lastErr = err
			continue
		}
		if response != nil {
			lastResponse = response
		}
	}

	if lastResponse == nil && lastErr != nil {
		return nil, lastErr
	}

	return lastResponse, nil
}

// emitEvent emits an event through the event emitter.
func (a *Agent) emitEvent(event *events.Event) error {
	if a.eventEmitter == nil {
		return errors.New("no event emitter configured")
	}
	return a.eventEmitter(event)
}

// processEvent is the internal method to process events.
func (a *Agent) processEvent(ctx context.Context, event *events.Event) error {
	// This is called by the default event emitter
	_, err := a.ProcessEvent(ctx, event)
	return err
}

// handleUserMessage processes a user message event.
func (a *Agent) handleUserMessage(ctx context.Context, event *events.Event) (*events.Event, error) {
	content, err := event.GetUserMessageContent()
	if err != nil {
		return nil, err
	}

	// Add the message to history
	a.historyMu.Lock()
	a.history = append(a.history, content.Message)
	a.historyMu.Unlock()

	// Generate a response using the LLM
	response, err := a.generateResponse(ctx, content.Message)
	if err != nil {
		return nil, err
	}

	// Create and return the agent response event
	return events.NewAgentResponseEvent(event.SessionID, a.id, response, event.ID)
}

// handleToolResponse processes a tool response event.
func (a *Agent) handleToolResponse(ctx context.Context, event *events.Event) (*events.Event, error) {
	content, err := event.GetToolResponseContent()
	if err != nil {
		return nil, err
	}

	// Create a system message for the tool response
	var systemContent string
	if content.Error != "" {
		systemContent = fmt.Sprintf("Tool execution failed: %s", content.Error)
	} else {
		systemContent = fmt.Sprintf("Tool execution succeeded: %v", content.Result)
	}

	systemMessage := &genai.Content{
		Role: model.RoleSystem,
		Parts: []*genai.Part{
			{Text: systemContent},
		},
	}

	// Add the message to history
	a.historyMu.Lock()
	a.history = append(a.history, systemMessage)
	a.historyMu.Unlock()

	// Generate a response using the LLM
	response, err := a.generateResponse(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Create and return the agent response event
	return events.NewAgentResponseEvent(event.SessionID, a.id, response, event.ID)
}

// generateResponse generates a response from the LLM using the current history.
func (a *Agent) generateResponse(ctx context.Context, additionalContent *genai.Content) (*genai.Content, error) {
	var history []*genai.Content

	// Copy the history to prevent race conditions
	a.historyMu.RLock()
	history = make([]*genai.Content, len(a.history))
	copy(history, a.history)
	a.historyMu.RUnlock()

	// Add additional content if provided
	if additionalContent != nil {
		history = append(history, additionalContent)
	}

	// Create the LLM request
	request := model.NewLLMRequest(history)

	// Add system prompt if available
	if a.systemPrompt != "" {
		request.AppendInstructions(a.systemPrompt)
	}

	// Add tools if available
	if a.toolRegistry != nil {
		tools := a.toolRegistry.ToGenAITools()
		if len(tools) > 0 {
			request.AppendTools(tools...)
		}
	}

	// Generate the response
	response, err := a.model.GenerateContent(ctx, request)
	if err != nil {
		return nil, err
	}

	// Extract and process any tool calls
	for _, item := range response.Candidates {
		for _, content := range item.Content {
			if content.Role == model.RoleAssistant {
				// Add the response to history
				a.historyMu.Lock()
				a.history = append(a.history, content)
				a.historyMu.Unlock()

				// Process any tool calls
				if len(content.Parts) > 0 {
					for _, part := range content.Parts {
						if part.FunctionCall != nil {
							a.handleFunctionCall(ctx, part.FunctionCall)
						}
					}
				}

				return content, nil
			}
		}
	}

	return nil, errors.New("no assistant response found in model output")
}

// handleFunctionCall processes a function call from the LLM.
func (a *Agent) handleFunctionCall(ctx context.Context, functionCall *genai.FunctionCall) error {
	// Create a tool call event
	toolCallEvent, err := events.NewToolCallEvent(
		a.sessionID,
		a.id,
		functionCall.Name,
		functionCall.Args,
		"",
	)
	if err != nil {
		return err
	}

	// Emit the tool call event
	return a.emitEvent(toolCallEvent)
}

// generateID generates a unique ID for an agent.
func generateID() string {
	return events.GenerateID()
}

