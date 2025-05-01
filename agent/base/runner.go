// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/go-a2a/adk-go/agent/events"
	"github.com/go-a2a/adk-go/agent/state"
	"github.com/go-a2a/adk-go/agent/tools"
	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

// RunnerOption is a function that configures a Runner.
type RunnerOption func(*Runner)

// Runner manages the execution of agents and routes events between them.
type Runner struct {
	// Session information
	sessionID string
	
	// Components
	stateLayer   state.StateLayer
	toolRegistry *tools.Registry
	
	// Event handling
	eventCh       chan *events.Event
	eventHandlers map[events.EventType][]events.EventHandler
	
	// Agents
	agents    map[string]*Agent
	agentsMu  sync.RWMutex
	
	// Execution control
	running   bool
	runningMu sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// WithSessionID sets the session ID for the runner.
func WithSessionID(sessionID string) RunnerOption {
	return func(r *Runner) {
		r.sessionID = sessionID
	}
}

// WithStateLayer sets the state layer for the runner.
func WithStateLayer(stateLayer state.StateLayer) RunnerOption {
	return func(r *Runner) {
		r.stateLayer = stateLayer
	}
}

// WithToolRegistry sets the tool registry for the runner.
func WithToolRegistry(registry *tools.Registry) RunnerOption {
	return func(r *Runner) {
		r.toolRegistry = registry
	}
}

// NewRunner creates a new runner with the given options.
func NewRunner(opts ...RunnerOption) *Runner {
	r := &Runner{
		sessionID:     events.GenerateID(),
		eventCh:       make(chan *events.Event, 100),
		eventHandlers: make(map[events.EventType][]events.EventHandler),
		agents:        make(map[string]*Agent),
	}
	
	for _, opt := range opts {
		opt(r)
	}
	
	// Create default components if not provided
	if r.stateLayer == nil {
		r.stateLayer = state.NewMemoryStateLayer()
	}
	
	if r.toolRegistry == nil {
		r.toolRegistry = tools.NewRegistry()
	}
	
	// Register default event handlers
	r.RegisterEventHandler(events.EventTypeToolCall, r.handleToolCall)
	
	return r
}

// RegisterAgent registers an agent with the runner.
func (r *Runner) RegisterAgent(agent *Agent) {
	r.agentsMu.Lock()
	defer r.agentsMu.Unlock()
	
	// Configure the agent to emit events to the runner
	agent.eventEmitter = r.EmitEvent
	
	r.agents[agent.ID()] = agent
}

// RegisterEventHandler registers a handler for a specific event type.
func (r *Runner) RegisterEventHandler(eventType events.EventType, handler events.EventHandler) {
	if _, exists := r.eventHandlers[eventType]; !exists {
		r.eventHandlers[eventType] = make([]events.EventHandler, 0)
	}
	r.eventHandlers[eventType] = append(r.eventHandlers[eventType], handler)
}

// EmitEvent adds an event to the runner's event queue.
func (r *Runner) EmitEvent(event *events.Event) error {
	// Ensure the session ID is set
	if event.SessionID == "" {
		event.SessionID = r.sessionID
	}
	
	// Add to the event channel if running, otherwise process directly
	r.runningMu.RLock()
	running := r.running
	r.runningMu.RUnlock()
	
	if running {
		select {
		case r.eventCh <- event:
			return nil
		default:
			return errors.New("event channel is full")
		}
	} else {
		return r.processEvent(context.Background(), event)
	}
}

// Start starts the runner's event processing loop.
func (r *Runner) Start(ctx context.Context) error {
	r.runningMu.Lock()
	defer r.runningMu.Unlock()
	
	if r.running {
		return errors.New("runner is already running")
	}
	
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.running = true
	
	go r.eventLoop()
	
	return nil
}

// Stop stops the runner's event processing loop.
func (r *Runner) Stop() {
	r.runningMu.Lock()
	defer r.runningMu.Unlock()
	
	if !r.running {
		return
	}
	
	r.cancel()
	r.running = false
}

// SendMessage sends a user message to the specified agent.
func (r *Runner) SendMessage(ctx context.Context, agentID string, message string) error {
	r.agentsMu.RLock()
	agent, exists := r.agents[agentID]
	r.agentsMu.RUnlock()
	
	if !exists {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	
	content := &genai.Content{
		Role: model.RoleUser,
		Parts: []*genai.Part{
			{Text: message},
		},
	}
	
	event, err := events.NewUserMessageEvent(r.sessionID, content)
	if err != nil {
		return err
	}
	
	// Set the agent ID
	event.AgentID = agentID
	
	return r.EmitEvent(event)
}

// eventLoop processes events from the event channel.
func (r *Runner) eventLoop() {
	for {
		select {
		case event := <-r.eventCh:
			if err := r.processEvent(r.ctx, event); err != nil {
				// Log the error
				fmt.Printf("Error processing event: %v\n", err)
			}
		case <-r.ctx.Done():
			return
		}
	}
}

// processEvent processes a single event.
func (r *Runner) processEvent(ctx context.Context, event *events.Event) error {
	// Call all registered handlers for this event type
	handlers, exists := r.eventHandlers[event.Type]
	if exists {
		for _, handler := range handlers {
			if err := handler(event); err != nil {
				// Log the error but continue processing
				fmt.Printf("Error in event handler for %s: %v\n", event.Type, err)
			}
		}
	}
	
	// If the event has an agent ID, route it to that agent
	if event.AgentID != "" {
		r.agentsMu.RLock()
		agent, exists := r.agents[event.AgentID]
		r.agentsMu.RUnlock()
		
		if exists {
			if _, err := agent.ProcessEvent(ctx, event); err != nil {
				return fmt.Errorf("error in agent %s: %w", event.AgentID, err)
			}
		} else {
			return fmt.Errorf("agent not found: %s", event.AgentID)
		}
	}
	
	return nil
}

// handleToolCall handles tool call events.
func (r *Runner) handleToolCall(event *events.Event) error {
	toolCall, err := event.GetToolCallContent()
	if err != nil {
		return err
	}
	
	// Execute the tool
	result, err := r.toolRegistry.ExecuteTool(context.Background(), toolCall.Name, toolCall.Parameters)
	
	// Create a tool response event
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	
	responseEvent, err := events.NewToolResponseEvent(
		event.SessionID,
		event.AgentID,
		result,
		errMsg,
		event.ID,
	)
	if err != nil {
		return err
	}
	
	// Emit the response event
	return r.EmitEvent(responseEvent)
}