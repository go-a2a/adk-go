// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"iter"
	"log/slog"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// Base represents the base agent.
type Base struct {
	*Config
}

var _ types.Agent = (*Base)(nil)

// NewBase creates a new agent configuration with the given name.
func NewBase(name string, opts ...Option) (*Base, error) {
	base := &Base{
		Config: NewConfig(name),
	}
	for _, opt := range opts {
		opt.apply(base.Config)
	}

	for _, subAgent := range base.subAgents {
		if subAgent.ParentAgent() != nil {
			return nil, fmt.Errorf("Agent %s already has a parent agent, current parent: %s, trying to add: %s", subAgent.Name(), subAgent.ParentAgent().Name(), base.name)
		}
	}

	return base, nil
}

// Name implements [types.Agent].
func (a *Base) Name() string {
	return a.name
}

// Execute implements [types.Agent].
func (a *Base) Execute(ctx context.Context, input map[string]any, opts ...types.RunOption) (*types.LLMResponse, error) {
	return nil, nil
}

// Run entry method to run an agent via text-based conversation.
func (a *Base) Run(ctx context.Context, parentContext *types.InvocationContext) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		ic := a.createInvocationContext(parentContext)
		beforeEvent, err := a.handleBeforeAgentCallback(ctx, ic)
		if err != nil {
			yield(nil, err)
			return
		}
		if beforeEvent != nil {
			if !yield(beforeEvent, nil) {
				return
			}
			if ic.EndInvocation {
				return
			}
		}
		// async for event in self._run_async_impl(ctx):
		//   yield event
		if ic.EndInvocation {
			return
		}

		afterEvent, err := a.handleAfterAgentCallback(ctx, ic)
		if err != nil {
			yield(nil, err)
			return
		}
		if beforeEvent != nil {
			if !yield(afterEvent, nil) {
				return
			}
		}
	}
}

// RunLive entry method to run an agent via video/audio-based conversation.
func (a *Base) RunLive(ctx context.Context, parentContext *types.InvocationContext) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		ic := a.createInvocationContext(parentContext)
		_ = ic
		// async for event in self._run_live_impl(ctx):
		//   yield event
	}
}

// ParentAgent returns the parent agent of this agent.
func (a *Base) ParentAgent() types.Agent {
	return a.parentAgent
}

// RootAgent gets the root agent of this agent.
func (a *Base) RootAgent() types.Agent {
	rootAgent := types.Agent(a)
	for {
		parentAgent := rootAgent.ParentAgent()
		if parentAgent == nil {
			break
		}
		rootAgent = parentAgent
	}
	return rootAgent
}

// FindAgent finds the agent with the given name in this agent and its descendants.
func (a *Base) FindAgent(name string) types.Agent {
	if name == a.name {
		return a
	}
	return a.FindSubAgent(name)
}

// FindSubAgent finds the agent with the given name in this agent's descendants.
func (a *Base) FindSubAgent(name string) types.Agent {
	for _, subAgent := range a.subAgents {
		if result := subAgent.FindAgent(name); result != nil {
			return result
		}
	}
	return nil
}

// createInvocationContext creates a new invocation context for this agent.
func (a *Base) createInvocationContext(parentContext *types.InvocationContext) *types.InvocationContext {
	parentContext.Agent = a
	if parentContext.Branch != "" {
		parentContext.Branch += "." + a.Name()
	}
	return parentContext
}

// handleBeforeAgentCallback runs the before_agent_callback if it exists.
func (a *Base) handleBeforeAgentCallback(ctx context.Context, ic *types.InvocationContext) (*types.Event, error) {
	cc := types.NewCallbackContext(ic)
	bcContent, err := a.TriggerBeforeCallback(ctx, cc)
	if err != nil {
		return nil, err
	}
	if bcContent == nil {
		return nil, nil
	}

	var ev *types.Event
	if bcContent != nil {
		ev = types.NewEvent()
		ev.InvocationID = ic.InvocationID
		ev.Author = a.name
		ev.Branch = ic.Branch
		ev.Content = bcContent
		ev.Action = cc.EventAction

		ic.EndInvocation = true
		return ev, nil
	}

	if cc.State.HasDelta() {
		ev = types.NewEvent()
		ev.InvocationID = ic.InvocationID
		ev.Author = a.name
		ev.Branch = ic.Branch
		ev.Action = cc.EventAction
	}

	return ev, nil
}

// handleAfterAgentCallback runs the after_agent_callback if it exists.
func (a *Base) handleAfterAgentCallback(ctx context.Context, ic *types.InvocationContext) (*types.Event, error) {
	cc := types.NewCallbackContext(ic)
	bcContent, err := a.TriggerBeforeCallback(ctx, cc)
	if err != nil {
		return nil, err
	}
	if bcContent == nil {
		return nil, nil
	}

	var ev *types.Event
	if cc.State.HasDelta() {
		ev := types.NewEvent()
		ev.InvocationID = ic.InvocationID
		ev.Author = a.name
		ev.Branch = ic.Branch
		ev.Content = bcContent
		ev.Action = cc.EventAction
	}

	return ev, nil
}

// TriggerBeforeCallback triggers before callbacks.
func (a *Base) TriggerBeforeCallback(ctx context.Context, callbackCtx *types.CallbackContext) (*genai.Content, error) {
	if a.beforeAgentCallback != nil {
		return nil, nil
	}

	content, err := a.beforeAgentCallback(callbackCtx)
	if err != nil {
		a.logger.ErrorContext(ctx, "before callback error", slog.Any("error", err))
		return nil, err
	}

	return content, nil
}

// TriggerAfterCallback triggers after callbacks.
func (a *Base) TriggerAfterCallback(ctx context.Context, callbackCtx *types.CallbackContext) (*genai.Content, error) {
	if a.afterAgentCallback != nil {
		return nil, nil
	}

	content, err := a.afterAgentCallback(callbackCtx)
	if err != nil {
		a.logger.ErrorContext(ctx, "after callback error", slog.Any("error", err))
		return nil, err
	}

	return content, nil
}
