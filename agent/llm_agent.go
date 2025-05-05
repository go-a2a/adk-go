// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
)

// LLMAgent is an agent that uses a language model to generate responses.
type LLMAgent struct {
	Agent
	model    model.Model
	template string
	logger   *slog.Logger
}

// LLMAgentOption is a function that modifies an LLMAgent.
type LLMAgentOption func(*LLMAgent)

// WithLLMModel sets the model for the LLM agent.
func WithLLMModel(model model.Model) LLMAgentOption {
	return func(a *LLMAgent) {
		a.model = model
	}
}

// WithTemplate sets the template for the LLM agent.
func WithTemplate(template string) LLMAgentOption {
	return func(a *LLMAgent) {
		a.template = template
	}
}

// WithLLMLogger sets the logger for the LLM agent.
func WithLLMLogger(logger *slog.Logger) LLMAgentOption {
	return func(a *LLMAgent) {
		a.logger = logger
	}
}

// NewLLMAgent creates a new LLM agent with the given options.
func NewLLMAgent(options ...LLMAgentOption) *LLMAgent {
	agent := &LLMAgent{
		Agent:  *NewAgent(),
		logger: slog.Default(),
	}

	for _, option := range options {
		option(agent)
	}

	return agent
}

// InvokeAsync invokes the LLM agent and returns a stream of responses.
func (a *LLMAgent) InvokeAsync(ctx context.Context, invocationCtx InvocationContext) iter.Seq2[*genai.Content, error] {
	return func(yield func(*genai.Content, error) bool) {
		// Validate that we have a model
		if a.model == nil {
			yield(nil, errors.New("model not set for LLM agent"))
			return
		}

		// Get the history and request from the invocation context
		history := invocationCtx.GetHistory()
		request := invocationCtx.GetRequest()

		// Create callback context for before callbacks
		callbackCtx := NewCallbackContextWithOptions(
			WithHistory(history),
			WithRequest(request),
		)

		// Execute before callbacks
		beforeResult := invocationCtx.ExecuteBeforeCallbacks(callbackCtx)
		if beforeResult != nil {
			// If a before callback returned a result, use it instead of calling the model
			a.logger.Debug("Using result from before callback")
			yield(beforeResult, nil)
			return
		}

		// Prepare the model request
		contents := make([]*genai.Content, len(history))
		copy(contents, history)

		// Add the user request if it's not already in the history
		if request != nil {
			contents = append(contents, request)
		}

		// Create the model request
		llmRequest := &model.LLMRequest{
			Contents: contents,
		}

		// Call the model
		a.logger.Debug("Calling model", "model", a.model.Name())
		iterator := a.model.StreamGenerateContent(ctx, llmRequest)

		assistantContent := &genai.Content{
			Role:  model.RoleAssistant,
			Parts: []*genai.Part{},
		}

		// Process the model responses
		for modelResp, err := range iterator {
			if err != nil {
				yield(nil, fmt.Errorf("model error: %w", err))
				return
			}

			if modelResp == nil || modelResp.Content == nil {
				continue
			}

			// Get the first candidate
			candidate := modelResp.Content

			// Accumulate the content
			for _, part := range candidate.Parts {
				assistantContent.Parts = append(assistantContent.Parts, part)
			}

			// Yield the current state of the content
			currentContent := &genai.Content{
				Role:  model.RoleAssistant,
				Parts: make([]*genai.Part, len(assistantContent.Parts)),
			}
			copy(currentContent.Parts, assistantContent.Parts)

			if !yield(currentContent, nil) {
				return
			}
		}

		// Create callback context for after callbacks
		callbackCtx = NewCallbackContextWithOptions(
			WithHistory(history),
			WithRequest(request),
			WithContent(assistantContent),
		)
		callbackCtx.MarkEnd()

		// Execute after callbacks
		afterResult := invocationCtx.ExecuteAfterCallbacks(callbackCtx)
		if afterResult != nil {
			// If an after callback returned a result, yield it
			a.logger.Debug("Using result from after callback")
			yield(afterResult, nil)
		}
	}
}

// Invoke synchronously invokes the LLM agent and returns the final response.
func (a *LLMAgent) Invoke(ctx context.Context, invocationCtx InvocationContext) (*genai.Content, error) {
	return a.Agent.Invoke(ctx, invocationCtx)
}
