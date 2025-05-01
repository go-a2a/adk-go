// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"context"
	"fmt"

	"github.com/go-a2a/adk-go/agent/events"
	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

// LLMAgentOption is a function that configures an LLMAgent.
type LLMAgentOption func(*LLMAgent)

// LLMAgent is a specialized agent that leverages language models for decision making.
type LLMAgent struct {
	*Agent
	
	// LLM-specific configuration
	temperature      float32
	topP             float32
	topK             int32
	maxOutputTokens  int32
	responseFormat   string
	candidateCount   int32
	
	// Prompt templates
	thoughtPrompt    string
	reasoningPrompt  string
}

// WithTemperature sets the temperature for LLM sampling.
func WithTemperature(temp float32) LLMAgentOption {
	return func(a *LLMAgent) {
		a.temperature = temp
	}
}

// WithTopP sets the top-p value for LLM sampling.
func WithTopP(topP float32) LLMAgentOption {
	return func(a *LLMAgent) {
		a.topP = topP
	}
}

// WithTopK sets the top-k value for LLM sampling.
func WithTopK(topK int32) LLMAgentOption {
	return func(a *LLMAgent) {
		a.topK = topK
	}
}

// WithMaxOutputTokens sets the maximum number of tokens to generate.
func WithMaxOutputTokens(maxTokens int32) LLMAgentOption {
	return func(a *LLMAgent) {
		a.maxOutputTokens = maxTokens
	}
}

// WithResponseFormat sets the desired response format.
func WithResponseFormat(format string) LLMAgentOption {
	return func(a *LLMAgent) {
		a.responseFormat = format
	}
}

// WithCandidateCount sets the number of candidate responses to generate.
func WithCandidateCount(count int32) LLMAgentOption {
	return func(a *LLMAgent) {
		a.candidateCount = count
	}
}

// WithThoughtPrompt sets the prompt template for generating thoughts.
func WithThoughtPrompt(prompt string) LLMAgentOption {
	return func(a *LLMAgent) {
		a.thoughtPrompt = prompt
	}
}

// WithReasoningPrompt sets the prompt template for reasoning.
func WithReasoningPrompt(prompt string) LLMAgentOption {
	return func(a *LLMAgent) {
		a.reasoningPrompt = prompt
	}
}

// NewLLMAgent creates a new LLM agent with the given options.
func NewLLMAgent(baseAgent *Agent, opts ...LLMAgentOption) *LLMAgent {
	agent := &LLMAgent{
		Agent:           baseAgent,
		temperature:     0.7,
		topP:            0.95,
		topK:            40,
		maxOutputTokens: 1024,
		responseFormat:  "text",
		candidateCount:  1,
		thoughtPrompt:   "Think step by step about how to respond to the user's request.",
		reasoningPrompt: "Explain your reasoning for this response:",
	}
	
	for _, opt := range opts {
		opt(agent)
	}
	
	// Override the base agent's user message handler
	baseAgent.RegisterEventHandler(events.EventTypeUserMessage, agent.handleUserMessage)
	
	return agent
}

// handleUserMessage processes a user message with chain-of-thought reasoning.
func (a *LLMAgent) handleUserMessage(ctx context.Context, event *events.Event) (*events.Event, error) {
	content, err := event.GetUserMessageContent()
	if err != nil {
		return nil, err
	}
	
	// Add the message to history
	a.historyMu.Lock()
	a.history = append(a.history, content.Message)
	a.historyMu.Unlock()
	
	// Generate thoughts first (internal thinking)
	thoughts, err := a.generateThoughts(ctx, content.Message)
	if err != nil {
		return nil, err
	}
	
	// Store the thoughts in agent state for later reference
	if a.stateManager != nil {
		if err := a.stateManager.SetAgent(ctx, "last_thoughts", thoughts); err != nil {
			// Non-critical error, just log it
			fmt.Printf("Error storing thoughts: %v\n", err)
		}
	}
	
	// Generate the final response using the thoughts
	response, err := a.generateResponseWithThoughts(ctx, content.Message, thoughts)
	if err != nil {
		return nil, err
	}
	
	// Create and return the agent response event
	return events.NewAgentResponseEvent(event.SessionID, a.id, response, event.ID)
}

// generateThoughts generates internal reasoning thoughts about how to respond.
func (a *LLMAgent) generateThoughts(ctx context.Context, userMessage *genai.Content) (string, error) {
	// Create a copy of the history
	a.historyMu.RLock()
	history := make([]*genai.Content, len(a.history))
	copy(history, a.history)
	a.historyMu.RUnlock()
	
	// Add a system message with the thought prompt
	thoughtSystem := &genai.Content{
		Role: model.RoleSystem,
		Parts: []*genai.Part{
			{Text: a.thoughtPrompt},
		},
	}
	
	// Create the request with special thought generation instructions
	request := model.NewLLMRequest(append(history, thoughtSystem))
	
	// Configure the generation parameters
	genConfig := &genai.GenerateContentConfig{
		Temperature:     a.temperature,
		TopP:            a.topP,
		TopK:            a.topK,
		MaxOutputTokens: a.maxOutputTokens,
		CandidateCount:  a.candidateCount,
	}
	request.WithGenerationConfig(genConfig)
	
	// Generate the thoughts
	response, err := a.model.GenerateContent(ctx, request)
	if err != nil {
		return "", err
	}
	
	// Extract the thoughts from the response
	if len(response.Candidates) > 0 && len(response.Candidates[0].Content.Parts) > 0 {
		for _, part := range response.Candidates[0].Content.Parts {
			if part.Text != "" {
				return part.Text, nil
			}
		}
	}
	
	return "", fmt.Errorf("no thoughts generated")
}

// generateResponseWithThoughts generates a final response using the thoughts.
func (a *LLMAgent) generateResponseWithThoughts(ctx context.Context, userMessage *genai.Content, thoughts string) (*genai.Content, error) {
	// Create a copy of the history
	a.historyMu.RLock()
	history := make([]*genai.Content, len(a.history))
	copy(history, a.history)
	a.historyMu.RUnlock()
	
	// Create system messages with the thoughts and reasoning prompt
	thoughtsContent := &genai.Content{
		Role: model.RoleSystem,
		Parts: []*genai.Part{
			{Text: fmt.Sprintf("Your internal thoughts: %s", thoughts)},
		},
	}
	
	reasoningPrompt := &genai.Content{
		Role: model.RoleSystem,
		Parts: []*genai.Part{
			{Text: a.reasoningPrompt},
		},
	}
	
	// Create the LLM request
	request := model.NewLLMRequest(append(history, thoughtsContent, reasoningPrompt))
	
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
	
	// Configure the generation parameters
	genConfig := &genai.GenerateContentConfig{
		Temperature:     a.temperature,
		TopP:            a.topP,
		TopK:            a.topK,
		MaxOutputTokens: a.maxOutputTokens,
		CandidateCount:  a.candidateCount,
	}
	request.WithGenerationConfig(genConfig)
	
	// Generate the response
	response, err := a.model.GenerateContent(ctx, request)
	if err != nil {
		return nil, err
	}
	
	// Extract and process the response
	for _, candidate := range response.Candidates {
		for _, content := range candidate.Content {
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
	
	return nil, fmt.Errorf("no assistant response found in model output")
}