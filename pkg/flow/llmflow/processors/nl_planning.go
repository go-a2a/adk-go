// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package processors

import (
	"context"
	"strings"
	
	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
)

// NLPlanningRequestProcessor processes natural language planning in requests.
type NLPlanningRequestProcessor struct {
	*RequestProcessor
}

// NewNLPlanningRequestProcessor creates a new NLPlanningRequestProcessor.
func NewNLPlanningRequestProcessor() *NLPlanningRequestProcessor {
	return &NLPlanningRequestProcessor{
		RequestProcessor: NewRequestProcessor("NLPlanningRequestProcessor"),
	}
}

// Process implements RequestProcessor.Process.
func (p *NLPlanningRequestProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
) (<-chan *event.Event, error) {
	// In a real implementation, this would detect planning-related tasks
	// and add appropriate context or instructions
	
	// For example, add planning instructions to complex queries
	if lastUserMessage := findLastUserMessage(req.Messages); lastUserMessage != "" {
		if isComplexQuery(lastUserMessage) {
			// Add planning-related instructions
			if req.System != "" {
				req.System += "\n\n"
			}
			req.System += "For complex tasks, first break down the problem into steps. " +
				"Think through your approach step by step before providing your final answer."
		}
	}
	
	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements RequestProcessor.ProcessLive.
func (p *NLPlanningRequestProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	req *flow.LLMRequest,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, req)
	return err
}

// NLPlanningResponseProcessor processes natural language planning in responses.
type NLPlanningResponseProcessor struct {
	*ResponseProcessor
}

// NewNLPlanningResponseProcessor creates a new NLPlanningResponseProcessor.
func NewNLPlanningResponseProcessor() *NLPlanningResponseProcessor {
	return &NLPlanningResponseProcessor{
		ResponseProcessor: NewResponseProcessor("NLPlanningResponseProcessor"),
	}
}

// Process implements ResponseProcessor.Process.
func (p *NLPlanningResponseProcessor) Process(
	ctx context.Context,
	ic *flow.InvocationContext,
	resp *flow.LLMResponse,
) (<-chan *event.Event, error) {
	// This would process planning-related content in the response
	// For now, we'll just leave the response as is
	
	// In a real implementation, we might extract planning steps for tracing/logging
	// or reformat them for better presentation
	
	// Return empty channel as this processor doesn't generate events
	ch := make(chan *event.Event)
	close(ch)
	return ch, nil
}

// ProcessLive implements ResponseProcessor.ProcessLive.
func (p *NLPlanningResponseProcessor) ProcessLive(
	ctx context.Context,
	ic *flow.InvocationContext,
	resp *flow.LLMResponse,
	callback func(*event.Event),
) error {
	// Use the same processing logic as the non-live version
	_, err := p.Process(ctx, ic, resp)
	return err
}

// Helper functions

// findLastUserMessage finds the last message from the user.
func findLastUserMessage(messages []flow.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

// isComplexQuery determines if a query is complex and might benefit from planning.
func isComplexQuery(query string) bool {
	// This is a very simplistic heuristic - in a real implementation,
	// we would use more sophisticated methods
	
	// Check if the query is long
	if len(query) > 200 {
		return true
	}
	
	// Check for keywords that might indicate complexity
	complexityIndicators := []string{
		"step by step",
		"explain",
		"complex",
		"difficult",
		"multiple",
		"analyze",
		"compare",
		"contrast",
		"synthesize",
		"how would you",
		"what is the best way",
	}
	
	queryLower := strings.ToLower(query)
	for _, indicator := range complexityIndicators {
		if strings.Contains(queryLower, indicator) {
			return true
		}
	}
	
	// Count the number of questions
	questionCount := strings.Count(query, "?")
	if questionCount > 1 {
		return true
	}
	
	return false
}