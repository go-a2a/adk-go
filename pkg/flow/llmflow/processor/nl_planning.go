// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"log/slog"

	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/flow"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/planner"
)

// NLPlanningProcessor processes natural language planning in LLM requests.
type NLPlanningProcessor struct {
	planProcessor *planner.PlanReActPlanner
}

// NewNLPlanningProcessor creates a new NLPlanningProcessor.
func NewNLPlanningProcessor() *NLPlanningProcessor {
	return &NLPlanningProcessor{
		planProcessor: planner.NewPlanReActPlanner(),
	}
}

// Run processes the LLM request and returns a channel of events.
func (p *NLPlanningProcessor) Run(ctx *flow.LlmFlowContext, request *flow.LlmRequest) (<-chan event.Event, error) {
	eventCh := make(chan event.Event, 10)

	go func() {
		defer close(eventCh)

		slog.InfoContext(ctx.Context, "Processing natural language planning in LLM request")

		// Check if planning is enabled for this session
		state := ctx.Session.GetState()
		config := state.Config

		planningEnabled, ok := config["enable_planning"].(bool)
		if !ok || !planningEnabled {
			slog.DebugContext(ctx.Context, "Natural language planning is not enabled")
			return
		}

		// Extract the latest user query from the contents
		var userQuery string
		for i := len(request.Contents) - 1; i >= 0; i-- {
			content := request.Contents[i]
			if content.Role() == "user" {
				if text, ok := content.Parts()[0].(string); ok {
					userQuery = text
					break
				}
			}
		}

		if userQuery == "" {
			slog.DebugContext(ctx.Context, "No user query found for planning")
			return
		}

		// Generate a plan based on the user query
		plan, err := p.planProcessor.GeneratePlan(ctx.Context, userQuery, state.Events)
		if err != nil {
			slog.ErrorContext(ctx.Context, "Failed to generate plan", "error", err)
			return
		}

		// Add the plan to the request as a system message
		if plan != "" {
			planContent := message.NewSystemContent("Plan: " + plan)
			// Insert the plan after any system messages but before user messages
			var newContents []message.Content
			systemDone := false

			for _, content := range request.Contents {
				if !systemDone && content.Role() != "system" {
					newContents = append(newContents, planContent)
					systemDone = true
				}
				newContents = append(newContents, content)
			}

			if !systemDone {
				newContents = append(newContents, planContent)
			}

			request.Contents = newContents
			slog.DebugContext(ctx.Context, "Added plan to LLM request")
		}
	}()

	return eventCh, nil
}
