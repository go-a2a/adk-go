// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package planner provides planning capabilities for AI agents in the ADK Go framework.
//
// Planners help structure agent responses by guiding the model through a systematic
// problem-solving approach. This package includes different planner implementations that
// can be used based on the needs of the application.
//
// # Core Components
//
//   - Context: Contains read-only information for planning operations, such as conversation
//     history, current query, and session details.
//
// - CallbackContext: Extends Context with mutable state for callback operations.
//
//   - LlmRequest: Represents a request to a language model, including system instructions,
//     messages, and configuration options.
//
//   - Planner: Interface that defines the planning strategy, with methods for building
//     planning instructions and processing model responses.
//
// # Available Planners
//
//  1. BuiltInPlanner:
//     A basic planner that relies on the model's native thinking capabilities. It
//     supports configuration of thinking features but doesn't impose a strict
//     structure on the model's outputs.
//
//     Example:
//     ```go
//     // Create a built-in planner with visible thinking
//     thinkingConfig := &planner.ThinkingConfig{
//     Enabled: true,
//     Visible: true,
//     }
//     builtInPlanner := planner.NewBuiltInPlanner(thinkingConfig)
//     ```
//
//  2. PlanReActPlanner:
//     A structured planner that guides the model through explicit planning, reasoning,
//     action, and final answer phases. It uses tags to delineate different phases and
//     can enforce structured outputs.
//
//     Example:
//     ```go
//     // Create a plan-re-act planner with default settings
//     reactPlanner := planner.NewPlanReActPlanner()
//
//     // Or with custom configuration
//     customPlanner := planner.NewPlanReActPlanner(
//     planner.WithFinalAnswerCheck(true),
//     planner.WithStructuredOutput(true),
//     )
//     ```
//
// # Registry
//
// The package includes a Registry for centralizing planner management:
//
// ```go
// // Create a registry with default planners
// registry := planner.NewRegistry()
//
// // Get a specific planner
// reactPlanner, err := registry.Get("plan_re_act")
//
//	if err != nil {
//	    // Handle error
//	}
//
// // Register a custom planner
// registry.Register("my_planner", myPlanner)
// ```
//
// # Integration with LLM Agents
//
// Planners are typically used by LLM agents to structure their thinking process:
//
// ```go
// // Create a context
// ctx := planner.NewContext(messages, query, userID, sessionID)
//
// // Create an LLM request
//
//	request := &planner.LlmRequest{
//	    SystemPrompt: systemPrompt,
//	    Messages:     messages,
//	    Temperature:  0.7,
//	    MaxTokens:    2048,
//	}
//
// // Get planning instruction
// instruction, err := myPlanner.BuildPlanningInstruction(ctx, request)
//
//	if err != nil {
//	    // Handle error
//	}
//
// // Append instruction to system prompt
// request.SystemPrompt += "\n\n" + instruction
//
// // After getting LLM response
// callbackCtx := planner.NewCallbackContext(ctx)
// processedResponses, err := myPlanner.ProcessPlanningResponse(callbackCtx, responses)
//
//	if err != nil {
//	    // Handle error
//	}
//
// ```
package planner
