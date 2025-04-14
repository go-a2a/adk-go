// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package planner_test

import (
	"fmt"
	"strings"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/planner"
)

func ExampleBuiltInPlanner() {
	// Create a built-in planner with visible thinking
	thinkingConfig := &planner.ThinkingConfig{
		Enabled: true,
		Visible: true,
	}
	builtInPlanner := planner.NewBuiltInPlanner(thinkingConfig)

	// Create test messages
	messages := []message.Message{
		message.NewUserMessage("What is the capital of France?"),
	}

	// Create context and request
	ctx := planner.NewContext(messages, "What is the capital of France?", "user123", "session456")
	request := &planner.LlmRequest{
		SystemPrompt: "You are a helpful assistant.",
		Messages:     messages,
		Temperature:  0.7,
		MaxTokens:    1024,
	}

	// Get planning instruction
	instruction, _ := builtInPlanner.BuildPlanningInstruction(ctx, request)
	fmt.Println("Planning instruction:", instruction)
	fmt.Println("Thinking enabled:", request.Thinking.Enabled)
	fmt.Println("Thinking visible:", request.Thinking.Visible)
	
	// Output:
	// Planning instruction: 
	// Thinking enabled: true
	// Thinking visible: true
}

func ExamplePlanReActPlanner() {
	// Create a PlanReActPlanner with default options
	reactPlanner := planner.NewPlanReActPlanner()

	// Create test messages
	messages := []message.Message{
		message.NewUserMessage("How do I calculate the area of a circle?"),
	}

	// Create context and request
	ctx := planner.NewContext(messages, "How do I calculate the area of a circle?", "user123", "session456")
	request := &planner.LlmRequest{
		SystemPrompt: "You are a helpful math tutor.",
		Messages:     messages,
		Temperature:  0.7,
		MaxTokens:    1024,
	}

	// Get planning instruction (output shortened for example)
	instruction, _ := reactPlanner.BuildPlanningInstruction(ctx, request)
	fmt.Println("Planning instruction contains PLANNING tag:", strings.Contains(instruction, planner.PlanningTag))
	fmt.Println("Planning instruction contains REASONING tag:", strings.Contains(instruction, planner.ReasoningTag))
	fmt.Println("Planning instruction contains ACTION tag:", strings.Contains(instruction, planner.ActionTag))
	fmt.Println("Planning instruction contains FINAL_ANSWER tag:", strings.Contains(instruction, planner.FinalAnswerTag))

	// Create a response to process
	response := message.NewAssistantMessage("The area of a circle is calculated using the formula A = πr².")
	
	// Process the response
	callbackCtx := planner.NewCallbackContext(ctx)
	processedResponses, _ := reactPlanner.ProcessPlanningResponse(callbackCtx, []message.Message{response})
	
	// Check that the response has been structured
	fmt.Println("Response contains final answer tag:", strings.Contains(processedResponses[0].Content, planner.FinalAnswerTag))
	
	// Output:
	// Planning instruction contains PLANNING tag: true
	// Planning instruction contains REASONING tag: true
	// Planning instruction contains ACTION tag: true
	// Planning instruction contains FINAL_ANSWER tag: true
	// Response contains final answer tag: true
}

func ExampleRegistry() {
	// Create a registry with default planners
	registry := planner.NewRegistry()

	// List available planners
	plannerNames := registry.List()
	fmt.Println("Available planners:", strings.Join(plannerNames, ", "))

	// Get a specific planner
	reactPlanner, _ := registry.Get("plan_re_act")
	fmt.Printf("Retrieved planner type: %T\n", reactPlanner)

	// Register a custom planner
	customPlanner := planner.NewPlanReActPlanner(
		planner.WithFinalAnswerCheck(false),
		planner.WithStructuredOutput(false),
	)
	registry.Register("custom_planner", customPlanner)

	// Verify registration
	customRetrieval, _ := registry.Get("custom_planner")
	fmt.Printf("Custom planner type: %T\n", customRetrieval)
	
	// Output:
	// Available planners: built_in, plan_re_act
	// Retrieved planner type: *planner.PlanReActPlanner
	// Custom planner type: *planner.PlanReActPlanner
}