// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package planner

import (
	"strings"
	"testing"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/google/go-cmp/cmp"
)

func TestContext(t *testing.T) {
	// Create test messages
	messages := []message.Message{
		message.NewUserMessage("Hello"),
		message.NewAssistantMessage("Hi there"),
	}
	
	// Create a context
	ctx := NewContext(messages, "query", "user1", "session1")
	
	// Test context values
	if ctx.Query != "query" {
		t.Errorf("Expected Query to be 'query', got %q", ctx.Query)
	}
	
	if ctx.UserID != "user1" {
		t.Errorf("Expected UserID to be 'user1', got %q", ctx.UserID)
	}
	
	if ctx.SessionID != "session1" {
		t.Errorf("Expected SessionID to be 'session1', got %q", ctx.SessionID)
	}
	
	if len(ctx.Messages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(ctx.Messages))
	}
	
	// Create a callback context
	callbackCtx := NewCallbackContext(ctx)
	
	// Test that callback context contains the original context
	if callbackCtx.Query != ctx.Query {
		t.Errorf("Expected Query to be %q, got %q", ctx.Query, callbackCtx.Query)
	}
	
	// Test that planner state is initialized
	if callbackCtx.PlannerState == nil {
		t.Error("Expected PlannerState to be initialized")
	}
}

func TestBuiltInPlanner(t *testing.T) {
	// Create a planner with thinking config
	thinkingConfig := &ThinkingConfig{
		Enabled: true,
		Visible: false,
	}
	planner := NewBuiltInPlanner(thinkingConfig)
	
	// Test thinking config
	if !planner.GetThinkingConfig().Enabled {
		t.Error("Expected thinking to be enabled")
	}
	
	if planner.GetThinkingConfig().Visible {
		t.Error("Expected thinking to be invisible")
	}
	
	// Test applying thinking config
	request := &LlmRequest{
		SystemPrompt: "Test",
		Messages:     []message.Message{},
		Temperature:  0.7,
	}
	
	// Apply thinking config
	planner.ApplyThinkingConfig(request)
	
	// Check that thinking config was applied
	if request.Thinking == nil {
		t.Error("Expected Thinking to be set")
	}
	
	if !request.Thinking.Enabled {
		t.Error("Expected Thinking.Enabled to be true")
	}
	
	// Test building planning instruction
	ctx := NewContext([]message.Message{}, "query", "user1", "session1")
	instruction, err := planner.BuildPlanningInstruction(ctx, request)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// BuiltInPlanner should return an empty string
	if instruction != "" {
		t.Errorf("Expected empty instruction, got %q", instruction)
	}
	
	// Test processing response
	callbackCtx := NewCallbackContext(ctx)
	responseParts := []message.Message{
		message.NewAssistantMessage("Test response"),
	}
	
	processed, err := planner.ProcessPlanningResponse(callbackCtx, responseParts)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// BuiltInPlanner should return the response unchanged
	if !cmp.Equal(responseParts, processed) {
		t.Errorf("Expected response to be unchanged, got: %v", cmp.Diff(responseParts, processed))
	}
}

func TestPlanReActPlanner(t *testing.T) {
	// Create a planner with default options
	planner := NewPlanReActPlanner()
	
	// Test building planning instruction
	ctx := NewContext([]message.Message{}, "query", "user1", "session1")
	request := &LlmRequest{
		SystemPrompt: "Test",
		Messages:     []message.Message{},
		Temperature:  0.7,
	}
	
	instruction, err := planner.BuildPlanningInstruction(ctx, request)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// Check that instruction contains planning tags
	if !contains(instruction, PlanningTag) || !contains(instruction, ReasoningTag) {
		t.Errorf("Expected instruction to contain planning tags")
	}
	
	// Test processing response without final answer tag
	callbackCtx := NewCallbackContext(ctx)
	response := message.NewAssistantMessage("Test response without tags")
	
	responseParts := []message.Message{response}
	processed, err := planner.ProcessPlanningResponse(callbackCtx, responseParts)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// Check that final answer tags were added
	if !contains(processed[0].Content, FinalAnswerTag) {
		t.Errorf("Expected final answer tags to be added, got: %s", processed[0].Content)
	}
	
	// Test processing response with existing tags
	responseWithTags := message.NewAssistantMessage(ReasoningTag + "Some reasoning" + ReasoningEndTag)
	responseParts = []message.Message{responseWithTags}
	
	processed, err = planner.ProcessPlanningResponse(callbackCtx, responseParts)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// Check that existing tags were preserved
	if !contains(processed[0].Content, ReasoningTag) {
		t.Errorf("Expected reasoning tags to be preserved, got: %s", processed[0].Content)
	}
	
	// Test with disabled structured output
	planner = NewPlanReActPlanner(WithStructuredOutput(false))
	processed, err = planner.ProcessPlanningResponse(callbackCtx, []message.Message{response})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	// Check that tags were not added when structured output is disabled
	if contains(processed[0].Content, FinalAnswerTag) {
		t.Errorf("Expected no tags to be added when structured output is disabled, got: %s", processed[0].Content)
	}
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry()
	
	// Test listing planners
	planners := registry.List()
	if len(planners) != 2 {
		t.Errorf("Expected 2 planners, got %d", len(planners))
	}
	
	// Test getting an existing planner
	planner, err := registry.Get("built_in")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	if _, ok := planner.(*BuiltInPlanner); !ok {
		t.Errorf("Expected *BuiltInPlanner, got %T", planner)
	}
	
	// Test getting a non-existent planner
	_, err = registry.Get("non_existent")
	if err == nil {
		t.Error("Expected error when getting non-existent planner")
	}
	
	// Test registering a new planner
	customPlanner := NewPlanReActPlanner(WithFinalAnswerCheck(false))
	registry.Register("custom", customPlanner)
	
	// Check that the new planner was registered
	planner, err = registry.Get("custom")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	
	if _, ok := planner.(*PlanReActPlanner); !ok {
		t.Errorf("Expected *PlanReActPlanner, got %T", planner)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}