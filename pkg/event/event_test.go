// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package event

import (
	"testing"
	
	"github.com/google/go-cmp/cmp"
)

func TestNewEvent(t *testing.T) {
	event, err := NewEvent("agent", "Hello, world!")
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}
	
	if event.Author != "agent" {
		t.Errorf("Expected author to be 'agent', got '%s'", event.Author)
	}
	
	if event.Content != "Hello, world!" {
		t.Errorf("Expected content to be 'Hello, world!', got '%s'", event.Content)
	}
	
	if event.InvocationID == "" {
		t.Errorf("Expected InvocationID to be set")
	}
	
	if event.Actions == nil {
		t.Errorf("Expected Actions to be initialized")
	}
	
	if len(event.FunctionCalls) != 0 {
		t.Errorf("Expected FunctionCalls to be empty, got %d calls", len(event.FunctionCalls))
	}
	
	// Test with empty author
	_, err = NewEvent("", "Content")
	if err != ErrEmptyAuthor {
		t.Errorf("Expected ErrEmptyAuthor, got %v", err)
	}
}

func TestNewUserEvent(t *testing.T) {
	event, err := NewUserEvent("User message")
	if err != nil {
		t.Fatalf("NewUserEvent returned error: %v", err)
	}
	
	if event.Author != "user" {
		t.Errorf("Expected author to be 'user', got '%s'", event.Author)
	}
}

func TestNewAgentEvent(t *testing.T) {
	event, err := NewAgentEvent("assistant", "Agent response")
	if err != nil {
		t.Fatalf("NewAgentEvent returned error: %v", err)
	}
	
	if event.Author != "assistant" {
		t.Errorf("Expected author to be 'assistant', got '%s'", event.Author)
	}
}

func TestWithBranch(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	event.WithBranch("main")
	
	if event.Branch != "main" {
		t.Errorf("Expected branch to be 'main', got '%s'", event.Branch)
	}
}

func TestAddFunctionCall(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	
	params := map[string]interface{}{
		"param1": "value1",
		"param2": 42,
	}
	
	fc, err := event.AddFunctionCall("test_function", params)
	if err != nil {
		t.Fatalf("AddFunctionCall returned error: %v", err)
	}
	
	if fc.Name != "test_function" {
		t.Errorf("Expected function name to be 'test_function', got '%s'", fc.Name)
	}
	
	if fc.ID == "" {
		t.Errorf("Expected function ID to be set")
	}
	
	if !cmp.Equal(fc.Parameters, params) {
		t.Errorf("Parameters mismatch: got %v, want %v", fc.Parameters, params)
	}
	
	if len(event.FunctionCalls) != 1 {
		t.Errorf("Expected 1 function call, got %d", len(event.FunctionCalls))
	}
}

func TestAddLongRunningFunctionCall(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	
	params := map[string]interface{}{
		"param1": "value1",
	}
	
	fc, err := event.AddLongRunningFunctionCall("long_function", params)
	if err != nil {
		t.Fatalf("AddLongRunningFunctionCall returned error: %v", err)
	}
	
	if !fc.IsLongRunning {
		t.Errorf("Expected IsLongRunning to be true")
	}
	
	if len(event.LongRunningToolIDs) != 1 {
		t.Errorf("Expected 1 long running tool ID, got %d", len(event.LongRunningToolIDs))
	}
	
	if event.LongRunningToolIDs[0] != fc.ID {
		t.Errorf("Expected long running tool ID to match function ID")
	}
}

func TestSetFunctionResponse(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	fc, _ := event.AddFunctionCall("test_function", map[string]interface{}{})
	
	response := map[string]interface{}{
		"result": "success",
		"data": 123,
	}
	
	err := event.SetFunctionResponse(fc.ID, response)
	if err != nil {
		t.Fatalf("SetFunctionResponse returned error: %v", err)
	}
	
	// Check if response was set
	if !cmp.Equal(event.FunctionCalls[0].Response, response) {
		t.Errorf("Response mismatch: got %v, want %v", event.FunctionCalls[0].Response, response)
	}
	
	// Try to set response for non-existent function call
	err = event.SetFunctionResponse("non-existent-id", response)
	if err == nil {
		t.Errorf("Expected error for non-existent function call")
	}
}

func TestIsFinalResponse(t *testing.T) {
	// User events are never final responses
	userEvent, _ := NewUserEvent("User message")
	if userEvent.IsFinalResponse() {
		t.Errorf("User event should not be a final response")
	}
	
	// Agent event with no function calls is a final response
	agentEvent, _ := NewAgentEvent("assistant", "Agent response")
	if !agentEvent.IsFinalResponse() {
		t.Errorf("Agent event with no function calls should be a final response")
	}
	
	// Agent event with a function call without response is not final
	agentEvent2, _ := NewAgentEvent("assistant", "Agent response")
	_, _ = agentEvent2.AddFunctionCall("test_function", map[string]interface{}{})
	if agentEvent2.IsFinalResponse() {
		t.Errorf("Agent event with function call without response should not be final")
	}
	
	// Agent event with a function call with response is final
	agentEvent3, _ := NewAgentEvent("assistant", "Agent response")
	fc, _ := agentEvent3.AddFunctionCall("test_function", map[string]interface{}{})
	_ = agentEvent3.SetFunctionResponse(fc.ID, map[string]interface{}{"result": "success"})
	if !agentEvent3.IsFinalResponse() {
		t.Errorf("Agent event with function call with response should be final")
	}
	
	// Agent event with long running tool is not final
	agentEvent4, _ := NewAgentEvent("assistant", "Agent response")
	_, _ = agentEvent4.AddLongRunningFunctionCall("long_function", map[string]interface{}{})
	if agentEvent4.IsFinalResponse() {
		t.Errorf("Agent event with long running tool should not be final")
	}
}

func TestGetFunctionCalls(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	_, _ = event.AddFunctionCall("function1", map[string]interface{}{"p1": "v1"})
	_, _ = event.AddFunctionCall("function2", map[string]interface{}{"p2": "v2"})
	
	calls := event.GetFunctionCalls()
	if len(calls) != 2 {
		t.Errorf("Expected 2 function calls, got %d", len(calls))
	}
	
	// Check that the returned slice is a copy (modifying it shouldn't affect the original)
	calls[0].Name = "modified"
	if event.FunctionCalls[0].Name == "modified" {
		t.Errorf("GetFunctionCalls should return a copy, not a reference")
	}
}

func TestGetFunctionResponses(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	
	fc1, _ := event.AddFunctionCall("function1", map[string]interface{}{})
	_ = event.SetFunctionResponse(fc1.ID, map[string]interface{}{"r1": "v1"})
	
	fc2, _ := event.AddFunctionCall("function2", map[string]interface{}{})
	_ = event.SetFunctionResponse(fc2.ID, map[string]interface{}{"r2": "v2"})
	
	// Add a function call without response
	_, _ = event.AddFunctionCall("function3", map[string]interface{}{})
	
	responses := event.GetFunctionResponses()
	if len(responses) != 2 {
		t.Errorf("Expected 2 function responses, got %d", len(responses))
	}
	
	if responses["function1"]["r1"] != "v1" {
		t.Errorf("Expected response for function1 to contain r1=v1")
	}
	
	if responses["function2"]["r2"] != "v2" {
		t.Errorf("Expected response for function2 to contain r2=v2")
	}
	
	if _, exists := responses["function3"]; exists {
		t.Errorf("Function without response should not be included")
	}
}

func TestHasTrailingCodeExecutionResult(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "With trailing code execution result",
			content: `Some content
<code_execution_result>
Output
</code_execution_result>`,
			expected: true,
		},
		{
			name: "With code execution result in the middle",
			content: `<code_execution_result>
Output
</code_execution_result>
More content`,
			expected: false,
		},
		{
			name:     "Without code execution result",
			content:  "Just regular content",
			expected: false,
		},
		{
			name:     "With only opening tag",
			content:  "Content <code_execution_result>",
			expected: false,
		},
		{
			name:     "With only closing tag",
			content:  "Content </code_execution_result>",
			expected: false,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event, _ := NewEvent("agent", tc.content)
			result := event.HasTrailingCodeExecutionResult()
			if result != tc.expected {
				t.Errorf("HasTrailingCodeExecutionResult() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestNewID(t *testing.T) {
	id1, err := NewID()
	if err != nil {
		t.Fatalf("NewID returned error: %v", err)
	}
	
	if len(id1) != DefaultIDLength {
		t.Errorf("Expected ID length to be %d, got %d", DefaultIDLength, len(id1))
	}
	
	// Generate a second ID to ensure they're different
	id2, _ := NewID()
	if id1 == id2 {
		t.Errorf("Expected different IDs, got the same: %s", id1)
	}
}

func TestEventActions(t *testing.T) {
	// Test creation with default values
	actions := NewEventActions()
	
	if actions.SkipSummarization {
		t.Errorf("Expected SkipSummarization to be false by default")
	}
	
	if actions.StateDelta == nil {
		t.Errorf("Expected StateDelta to be initialized")
	}
	
	if actions.ArtifactDelta == nil {
		t.Errorf("Expected ArtifactDelta to be initialized")
	}
	
	if actions.RequestedAuthConfigs == nil {
		t.Errorf("Expected RequestedAuthConfigs to be initialized")
	}
	
	// Test fluent interface for setting values
	actions.WithSkipSummarization(true)
	if !actions.SkipSummarization {
		t.Errorf("Expected SkipSummarization to be true after setting")
	}
	
	actions.WithTransferToAgent("other_agent")
	if actions.TransferToAgent != "other_agent" {
		t.Errorf("Expected TransferToAgent to be 'other_agent', got '%s'", actions.TransferToAgent)
	}
	
	actions.WithEscalate(true)
	if !actions.Escalate {
		t.Errorf("Expected Escalate to be true after setting")
	}
	
	// Test adding to maps
	actions.AddStateDelta("key1", "value1")
	if actions.StateDelta["key1"] != "value1" {
		t.Errorf("Expected StateDelta to contain key1=value1")
	}
	
	actions.AddArtifactDelta("artifact1", "v2")
	if actions.ArtifactDelta["artifact1"] != "v2" {
		t.Errorf("Expected ArtifactDelta to contain artifact1=v2")
	}
	
	actions.AddRequestedAuthConfig("service1", map[string]string{"type": "oauth"})
	authConfig, ok := actions.RequestedAuthConfigs["service1"].(map[string]string)
	if !ok {
		t.Errorf("Expected RequestedAuthConfigs to contain service1 with map value")
	} else if authConfig["type"] != "oauth" {
		t.Errorf("Expected RequestedAuthConfigs for service1 to contain type=oauth")
	}
}