// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"maps"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/auth"
)

func TestNewEvent(t *testing.T) {
	event, err := NewEvent("agent", "Hello, world!")
	if err != nil {
		t.Fatalf("NewEvent returned error: %v", err)
	}

	if event.Author != "agent" {
		t.Errorf("expected author to be 'agent', got '%s'", event.Author)
	}

	// if event.Content != "Hello, world!" {
	// 	t.Errorf("expected content to be 'Hello, world!', got '%s'", event.Content)
	// }

	if event.ID == "" {
		t.Errorf("expected InvocationID to be set")
	}

	// if event.Actions == nil {
	// 	t.Errorf("expected Actions to be initialized")
	// }

	// if len(event.functionCalls) != 0 {
	// 	t.Errorf("expected FunctionCalls to be empty, got %d calls", len(event.functionCalls))
	// }

	// Test with empty author
	_, err = NewEvent("", "Content")
	if err != ErrEmptyAuthor {
		t.Errorf("expected ErrEmptyAuthor, got %v", err)
	}
}

func TestNewUserEvent(t *testing.T) {
	event, err := NewUserEvent("User message")
	if err != nil {
		t.Fatalf("NewUserEvent returned error: %v", err)
	}

	if event.Author != "user" {
		t.Errorf("expected author to be 'user', got '%s'", event.Author)
	}
}

func TestNewAgentEvent(t *testing.T) {
	event, err := NewAgentEvent("assistant", "Agent response")
	if err != nil {
		t.Fatalf("NewAgentEvent returned error: %v", err)
	}

	if event.Author != "assistant" {
		t.Errorf("expected author to be 'assistant', got '%s'", event.Author)
	}
}

func TestWithBranch(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	event.WithBranch("main")

	if event.Branch != "main" {
		t.Errorf("expected branch to be 'main', got '%s'", event.Branch)
	}
}

func TestAddFunctionCall(t *testing.T) {
	event, err := NewEvent("agent", "Content")
	if err != nil {
		t.Fatal(err)
	}

	params := map[string]any{
		"param1": "value1",
		"param2": 42,
	}

	fc, err := event.AddFunctionCall("test_function", params)
	if err != nil {
		t.Fatalf("AddFunctionCall returned error: %v", err)
	}

	if fc.Name != "test_function" {
		t.Errorf("expected function name to be 'test_function', got '%s'", fc.Name)
	}

	if fc.ID == "" {
		t.Errorf("expected function ID to be set")
	}

	if !maps.Equal(fc.Args, params) {
		t.Errorf("Parameters mismatch: got %v, want %v", fc.Args, params)
	}

	if len(event.FunctionCalls()) != 1 {
		t.Errorf("expected 1 function call, got %d", len(event.FunctionCalls()))
	}
}

func TestAddLongRunningFunctionCall(t *testing.T) {
	event, _ := NewEvent("agent", "Content")

	params := map[string]any{
		"param1": "value1",
	}

	fc, err := event.AddLongRunningFunctionCall("long_function", params)
	if err != nil {
		t.Fatalf("AddLongRunningFunctionCall returned error: %v", err)
	}

	if !slices.Contains(event.LongRunningToolIDs, fc.ID) {
		t.Errorf("expected IsLongRunning to be true")
	}

	if len(event.LongRunningToolIDs) != 1 {
		t.Fatalf("expected 1 long running tool ID, got %d", len(event.LongRunningToolIDs))
	}

	if event.LongRunningToolIDs[0] != fc.ID {
		t.Errorf("expected long running tool ID to match function ID")
	}
}

func TestAddFunctionResponse(t *testing.T) {
	event, err := NewEvent("agent", "Content")
	if err != nil {
		t.Fatal(err)
	}
	fc, err := event.AddFunctionCall("test_function", map[string]any{})
	if err != nil {
		t.Fatalf("event.AddFunctionCall returned error: %v", err)
	}

	response := &genai.FunctionResponse{
		Response: map[string]any{
			"result": "success",
			"data":   123,
		},
	}

	if err := event.AddFunctionResponse(fc.ID, response); err != nil {
		t.Fatalf("SetFunctionResponse returned error: %v", err)
	}

	// Check if response was set
	if !cmp.Equal(event.FunctionResponses()[0].Response, response.Response) {
		t.Errorf("Response mismatch: got %v, want %v", event.FunctionResponses()[0].Response, response.Response)
	}

	// Try to set response for non-existent function call
	if err := event.AddFunctionResponse("non-existent-id", response); err == nil {
		t.Errorf("expected error for non-existent function call")
	}
}

func TestIsFinalResponse(t *testing.T) {
	t.Skip("TODO")

	// User events are never final responses
	userEvent, err := NewUserEvent("User message")
	if err != nil {
		t.Fatal(err)
	}
	if userEvent.IsFinalResponse() {
		t.Errorf("User event should not be a final response")
	}

	// Agent event with no function calls is a final response
	agentEvent, err := NewAgentEvent("assistant", "Agent response")
	if err != nil {
		t.Fatal(err)
	}
	if !agentEvent.IsFinalResponse() {
		t.Errorf("Agent event with no function calls should be a final response")
	}

	// Agent event with a function call without response is not final
	agentEvent2, _ := NewAgentEvent("assistant", "Agent response")
	if _, err := agentEvent2.AddFunctionCall("test_function", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if agentEvent2.IsFinalResponse() {
		t.Errorf("Agent event with function call without response should not be final")
	}

	// Agent event with a function call with response is final
	agentEvent3, err := NewAgentEvent("assistant", "Agent response")
	if err != nil {
		t.Fatal(err)
	}
	fc, err := agentEvent3.AddFunctionCall("test_function", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := agentEvent3.AddFunctionResponse(fc.ID, &genai.FunctionResponse{Response: map[string]any{"result": "success"}}); err != nil {
		t.Fatal(err)
	}
	if !agentEvent3.IsFinalResponse() {
		t.Errorf("Agent event with function call with response should be final")
	}

	// Agent event with long running tool is not final
	agentEvent4, err := NewAgentEvent("assistant", "Agent response")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = agentEvent4.AddLongRunningFunctionCall("long_function", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if agentEvent4.IsFinalResponse() {
		t.Errorf("Agent event with long running tool should not be final")
	}
}

func TestFunctionCalls(t *testing.T) {
	event, _ := NewEvent("agent", "Content")
	if _, err := event.AddFunctionCall("function1", map[string]any{"p1": "v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := event.AddFunctionCall("function2", map[string]any{"p2": "v2"}); err != nil {
		t.Fatal(err)
	}

	calls := event.FunctionCalls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 function calls, got %d", len(calls))
	}

	// Check that the returned slice is a copy (modifying it shouldn't affect the original)
	calls[0].Name = "modified"
	if event.FunctionCalls()[0].Name == "modified" {
		t.Errorf("GetFunctionCalls should return a copy, not a reference")
	}
}

func TestFunctionResponses(t *testing.T) {
	event, _ := NewEvent("agent", "Content")

	fc1, err := event.AddFunctionCall("function1", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := event.AddFunctionResponse(fc1.ID, &genai.FunctionResponse{Response: map[string]any{"r1": "v1"}}); err != nil {
		t.Fatal(err)
	}

	fc2, err := event.AddFunctionCall("function2", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := event.AddFunctionResponse(fc2.ID, &genai.FunctionResponse{Response: map[string]any{"r2": "v2"}}); err != nil {
		t.Fatal(err)
	}

	// Add a function call without response
	_, err = event.AddFunctionCall("function3", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	responses := event.FunctionResponses()
	if len(responses) != 2 {
		t.Fatalf("expected 2 function responses, got %d", len(responses))
	}

	t.Logf("responses: %#v", responses[0])

	if responses[0].Name == "function1" && responses[0].Response["r1"] != "v1" {
		t.Errorf("expected response for function1 to contain r1=v1")
	}

	if responses[1].Name == "function2" && responses[0].Response["r2"] != "v2" {
		t.Errorf("expected response for function2 to contain r2=v2")
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
			expected: false,
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := NewEvent("agent", tt.content)
			if err != nil {
				t.Fatal(err)
			}
			result := event.HasTrailingCodeExecutionResult()
			if result != tt.expected {
				t.Errorf("HasTrailingCodeExecutionResult() = %v, want %v", result, tt.expected)
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
		t.Errorf("expected ID length to be %d, got %d", DefaultIDLength, len(id1))
	}

	// Generate a second ID to ensure they're different
	id2, _ := NewID()
	if id1 == id2 {
		t.Errorf("expected different IDs, got the same: %s", id1)
	}
}

func TestEventActions(t *testing.T) {
	// Test creation with default values
	actions := NewEventActions()

	if actions.SkipSummarization {
		t.Errorf("expected SkipSummarization to be false by default")
	}

	if actions.StateDelta == nil {
		t.Errorf("expected StateDelta to be initialized")
	}

	if actions.ArtifactDelta == nil {
		t.Errorf("expected ArtifactDelta to be initialized")
	}

	if actions.RequestedAuthConfigs == nil {
		t.Errorf("expected RequestedAuthConfigs to be initialized")
	}

	// Test fluent interface for setting values
	actions.WithSkipSummarization(true)
	if !actions.SkipSummarization {
		t.Errorf("expected SkipSummarization to be true after setting")
	}

	actions.WithTransferToAgent("other_agent")
	if actions.TransferToAgent != "other_agent" {
		t.Errorf("expected TransferToAgent to be 'other_agent', got '%s'", actions.TransferToAgent)
	}

	actions.WithEscalate(true)
	if !actions.Escalate {
		t.Errorf("expected Escalate to be true after setting")
	}

	// Test adding to maps
	actions.WithStateDelta("key1", "value1")
	if actions.StateDelta["key1"] != "value1" {
		t.Errorf("expected StateDelta to contain key1=value1")
	}

	actions.WithArtifactDelta("artifact1", 2)
	if actions.ArtifactDelta["artifact1"] != 2 {
		t.Errorf("expected ArtifactDelta to contain artifact1=v2")
	}

	actions.WithRequestedAuthConfig("service1", &auth.AuthConfig{
		AuthScheme: &auth.AuthScheme{
			OAuth2: &auth.OAuth2Scheme{
				Type: auth.SchemeTypeOAuth2,
			},
		},
	})
	authConfig, ok := actions.RequestedAuthConfigs["service1"]
	if !ok {
		t.Errorf("expected RequestedAuthConfigs to contain service1 with map value")
	} else if authConfig.AuthScheme.GetSchemeType() != auth.SchemeTypeOAuth2 {
		t.Errorf("expected RequestedAuthConfigs for service1 to contain type=oauth")
	}
}
