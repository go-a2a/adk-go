// Copyright 2024 The ADK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runner_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/mock"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/runner"
)

// mockAgent mocks the agent.Agent struct for testing
type mockAgent struct {
	mock.Mock
}

func (m *mockAgent) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	args := m.Called(ctx, msg)
	return args.Get(0).(message.Message), args.Error(1)
}

func (m *mockAgent) RunWithTools(ctx context.Context, req message.Message) (message.Message, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(message.Message), args.Error(1)
}

func (m *mockAgent) WithSubAgents(subAgents ...agent.Agent) *agent.Agent {
	// Convert varargs to a slice for mocking
	subAgentInterfaces := make([]interface{}, len(subAgents))
	for i, sa := range subAgents {
		subAgentInterfaces[i] = sa
	}
	
	args := m.Called(subAgentInterfaces)
	if ret := args.Get(0); ret != nil {
		return ret.(*agent.Agent)
	}
	return nil
}

func TestNewRunner(t *testing.T) {
	mockAgent := new(mockAgent)
	mockAgent.On("Name").Return("test-agent")
	
	r := runner.NewRunner(mockAgent)
	if r == nil { t.Fatalf("r is nil, want non-nil") }
}

func TestRunner_Run(t *testing.T) {
	mockAgent := new(mockAgent)
	mockAgent.On("Name").Return("test-agent")
	
	// Set up expectations for Process method
	expectedInput := "Hello, agent!"
	expectedResponse := message.NewAssistantMessage("Hello, user!")
	
	// We need to match the message based on content since the message ID and timestamp will be different
	mockAgent.On("Process", mock.Anything, mock.MatchedBy(func(msg message.Message) bool {
		return msg.Role == message.RoleUser && msg.Content == expectedInput
	})).Return(expectedResponse, nil)
	
	// Create runner and run
	r := runner.NewRunner(mockAgent)
	response, err := r.Run(context.Background(), expectedInput)
	
	// Verify
	if err != nil { t.Errorf("Unexpected error: %v", err) }
	if got, want := response.Role, expectedResponse.Role; !cmp.Equal(got, want) { t.Errorf("response.Role = %v, want %v", got, want) }
	if got, want := response.Content, expectedResponse.Content; !cmp.Equal(got, want) { t.Errorf("response.Content = %v, want %v", got, want) }
	
	mockAgent.AssertExpectations(t)
}

func TestRunner_RunConversation(t *testing.T) {
	mockAgent := new(mockAgent)
	mockAgent.On("Name").Return("test-agent")
	
	// Set up conversation messages
	messages := []message.Message{
		message.NewUserMessage("First message"),
		message.NewAssistantMessage("First response"),
		message.NewUserMessage("Second message"),
	}
	
	// In RunConversation, we expect the last message to be processed
	expectedResponse := message.NewAssistantMessage("Second response")
	
	// Set up expectations - we should only process the last message
	mockAgent.On("Process", mock.Anything, mock.MatchedBy(func(msg message.Message) bool {
		return msg.Role == message.RoleUser && msg.Content == "Second message"
	})).Return(expectedResponse, nil)
	
	// Create runner and run conversation
	r := runner.NewRunner(mockAgent)
	response, err := r.RunConversation(context.Background(), messages)
	
	// Verify
	if err != nil { t.Errorf("Unexpected error: %v", err) }
	if got, want := response.Role, expectedResponse.Role; !cmp.Equal(got, want) { t.Errorf("response.Role = %v, want %v", got, want) }
	if got, want := response.Content, expectedResponse.Content; !cmp.Equal(got, want) { t.Errorf("response.Content = %v, want %v", got, want) }
	
	mockAgent.AssertExpectations(t)
}

func TestRunner_RunConversation_EmptyMessages(t *testing.T) {
	mockAgent := new(mockAgent)
	mockAgent.On("Name").Return("test-agent")
	
	// Empty message array
	messages := []message.Message{}
	
	// Create runner and run conversation with empty messages
	r := runner.NewRunner(mockAgent)
	response, err := r.RunConversation(context.Background(), messages)
	
	// Verify we get an empty response
	if err != nil { t.Errorf("Unexpected error: %v", err) }
	if got, want := response, message.Message{}; !cmp.Equal(got, want) { t.Errorf("response = %v, want %v", got, want) }
}