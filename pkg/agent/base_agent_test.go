// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"testing"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/tool"
)

func TestNewBaseAgent(t *testing.T) {
	mockTool := &mockTool{}
	processFn := func(ctx context.Context, msg message.Message) (message.Message, error) {
		return message.NewAssistantMessage("Base agent response"), nil
	}

	a := agent.NewBaseAgent(
		"test-base-agent",
		"test base agent description",
		[]tool.Tool{mockTool},
		processFn,
	)

	if a == nil {
		t.Fatal("Expected agent to not be nil")
	}
	if got, want := a.Name(), "test-base-agent"; got != want {
		t.Errorf("a.Name() = %q, want %q", got, want)
	}
	if got, want := a.Description(), "test base agent description"; got != want {
		t.Errorf("a.Description() = %q, want %q", got, want)
	}
	if got, want := len(a.Tools()), 1; got != want {
		t.Errorf("len(a.Tools()) = %d, want %d", got, want)
	}
}

func TestBaseAgent_Process(t *testing.T) {
	expectedResponse := message.NewAssistantMessage("Custom process response")
	processFn := func(ctx context.Context, msg message.Message) (message.Message, error) {
		return expectedResponse, nil
	}

	a := agent.NewBaseAgent(
		"test-base-agent",
		"test base agent description",
		nil,
		processFn,
	)

	msg := message.NewUserMessage("Process this")
	response, err := a.Process(context.Background(), msg)
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}
	if got, want := response.Role, expectedResponse.Role; got != want {
		t.Errorf("response.Role = %q, want %q", got, want)
	}
	if got, want := response.Content, expectedResponse.Content; got != want {
		t.Errorf("response.Content = %q, want %q", got, want)
	}
}

func TestBaseAgent_ProcessWithTools(t *testing.T) {
	mockTool := &mockTool{}

	processFn := func(ctx context.Context, msg message.Message) (message.Message, error) {
		// Simulate checking tools and processing based on them
		tools := []string{}
		for _, tool := range []tool.Tool{mockTool} {
			tools = append(tools, tool.Name())
		}

		return message.NewAssistantMessage("Processed with tools: " + tools[0]), nil
	}

	a := agent.NewBaseAgent(
		"test-base-agent",
		"test base agent description",
		[]tool.Tool{mockTool},
		processFn,
	)

	msg := message.NewUserMessage("Use a tool")
	response, err := a.Process(context.Background(), msg)
	if err != nil {
		t.Errorf("Process() error = %v, want nil", err)
	}
	if got, want := response.Content, "Processed with tools: mock-tool"; got != want {
		t.Errorf("response.Content = %q, want %q", got, want)
	}
}
