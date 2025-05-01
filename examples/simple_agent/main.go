// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package main demonstrates a simple agent implementation using the ADK.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-a2a/adk-go/agent/base"
	"github.com/go-a2a/adk-go/agent/events"
	"github.com/go-a2a/adk-go/agent/state"
	"github.com/go-a2a/adk-go/agent/tools"
	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

func main() {
	ctx := context.Background()

	// Create a registry for the models
	modelRegistry := model.NewRegistry()

	// Register a model provider (this would typically come from configuration)
	// For this example, we'll use a mock model for simplicity
	modelRegistry.RegisterModelProvider("mock", func(ctx context.Context, opts ...model.Option) (model.Model, error) {
		return &MockModel{}, nil
	})

	// Get a model instance
	llm, err := modelRegistry.GetModel(ctx, "mock")
	if err != nil {
		fmt.Printf("Error getting model: %v\n", err)
		os.Exit(1)
	}

	// Create a tool registry
	toolRegistry := tools.NewRegistry()

	// Register some built-in tools
	dateTimeTool := tools.NewDateTimeTool()
	if err := toolRegistry.RegisterTool(dateTimeTool); err != nil {
		fmt.Printf("Error registering date time tool: %v\n", err)
		os.Exit(1)
	}

	// Create a state layer
	stateLayer := state.NewMemoryStateLayer()

	// Create a runner
	runner := base.NewRunner(
		base.WithSessionID("example-session"),
		base.WithStateLayer(stateLayer),
		base.WithToolRegistry(toolRegistry),
	)

	// Create a simple agent
	agent := base.NewAgent(
		base.WithID("example-agent"),
		base.WithName("Example Agent"),
		base.WithDescription("A simple example agent"),
		base.WithSessionID("example-session"),
		base.WithModel(llm),
		base.WithSystemPrompt("You are a helpful assistant that provides concise answers."),
	)

	// Register the agent with the runner
	runner.RegisterAgent(agent)

	// Start the runner
	if err := runner.Start(ctx); err != nil {
		fmt.Printf("Error starting runner: %v\n", err)
		os.Exit(1)
	}

	// Print a welcome message
	fmt.Println("==================================================")
	fmt.Println("Simple Agent Example")
	fmt.Println("==================================================")
	fmt.Println("Type a message to interact with the agent or type 'exit' to quit.")
	fmt.Println("Available tools: date/time")
	fmt.Println("==================================================")

	// Set up a channel to listen for responses
	responses := make(chan *events.Event, 10)

	// Register a response handler with the runner
	runner.RegisterEventHandler(events.EventTypeAgentResponse, func(event *events.Event) error {
		responses <- event
		return nil
	})

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		runner.Stop()
		os.Exit(0)
	}()

	// Simple interaction loop
	go func() {
		for {
			var input string
			fmt.Print("> ")
			fmt.Scanln(&input)

			if input == "exit" {
				fmt.Println("Exiting...")
				runner.Stop()
				os.Exit(0)
			}

			// Send the user message to the agent
			if err := runner.SendMessage(ctx, agent.ID(), input); err != nil {
				fmt.Printf("Error sending message: %v\n", err)
			}
		}
	}()

	// Process agent responses
	for event := range responses {
		content, err := event.GetAgentResponseContent()
		if err != nil {
			fmt.Printf("Error getting response content: %v\n", err)
			continue
		}

		var responseText string
		for _, part := range content.Response.Parts {
			if part.Text != "" {
				responseText += part.Text
			}
		}

		fmt.Printf("Agent: %s\n", responseText)
	}
}

// MockModel is a mock implementation of the Model interface for demo purposes.
type MockModel struct{}

func (m *MockModel) Name() string {
	return "mock-model"
}

func (m *MockModel) Connect() (model.BaseConnection, error) {
	return nil, nil
}

func (m *MockModel) GenerateContent(ctx context.Context, request *model.LLMRequest) (*model.LLMResponse, error) {
	// Simulate a delay to make it feel like a real API call
	time.Sleep(500 * time.Millisecond)

	// Determine if there's a tool call
	var userMessage string
	for _, content := range request.Contents {
		if content.Role == model.RoleUser {
			for _, part := range content.Parts {
				if part.Text != "" {
					userMessage = part.Text
					break
				}
			}
		}
	}

	// Check for datetime keywords to trigger tool usage
	if containsAny(userMessage, []string{"time", "date", "today", "now", "current"}) && 
	   request.Config != nil && len(request.Config.Tools) > 0 {
		// Generate a tool call
		return &model.LLMResponse{
			Candidates: []*model.Candidate{
				{
					Content: &genai.Content{
						Role: model.RoleAssistant,
						Parts: []*genai.Part{
							{
								FunctionCall: &genai.FunctionCall{
									Name: "datetime",
									Args: map[string]any{
										"format":   "RFC3339",
										"timezone": "UTC",
									},
								},
							},
						},
					},
				},
			},
		}, nil
	}

	// Otherwise, generate a simple text response
	return &model.LLMResponse{
		Candidates: []*model.Candidate{
			{
				Content: &genai.Content{
					Role: model.RoleAssistant,
					Parts: []*genai.Part{
						{Text: fmt.Sprintf("You said: %s", userMessage)},
					},
				},
			},
		},
	}, nil
}

func (m *MockModel) StreamGenerateContent(ctx context.Context, request *model.LLMRequest) iter.Seq2[*model.LLMResponse, error] {
	return nil
}

// containsAny checks if the string contains any of the substrings.
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(strings.ToLower(s), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}