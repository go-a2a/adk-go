package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/adk-go/agent"
)

// SimpleModel is a mock LLM model for demonstration.
type SimpleModel struct{}

// Generate generates content based on the given prompt.
func (m *SimpleModel) Generate(ctx context.Context, prompt string, opts ...agent.ModelOption) (string, error) {
	fmt.Println("Generating response for prompt:", prompt)

	// In a real implementation, this would call an actual LLM
	return "This is a response from the SimpleModel LLM. I can help you with that!", nil
}

// GenerateStream streams generated content for the given prompt.
func (m *SimpleModel) GenerateStream(ctx context.Context, prompt string, opts ...agent.ModelOption) (<-chan agent.StreamChunk, error) {
	chunks := make(chan agent.StreamChunk)

	go func() {
		defer close(chunks)

		response := "This is a streamed response from the SimpleModel LLM.\nI'm generating this text token by token.\nHow can I help you today?"
		words := []string{"This", "is", "a", "streamed", "response", "from", "the", "SimpleModel", "LLM.",
			"I'm", "generating", "this", "text", "token", "by", "token.", "How", "can", "I", "help", "you", "today?"}

		for _, word := range words {
			select {
			case <-ctx.Done():
				chunks <- agent.StreamChunk{Error: ctx.Err(), Done: true}
				return
			case chunks <- agent.StreamChunk{Content: word + " ", Done: false}:
				time.Sleep(200 * time.Millisecond) // Simulate thinking time
			}
		}

		chunks <- agent.StreamChunk{Done: true}
	}()

	return chunks, nil
}

// WeatherTool provides weather information
func WeatherTool() *agent.BaseTool {
	return agent.NewTool(
		agent.WithName("get_weather"),
		agent.WithDescription("Get the current weather for a location"),
		agent.WithSchema(map[string]any{
			"type": "object",
			"properties": map[string]any{
				"location": map[string]any{
					"type":        "string",
					"description": "The city and state to get weather for, e.g. 'San Francisco, CA'",
				},
			},
			"required": []string{"location"},
		}),
		agent.WithExecutor(func(ctx context.Context, input any) (any, error) {
			// Parse input
			inputMap, ok := input.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("input must be a map")
			}

			location, ok := inputMap["location"].(string)
			if !ok {
				return nil, fmt.Errorf("location must be a string")
			}

			// In a real implementation, this would call a weather API
			return map[string]any{
				"location":    location,
				"temperature": "72°F",
				"condition":   "sunny",
				"humidity":    "45%",
			}, nil
		}),
	)
}

func main() {
	// Initialize the agent
	if err := agent.Initialize(); err != nil {
		log.Fatalf("Failed to initialize ADK: %v", err)
	}

	// Create a simple memory
	memory := agent.NewSimpleMemory(10)

	// Create a simple model
	model := &SimpleModel{}

	// Create an LLM agent
	llmAgent, err := agent.CreateAgent(
		agent.AgentTypeLLM,
		"SimpleAssistant",
		agent.WithModel(model),
		agent.WithInstruction("You are a helpful assistant that can provide information and use tools when needed."),
		agent.WithMemory(memory),
	)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Add tools to the agent
	llmAgent.AddTool(WeatherTool())

	// Execute the agent
	response, err := llmAgent.Execute(
		context.Background(),
		"What's the weather like in San Francisco?",
		agent.WithMaxTokens(1000),
		agent.WithTemperature(0.7),
	)
	if err != nil {
		log.Fatalf("Failed to execute agent: %v", err)
	}

	// Print the response
	fmt.Println("Agent response:")
	fmt.Println(response.Content)

	// If there are tool calls, print them
	if len(response.ToolCalls) > 0 {
		fmt.Println("\nTool calls:")
		for _, tc := range response.ToolCalls {
			outputJSON, _ := json.MarshalIndent(tc.Output, "", "  ")
			fmt.Printf("- %s: %s\n", tc.Name, string(outputJSON))
		}
	}
}
