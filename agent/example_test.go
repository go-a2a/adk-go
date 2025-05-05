// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-a2a/adk-go/agent"
	"github.com/go-a2a/adk-go/model"
	"google.golang.org/genai"
)

// ExampleLLMAgent demonstrates how to use an LLMAgent.
func Example_llmAgent() {
	// Create a logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a Gemini model
	googleModel, err := model.NewGeminiModel(
		model.WithModelName("gemini-1.5-pro"),
		model.WithAPIKey(os.Getenv("GOOGLE_API_KEY")),
	)
	if err != nil {
		logger.Error("Failed to create model", "error", err)
		return
	}

	// Create an LLM agent
	llmAgent := agent.NewLLMAgent(
		agent.WithLLMModel(googleModel),
		agent.WithName("gemini-agent"),
		agent.WithLLMLogger(logger),
	)

	// Create a sample tool
	convertTempTool := agent.NewTool(
		agent.WithToolName("convertTemperature"),
		agent.WithToolDescription("Convert temperature between Celsius and Fahrenheit"),
		agent.WithToolParameters([]agent.Parameter{
			{
				Name:        "temperature",
				Type:        "number",
				Description: "The temperature value to convert",
				Required:    true,
			},
			{
				Name:        "from_unit",
				Type:        "string",
				Description: "The unit to convert from (C or F)",
				Required:    true,
				Enum:        []string{"C", "F"},
			},
		}),
		agent.WithToolExecuteFunc(func(ctx context.Context, params map[string]any) (any, error) {
			// Extract parameters
			temp, ok := params["temperature"].(float64)
			if !ok {
				return nil, fmt.Errorf("invalid temperature: %v", params["temperature"])
			}

			fromUnit, ok := params["from_unit"].(string)
			if !ok {
				return nil, fmt.Errorf("invalid from_unit: %v", params["from_unit"])
			}

			// Convert temperature
			var result float64
			var toUnit string
			switch fromUnit {
			case "C":
				result = temp*9/5 + 32
				toUnit = "F"
			case "F":
				result = (temp - 32) * 5 / 9
				toUnit = "C"
			default:
				return nil, fmt.Errorf("unsupported unit: %s", fromUnit)
			}

			return map[string]any{
				"original_temperature":  temp,
				"original_unit":         fromUnit,
				"converted_temperature": result,
				"converted_unit":        toUnit,
			}, nil
		}),
	)

	// Add the tool to the agent
	llmAgent.AddTool(convertTempTool)

	// Create an invocation context
	invocationCtx := agent.NewInvocationContextWithOptions(
		agent.WithInvocationRequest(&genai.Content{
			Role:  model.RoleUser,
			Parts: []genai.Part{genai.Text("Can you convert 25 degrees Celsius to Fahrenheit?")},
		}),
		agent.WithBeforeCallback(func(ctx *agent.CallbackContext) *genai.Content {
			logger.Info("Executing before callback")
			return nil
		}),
		agent.WithAfterCallback(func(ctx *agent.CallbackContext) *genai.Content {
			logger.Info("Executing after callback", "duration", ctx.Duration())
			return nil
		}),
	)

	// Invoke the agent synchronously
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := llmAgent.Invoke(ctx, *invocationCtx)
	if err != nil {
		logger.Error("Failed to invoke agent", "error", err)
		return
	}

	// Print the response
	fmt.Println("Agent response:")
	for _, part := range response.Parts {
		fmt.Println(part)
	}
}

// ExampleSequentialAgent demonstrates how to use a SequentialAgent.
func Example_sequentialAgent() {
	// Create a logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create two LLM agents
	googleModel, err := model.NewGeminiModel(
		model.WithModelName("gemini-1.5-pro"),
		model.WithAPIKey(os.Getenv("GOOGLE_API_KEY")),
	)
	if err != nil {
		logger.Error("Failed to create model", "error", err)
		return
	}

	// First agent to summarize the input
	summarizerAgent := agent.NewLLMAgent(
		agent.WithLLMModel(googleModel),
		agent.WithName("summarizer"),
		agent.WithLLMLogger(logger),
	)

	// Second agent to provide recommendations based on the summary
	recommenderAgent := agent.NewLLMAgent(
		agent.WithLLMModel(googleModel),
		agent.WithName("recommender"),
		agent.WithLLMLogger(logger),
	)

	// Create a sequential agent that chains the two agents
	seqAgent := agent.NewSequentialAgent(
		agent.WithName("sequential-agent"),
		agent.WithAgents([]agent.BaseAgent{summarizerAgent, recommenderAgent}),
		agent.WithSequentialLogger(logger),
	)

	// Create an invocation context
	invocationCtx := agent.NewInvocationContextWithOptions(
		agent.WithInvocationRequest(&genai.Content{
			Role:  model.RoleUser,
			Parts: []genai.Part{genai.Text("I need to plan a vacation for a family of four. We enjoy outdoor activities and good food.")},
		}),
	)

	// Invoke the agent synchronously
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	response, err := seqAgent.Invoke(ctx, *invocationCtx)
	if err != nil {
		logger.Error("Failed to invoke agent", "error", err)
		return
	}

	// Print the response
	fmt.Println("Sequential agent response:")
	for _, part := range response.Parts {
		fmt.Println(part)
	}
}
