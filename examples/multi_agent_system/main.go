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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/bytedance/sonic"
	"go.opentelemetry.io/otel/attribute"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/models"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/runner"
	"github.com/go-a2a/adk-go/pkg/tool"
	"github.com/go-a2a/adk-go/pkg/tools"
)

func main() {
	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down gracefully...")
		cancel()
	}()

	// Initialize logging
	observability.SetupLogger(observability.LoggerOptions{
		Level:      observability.LevelInfo,
		Writer:     os.Stdout,
		AddSource:  true,
		JSONFormat: false,
	})

	// Initialize tracing
	shutdownTracer, err := observability.InitTracer(ctx, "adk-go-multi-agent")
	if err != nil {
		slog.Error("Failed to initialize tracer", slog.Any("error", err))
		os.Exit(1)
	}
	defer shutdownTracer(context.Background())

	// Initialize metrics
	shutdownMeter, err := observability.InitMeter(ctx, "adk-go-multi-agent")
	if err != nil {
		slog.Error("Failed to initialize meter", slog.Any("error", err))
		os.Exit(1)
	}
	defer shutdownMeter(context.Background())

	// Get API key from environment
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		slog.Error("GEMINI_API_KEY environment variable is not set")
		os.Exit(1)
	}

	// Create a new Gemini model
	model, err := models.NewGeminiModel("gemini-2.0-flash", apiKey)
	if err != nil {
		slog.Error("Failed to create Gemini model", slog.Any("error", err))
		os.Exit(1)
	}
	defer model.Close()

	// Create common tools
	googleSearch := tools.NewGoogleSearchTool()
	loadWebPage := tools.NewLoadWebPageTool()

	// Create a research agent
	researchAgent := agent.NewLlmAgent(
		"ResearchAgent",
		model,
		"You are a specialized research agent. Your job is to find accurate information about topics using web search and reading web pages. Always provide factual information with sources.",
		"Specialized agent for research and fact-finding",
		[]tool.Tool{googleSearch, loadWebPage},
	)

	// Create a creative agent
	creativeAgent := agent.NewLlmAgent(
		"CreativeAgent",
		model,
		"You are a creative agent specializing in generating original content, stories, ideas, and solutions. Think outside the box and provide imaginative responses.",
		"Specialized agent for creative tasks",
		nil, // No tools needed for creative work
	)

	// Create a technical agent
	techAgent := agent.NewLlmAgent(
		"TechnicalAgent",
		model,
		"You are a technical agent with expertise in programming, computer science, and technical problem-solving. Provide clear, accurate technical explanations and solutions.",
		"Specialized agent for technical questions",
		[]tool.Tool{loadWebPage}, // Can load documentation
	)

	// Create a custom agent for analytics using BaseAgent
	analyticsAgent := agent.NewBaseAgent(
		"AnalyticsAgent",
		"Specialized agent for data analysis and interpretation",
		nil,
		func(ctx context.Context, msg message.Message) (message.Message, error) {
			// Start span for this operation
			ctx, span := observability.StartSpan(ctx, "analytics_agent_process")
			defer span.End()

			observability.Logger(ctx).Debug("Analytics agent processing message",
				slog.String("content", msg.Content),
			)

			// Simple mock implementation - in a real agent, this would do actual analytics
			result := "This is a mock data analysis result. In a real implementation, the analytics agent would process data and provide insights."

			// Record the operation
			observability.AddSpanAttributes(ctx,
				attribute.String("agent.name", "AnalyticsAgent"),
				attribute.String("agent.type", "custom"),
			)

			return message.NewAssistantMessage(result), nil
		},
	)

	// Create a simple routing tool for the coordinator
	routeToolSchema := tool.NewBaseTool(
		"route_agent",
		"Routes a query to the appropriate specialized agent. Use this to delegate work to specific agents.",
		model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"agent": map[string]any{
					"type":        "string",
					"enum":        []string{"ResearchAgent", "CreativeAgent", "TechnicalAgent", "AnalyticsAgent"},
					"description": "The name of the agent to route the query to",
				},
				"query": map[string]any{
					"type":        "string",
					"description": "The query to route to the agent",
				},
			},
			"required": []string{"agent", "query"},
		},
		func(ctx context.Context, args sonic.RawMessage) (string, error) {
			// This tool isn't actually used directly, it's just for the coordinator's planning
			return "Routing not implemented directly. This is a planning tool.", nil
		},
	)

	// Create a coordinator agent
	coordinator := agent.NewLlmAgent(
		"Coordinator",
		model,
		`You are a coordinator agent responsible for routing user queries to specialized agents.
Route queries to the most appropriate agent based on the query content:
- ResearchAgent: For factual questions requiring search and research
- CreativeAgent: For creative tasks, stories, ideas, or imagination
- TechnicalAgent: For technical questions about programming, computers, and technology
- AnalyticsAgent: For data analysis and interpretation questions

First analyze the user query to determine which agent(s) would be best suited to handle it.
If multiple agents could contribute, decide which one would provide the most value.`,
		"Coordinator that routes tasks to specialized agents",
		[]tool.Tool{routeToolSchema},
	)

	// Add sub-agents to the coordinator
	coordinator.WithSubAgents(researchAgent, creativeAgent, techAgent, analyticsAgent)

	// Create runner for the coordinator
	coordinatorRunner := runner.NewRunner(coordinator)

	// Run a simple conversation
	fmt.Println("ADK-Go Multi-Agent System - Type 'exit' to quit")
	fmt.Println("Available agents:")
	fmt.Println("- ResearchAgent: For factual questions requiring search")
	fmt.Println("- CreativeAgent: For creative tasks and ideas")
	fmt.Println("- TechnicalAgent: For technical questions")
	fmt.Println("- AnalyticsAgent: For data analysis questions")
	fmt.Println()

	// Track conversation history
	history := []message.Message{}

	for {
		// Print prompt
		fmt.Print("User: ")

		// Read user input
		var input string
		fmt.Scanln(&input)

		// Check for exit
		if input == "exit" {
			break
		}

		// Create user message
		userMsg := message.NewUserMessage(input)
		history = append(history, userMsg)

		// Set up context with timeout for this request
		requestCtx, requestCancel := context.WithTimeout(ctx, 60*time.Second)

		// Start span for the user request
		requestCtx, span := observability.StartSpan(requestCtx, "multi_agent_request")

		// Add attributes to the span
		span.SetAttributes(
			attribute.String("user.message", input),
			attribute.String("system.type", "multi_agent"),
		)

		// Process user message with the coordinator
		startTime := time.Now()
		response, err := coordinatorRunner.RunConversation(requestCtx, history)
		duration := time.Since(startTime)

		// Close the span
		span.End()

		// Cancel the request context
		requestCancel()

		// Record metrics
		observability.RecordLatency(ctx, duration,
			attribute.String("operation", "multi_agent_conversation_turn"),
		)

		if err != nil {
			slog.Error("Error processing user message with multi-agent system",
				slog.Any("error", err),
				slog.String("user_message", input),
				slog.Duration("duration", duration),
			)
			fmt.Printf("System: Sorry, I encountered an error: %v\n", err)
			continue
		}

		// Add response to history
		history = append(history, response)

		// Print response
		fmt.Printf("System (%dms): %s\n\n", duration.Milliseconds(), response.Content)
	}

	fmt.Println("Goodbye!")
}
