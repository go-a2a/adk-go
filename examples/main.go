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
	shutdownTracer, err := observability.InitTracer(ctx, "adk-go-example")
	if err != nil {
		slog.Error("Failed to initialize tracer", slog.Any("error", err))
		os.Exit(1)
	}
	defer shutdownTracer(context.Background())

	// Initialize metrics
	shutdownMeter, err := observability.InitMeter(ctx, "adk-go-example")
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

	// Create tools
	googleSearch := tools.NewGoogleSearchTool()
	loadWebPage := tools.NewLoadWebPageTool()

	// Register tools with a tool registry
	toolRegistry := tool.NewToolRegistry()
	toolRegistry.Register(googleSearch)
	toolRegistry.Register(loadWebPage)

	// Create a main agent
	mainAgent := agent.NewLlmAgent(
		"main_assistant",
		model,
		"You are a helpful assistant. Answer user questions by using the available tools when needed. For web searches, use the google_search tool. To read web pages, use the load_web_page tool.",
		"A versatile assistant that can search the web and read web pages.",
		[]tool.Tool{googleSearch, loadWebPage},
	)

	// Create a runner for the agent
	agentRunner := runner.NewRunner(mainAgent)

	// Run a simple conversation
	fmt.Println("ADK-Go Example - Type 'exit' to quit")
	fmt.Println("Available tools:")
	fmt.Println("- google_search: Search Google for information")
	fmt.Println("- load_web_page: Load a web page from a URL")
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

		// Start tracing span for the user request
		requestCtx, span := observability.StartSpan(requestCtx, "user_request")

		// Process user message
		startTime := time.Now()
		response, err := agentRunner.RunConversation(requestCtx, history)
		duration := time.Since(startTime)

		// Close the span
		span.End()

		// Cancel the request context
		requestCancel()

		// Record metrics
		observability.RecordLatency(ctx, duration,
			slog.String("operation", "conversation_turn").Any(),
		)

		if err != nil {
			slog.Error("Error processing user message",
				slog.Any("error", err),
				slog.String("user_message", input),
				slog.Duration("duration", duration),
			)
			fmt.Printf("Assistant: Sorry, I encountered an error: %v\n", err)
			continue
		}

		// Add response to history
		history = append(history, response)

		// Print response
		fmt.Printf("Assistant (%dms): %s\n\n", duration.Milliseconds(), response.Content)
	}

	fmt.Println("Goodbye!")
}
