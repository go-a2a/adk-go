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
	"log"
	"os"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/models"
	"github.com/go-a2a/adk-go/pkg/runner"
	"github.com/go-a2a/adk-go/pkg/tool"
	"github.com/go-a2a/adk-go/pkg/tools"
)

func main() {
	// Create a Gemini model for the agents
	model := models.NewGeminiModel(
		"gemini-2.0-flash",        // modelID
		"YOUR_API_KEY",            // apiKey (in a real app, get this from environment)
		"https://api.example.com", // endpoint
		0.7,                       // temperature
		8192,                      // maxTokens
	)

	// Create tools
	googleSearch := tools.NewGoogleSearchTool()
	loadWebPage := tools.NewLoadWebPageTool()

	// Create a greeter agent
	greeter := agent.NewLlmAgent(
		"Greeter",
		model,
		"You are a friendly greeter. Your job is to welcome users and make them feel comfortable.",
		"A friendly agent that welcomes users.",
		nil, // No tools needed for the greeter
	)

	// Create a task executor agent
	taskExecutor := agent.NewBaseAgent(
		"TaskExecutor",
		"An agent that executes specific tasks.",
		[]tool.Tool{googleSearch, loadWebPage},
		func(ctx context.Context, msg message.Message) (message.Message, error) {
			// This is a very simple implementation that just returns a fixed response
			// In a real implementation, this would use the tools to execute tasks
			return message.NewAssistantMessage(fmt.Sprintf("Task executor processed: %s", msg.Content)), nil
		},
	)

	// Create a coordinator agent that manages the other agents
	coordinator := agent.NewLlmAgent(
		"Coordinator",
		model,
		"You are a coordinator that decides which agent should handle a user request. For greetings, use the Greeter. For specific tasks, use the TaskExecutor.",
		"I coordinate greetings and tasks.",
		nil, // No tools needed for the coordinator
	)

	// Add sub-agents to the coordinator
	coordinator.WithSubAgents(greeter, taskExecutor)

	// Create a runner for the coordinator agent
	agentRunner := runner.NewRunner(coordinator)

	// Get user input, or use a default if none provided
	userInput := "Hello, I need help with a task."
	if len(os.Args) > 1 {
		userInput = os.Args[1]
	}

	// Run the coordinator with the user input
	response, err := agentRunner.Run(context.Background(), userInput)
	if err != nil {
		log.Fatalf("Error running coordinator: %v", err)
	}

	// Print the response
	fmt.Printf("Coordinator: %s\n", response.Content)
}
