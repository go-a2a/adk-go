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
	"github.com/go-a2a/adk-go/pkg/models"
	"github.com/go-a2a/adk-go/pkg/runner"
	"github.com/go-a2a/adk-go/pkg/tool"
	"github.com/go-a2a/adk-go/pkg/tools"
)

func main() {
	// Create a new Gemini model
	// In a real application, you would get these values from environment variables or a config file
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

	// Create an agent with the model and tools
	searchAssistant := agent.NewAgent(
		"search_assistant",
		model,
		"You are a helpful assistant. Answer user questions using Google Search when needed.",
		"An assistant that can search the web.",
		[]tool.Tool{googleSearch, loadWebPage},
	)

	// Create a runner for the agent
	agentRunner := runner.NewRunner(searchAssistant)

	// Get user input, or use a default if none provided
	userInput := "Tell me about Go programming language"
	if len(os.Args) > 1 {
		userInput = os.Args[1]
	}

	// Run the agent with the user input
	response, err := agentRunner.Run(context.Background(), userInput)
	if err != nil {
		log.Fatalf("Error running agent: %v", err)
	}

	// Print the response
	fmt.Printf("Assistant: %s\n", response.Content)
}
