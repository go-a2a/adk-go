// Copyright 2025 The ADK Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package runner provides facilities for managing agent execution within sessions.
//
// The package includes:
//
// * Runner: Manages agent execution with support for sessions, artifacts, and memory.
//
// * InvocationContext: Contains contextual information for a single agent invocation.
//
// Runner is the primary entry point for using agents in applications. It handles:
//   - Creating and managing sessions
//   - Processing messages through agents
//   - Saving artifacts from user messages
//   - Logging and tracing for observability
//
// Example:
//
//	// Create a model and agent
//	model := models.NewAnthropicModel("claude-3-sonnet-20240229", apiKey)
//	agent := agent.NewAgent("my-assistant", model, "You are a helpful assistant", "Assistant", nil)
//
//	// Create a runner with in-memory services
//	runner := runner.NewInMemoryRunner("my-app", agent)
//
//	// Process a single message
//	response, err := runner.Run(ctx, "Hello, world!")
//	if err != nil {
//	    log.Fatalf("Failed to process message: %v", err)
//	}
//	fmt.Println(response.Content)
//
//	// For multi-turn conversations, use a session
//	userID := "user123"
//	sessionID := "session456"
//	message := message.NewUserMessage("Tell me a story")
//	response, err = runner.RunWithSession(ctx, userID, sessionID, []message.Message{message})
package runner