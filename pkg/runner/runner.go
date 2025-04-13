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

package runner

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/message"
)

// Runner represents a runner for processing messages with an agent.
type Runner struct {
	agent *agent.Agent
}

// NewRunner creates a new runner with the provided agent.
func NewRunner(agent *agent.Agent) *Runner {
	return &Runner{
		agent: agent,
	}
}

// Run executes the agent with the given user input.
func (r *Runner) Run(ctx context.Context, userInput string) (message.Message, error) {
	msg := message.NewUserMessage(userInput)
	return r.agent.Process(ctx, msg)
}

// RunConversation handles a full conversation with multiple turns.
func (r *Runner) RunConversation(ctx context.Context, messages []message.Message) (message.Message, error) {
	// Implementation would handle a multi-turn conversation
	// This is a placeholder for the actual implementation
	if len(messages) == 0 {
		return message.Message{}, nil
	}

	// Use the last message as the current user input
	lastMsg := messages[len(messages)-1]
	return r.agent.Process(ctx, lastMsg)
}
