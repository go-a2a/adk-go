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

package agent

import (
	"context"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/tool"
)

type ProcessFunc func(ctx context.Context, msg message.Message) (message.Message, error)

// BaseAgent represents a customizable agent that can be implemented with custom logic.
type BaseAgent struct {
	name        string
	description string
	tools       []tool.Tool
	ProcessFunc ProcessFunc
}

// NewBaseAgent creates a new BaseAgent with the provided configuration.
func NewBaseAgent(name string, description string, tools []tool.Tool, processFn ProcessFunc) *BaseAgent {
	return &BaseAgent{
		name:        name,
		description: description,
		tools:       tools,
		ProcessFunc: processFn,
	}
}

// Name returns the agent's name.
func (a *BaseAgent) Name() string {
	return a.name
}

// Description returns the agent's description.
func (a *BaseAgent) Description() string {
	return a.description
}

// Process handles a user message using the custom process function.
func (a *BaseAgent) Process(ctx context.Context, msg message.Message) (message.Message, error) {
	return a.ProcessFunc(ctx, msg)
}

// Tools returns the agent's tools.
func (a *BaseAgent) Tools() []tool.Tool {
	return a.tools
}
