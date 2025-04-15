// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"github.com/go-a2a/adk-go/message"
)

// BuiltInPlanner is a basic planner that uses the model's built-in thinking features.
// It provides a framework for configuring model thinking capabilities.
type BuiltInPlanner struct {
	// thinkingConfig controls the model's thinking behavior.
	thinkingConfig *ThinkingConfig
}

// NewBuiltInPlanner creates a new built-in planner with the specified thinking configuration.
func NewBuiltInPlanner(thinkingConfig *ThinkingConfig) *BuiltInPlanner {
	if thinkingConfig == nil {
		thinkingConfig = &ThinkingConfig{
			Enabled: false,
			Visible: false,
		}
	}

	return &BuiltInPlanner{
		thinkingConfig: thinkingConfig,
	}
}

// BuildPlanningInstruction implements the Planner interface.
// For the built-in planner, this returns an empty string as it relies
// on the model's native capabilities rather than explicit instructions.
func (p *BuiltInPlanner) BuildPlanningInstruction(ctx *Context, request *LlmRequest) (string, error) {
	// Apply thinking configuration to the request
	if p.thinkingConfig != nil {
		request.Thinking = p.thinkingConfig
	}

	return "", nil
}

// ProcessPlanningResponse implements the Planner interface.
// For the built-in planner, this passes through the response unchanged
// as the model's native thinking capabilities are assumed to be sufficient.
func (p *BuiltInPlanner) ProcessPlanningResponse(ctx *CallbackContext, responseParts []message.Message) ([]message.Message, error) {
	return responseParts, nil
}

// ApplyThinkingConfig applies thinking configuration to an LLM request.
func (p *BuiltInPlanner) ApplyThinkingConfig(request *LlmRequest) {
	if p.thinkingConfig != nil {
		request.Thinking = p.thinkingConfig
	}
}

// GetThinkingConfig returns the current thinking configuration.
func (p *BuiltInPlanner) GetThinkingConfig() *ThinkingConfig {
	return p.thinkingConfig
}

// WithThinkingConfig updates the thinking configuration.
func (p *BuiltInPlanner) WithThinkingConfig(config *ThinkingConfig) *BuiltInPlanner {
	p.thinkingConfig = config
	return p
}
