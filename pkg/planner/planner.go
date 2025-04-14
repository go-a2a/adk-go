// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package planner provides planning capabilities for AI agents.
// It defines interfaces and implementations for different planning strategies
// that can guide agent actions and improve response quality.
package planner

import (
	"github.com/go-a2a/adk-go/pkg/message"
)

// Context represents a read-only context for planning operations.
type Context struct {
	// Messages contains the conversation history.
	Messages []message.Message

	// Query is the current user query being processed.
	Query string

	// UserID identifies the current user.
	UserID string

	// SessionID identifies the current session.
	SessionID string
}

// CallbackContext represents a context for callback operations.
type CallbackContext struct {
	*Context

	// PlannerState contains state information for the planner.
	PlannerState map[string]any
}

// NewContext creates a new planning context.
func NewContext(messages []message.Message, query, userID, sessionID string) *Context {
	return &Context{
		Messages:  messages,
		Query:     query,
		UserID:    userID,
		SessionID: sessionID,
	}
}

// NewCallbackContext creates a new callback context.
func NewCallbackContext(ctx *Context) *CallbackContext {
	return &CallbackContext{
		Context:      ctx,
		PlannerState: make(map[string]any),
	}
}

// LlmRequest represents a request to a language model.
type LlmRequest struct {
	// SystemPrompt contains system instructions for the model.
	SystemPrompt string

	// Messages contains conversation messages for the model.
	Messages []message.Message

	// Thinking contains optional thinking configuration.
	Thinking *ThinkingConfig

	// Temperature controls randomness in model output (0.0-1.0).
	Temperature float64

	// MaxTokens controls maximum length of generated output.
	MaxTokens int
}

// ThinkingConfig represents configuration for model thinking capabilities.
type ThinkingConfig struct {
	// Enabled indicates if thinking should be active.
	Enabled bool `json:"enabled"`

	// Visible controls if thinking is visible in the final output.
	Visible bool `json:"visible"`
}

// Planner defines the interface for planning strategies.
type Planner interface {
	// BuildPlanningInstruction generates a system instruction for planning.
	// This instruction will be appended to the LLM request.
	BuildPlanningInstruction(ctx *Context, request *LlmRequest) (string, error)

	// ProcessPlanningResponse processes the LLM response for planning.
	// It can modify, filter, or structure the response parts.
	ProcessPlanningResponse(ctx *CallbackContext, responseParts []message.Message) ([]message.Message, error)
}
