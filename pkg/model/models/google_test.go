// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package models_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/model/models"
)

func TestGoogleModel(t *testing.T) {
	m, err := models.NewGoogleModel("gemini-1.5-flash", "api-key", "api-endpoint")
	if err != nil {
		t.Fatalf("NewGoogleModel failed: %v", err)
	}

	// Test model properties
	if got, want := m.ModelID(), "gemini-1.5-flash"; !cmp.Equal(got, want) {
		t.Errorf("m.ModelID() = %q, want %q", got, want)
	}

	if got, want := m.Provider(), model.ModelProviderGoogle; !cmp.Equal(got, want) {
		t.Errorf("m.Provider() = %v, want %v", got, want)
	}

	// Test capabilities
	capabilities := []model.ModelCapability{
		model.ModelCapabilityToolCalling,
		model.ModelCapabilityVision,
		model.ModelCapabilityJSON,
		model.ModelCapabilityStreaming,
		model.ModelCapabilityFunctionCalling,
	}

	for _, capability := range capabilities {
		if !m.HasCapability(capability) {
			t.Errorf("expected model to have capability %v", capability)
		}
	}

	// Test Generate
	ctx := context.Background()
	messages := []message.Message{
		message.NewUserMessage("Hello"),
	}

	resp, err := m.Generate(ctx, messages)
	if err != nil {
		t.Fatalf("m.Generate failed: %v", err)
	}

	if got, want := resp.Role, message.RoleAssistant; !cmp.Equal(got, want) {
		t.Errorf("resp.Role = %v, want %v", got, want)
	}

	// Test GenerateWithOptions
	opts := model.GenerateOptions{
		Temperature: 0.5,
		TopP:        0.9,
		MaxTokens:   100,
	}

	resp, err = m.GenerateWithOptions(ctx, messages, opts)
	if err != nil {
		t.Fatalf("m.GenerateWithOptions failed: %v", err)
	}

	if got, want := resp.Role, message.RoleAssistant; !cmp.Equal(got, want) {
		t.Errorf("resp.Role = %v, want %v", got, want)
	}

	// Test GenerateWithTools
	tools := []model.ToolDefinition{
		{
			Name:        "search",
			Description: "Search the web",
			Parameters: model.ToolParameterSpec{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The search query",
					},
				},
				"required": []string{"query"},
			},
		},
	}

	resp, err = m.GenerateWithTools(ctx, messages, tools)
	if err != nil {
		t.Fatalf("m.GenerateWithTools failed: %v", err)
	}

	if len(resp.ToolCalls) == 0 {
		t.Errorf("expected tool calls in response")
	}

	// Test GenerateStream
	var streamResponses []message.Message
	handler := func(msg message.Message) {
		streamResponses = append(streamResponses, msg)
	}

	err = m.GenerateStream(ctx, messages, handler)
	if err != nil {
		t.Fatalf("m.GenerateStream failed: %v", err)
	}

	if len(streamResponses) == 0 {
		t.Errorf("expected stream responses")
	}
}
