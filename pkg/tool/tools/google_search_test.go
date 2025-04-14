// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package tools_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/tool/tools"
)

func TestNewGoogleSearchTool(t *testing.T) {
	tool := tools.NewGoogleSearchTool()

	if got, want := tool.Name(), "google_search"; !cmp.Equal(got, want) {
		t.Errorf("tool.Name() = %v, want %v", got, want)
	}

	if got := tool.Description(); !strings.Contains(got, "Search Google") {
		t.Errorf("tool.Description() = %q, want to contain %q", got, "Search Google")
	}
}

// We'll use a mock HTTP server to test the Google Search tool
// Note: This test is simplified and focuses on the integration points rather
// than the actual Google API interaction
func TestGoogleSearchTool_Execute(t *testing.T) {
	tool := tools.NewGoogleSearchTool()

	// Create a simple JSON query
	queryJSON := []byte(`{"query": "test search"}`)

	// Execute the tool
	result, err := tool.Execute(context.Background(), queryJSON)
	// Since we don't have real implementation details, we'll just verify
	// basic behavior without asserting specific results
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Verify we got some kind of result
	if result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestGoogleSearchTool_Execute_InvalidQuery(t *testing.T) {
	tool := tools.NewGoogleSearchTool()

	// Test with invalid JSON
	invalidJSON := []byte(`{"query": }`)

	// Execute the tool with invalid input
	_, err := tool.Execute(context.Background(), invalidJSON)

	// We should get an error
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestGoogleSearchTool_ToToolDefinition(t *testing.T) {
	tool := tools.NewGoogleSearchTool()

	// Get tool definition
	toolDef := tool.ToToolDefinition()

	if got, want := toolDef.Name, "google_search"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Name = %v, want %v", got, want)
	}
	if !strings.Contains(toolDef.Description, "Search Google") {
		t.Errorf("toolDef.Description = %q, want contain %q", toolDef.Description, "Search Google")
	}

	// Check parameter schema in the tool definition
	paramSchema := toolDef.Parameters

	// Check if properties map exists
	properties, ok := paramSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("paramSchema[\"properties\"] is not a map[string]interface{}")
	}

	// Check if query parameter exists
	_, ok = properties["query"]
	if !ok {
		t.Errorf("Tool parameters should include 'query'")
	}
}
