// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package tools_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/tool/tools"
)

func TestNewLoadWebPageTool(t *testing.T) {
	tool := tools.NewLoadWebPageTool()

	if tool == nil {
		t.Fatalf("tool is nil, want non-nil")
	}
	if got, want := tool.Name(), "load_web_page"; !cmp.Equal(got, want) {
		t.Errorf("tool.Name() = %v, want %v", got, want)
	}
	if !strings.Contains(tool.Description(), "Loads content from a web page") {
		t.Errorf("tool.Description() does not contain %q", "Loads content from a web page")
	}

	// Check parameter schema
	paramSchema := tool.ParameterSchema()
	paramJSON, err := sonic.Marshal(paramSchema)
	if err != nil {
		t.Fatalf("sonic.Marshal failed: %v", err)
	}

	if !strings.Contains(string(paramJSON), "url") {
		t.Errorf("string(paramJSON) does not contain %q", "url")
	}
	if !strings.Contains(string(paramJSON), "string") {
		t.Errorf("string(paramJSON) does not contain %q", "string")
	}
}

func TestLoadWebPageTool_Execute(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is a test page for the web page tool.</p>
</body>
</html>`))
	}))
	defer server.Close()

	// Create the tool
	tool := tools.NewLoadWebPageTool()

	// Create the arguments
	args, err := sonic.Marshal(map[string]string{
		"url": server.URL,
	})
	if err != nil {
		t.Fatalf("sonic.Marshal failed: %v", err)
	}

	// Execute the tool
	result, err := tool.Execute(context.Background(), args)
	// Verify the results
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Hello, World!") {
		t.Errorf("result does not contain %q", "Hello, World!")
	}
	if !strings.Contains(result, "This is a test page for the web page tool.") {
		t.Errorf("result does not contain %q", "This is a test page for the web page tool.")
	}
}

func TestLoadWebPageTool_Execute_InvalidURL(t *testing.T) {
	tool := tools.NewLoadWebPageTool()

	// Test with invalid URL
	args, err := sonic.Marshal(map[string]string{
		"url": "not-a-valid-url",
	})
	if err != nil {
		t.Fatalf("sonic.Marshal failed: %v", err)
	}

	// Execute the tool
	_, err = tool.Execute(context.Background(), args)
	// Should return an error
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "only HTTP and HTTPS URLs are supported") {
		t.Errorf("err.Error() = %q, want contain %q", err.Error(), "only HTTP and HTTPS URLs are supported")
	}
}

func TestLoadWebPageTool_Execute_NonExistentURL(t *testing.T) {
	tool := tools.NewLoadWebPageTool()

	// Test with non-existent server
	args, err := sonic.Marshal(map[string]string{
		"url": "http://non-existent-server.invalid",
	})
	if err != nil {
		t.Fatalf("sonic.Marshal failed: %v", err)
	}

	// Execute the tool
	_, err = tool.Execute(context.Background(), args)

	// Should return an error
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}

func TestLoadWebPageTool_ToToolDefinition(t *testing.T) {
	tool := tools.NewLoadWebPageTool()

	// Get tool definition
	toolDef := tool.ToToolDefinition()

	if got, want := toolDef.Name, "load_web_page"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Name = %v, want %v", got, want)
	}
	if !strings.Contains(toolDef.Description, "Loads content from a web page") {
		t.Errorf("toolDef.Description does not contain %q", "Loads content from a web page")
	}

	// Check parameter schema in the tool definition
	paramSchema := toolDef.Parameters

	// Check if properties map exists
	properties, ok := paramSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("paramSchema[\"properties\"] is not a map[string]interface{}")
	}

	// Check if url property exists
	_, ok = properties["url"]
	if !ok {
		t.Errorf("Tool parameters should include 'url'")
	}
}
