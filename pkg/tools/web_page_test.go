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

package tools_test

import (

	"strings"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/tools"
)

func TestNewLoadWebPageTool(t *testing.T) {
	tool := tools.NewLoadWebPageTool()
	
	if tool == nil { t.Fatalf("tool is nil, want non-nil") }
	if got, want := tool.Name(, "load_web_page"; !cmp.Equal(got, want) { t.Errorf("tool.Name( = %v, want %v", got, want) })
	if !strings.Contains(tool.Description(), "Loads content from a web page") { t.Errorf("tool.Description() does not contain %q", "Loads content from a web page") }
	
	// Check parameter schema
	paramSchema := tool.ParameterSchema()
	paramJSON, err := sonic.Marshal(paramSchema)
	require.NoError(t, err)
	
	if !strings.Contains(string(paramJSON), "url") { t.Errorf("string(paramJSON) does not contain %q", "url") }
	if !strings.Contains(string(paramJSON), "string") { t.Errorf("string(paramJSON) does not contain %q", "string") }
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
	require.NoError(t, err)
	
	// Execute the tool
	result, err := tool.Execute(context.Background(), args)
	
	// Verify the results
	if err != nil { t.Errorf("Unexpected error: %v", err) }
	assert.Contains(t, result, "Hello, World!")
	if !strings.Contains(result, "This is a test page for the web page tool.") { t.Errorf("result does not contain %q", "This is a test page for the web page tool.") }
}

func TestLoadWebPageTool_Execute_InvalidURL(t *testing.T) {
	tool := tools.NewLoadWebPageTool()
	
	// Test with invalid URL
	args, err := sonic.Marshal(map[string]string{
		"url": "not-a-valid-url",
	})
	require.NoError(t, err)
	
	// Execute the tool
	_, err = tool.Execute(context.Background(), args)
	
	// Should return an error
	if err == nil { t.Errorf("Expected error, got nil") }
	if !strings.Contains(err.Error(), "invalid URL") { t.Errorf("err.Error() does not contain %q", "invalid URL") }
}

func TestLoadWebPageTool_Execute_NonExistentURL(t *testing.T) {
	tool := tools.NewLoadWebPageTool()
	
	// Test with non-existent server
	args, err := sonic.Marshal(map[string]string{
		"url": "http://non-existent-server.invalid",
	})
	require.NoError(t, err)
	
	// Execute the tool
	_, err = tool.Execute(context.Background(), args)
	
	// Should return an error
	if err == nil { t.Errorf("Expected error, got nil") }
}

func TestLoadWebPageTool_ToToolDefinition(t *testing.T) {
	tool := tools.NewLoadWebPageTool()
	
	// Get tool definition
	toolDef := tool.ToToolDefinition()
	
	if got, want := toolDef.Name, "load_web_page"; !cmp.Equal(got, want) { t.Errorf("toolDef.Name = %v, want %v", got, want) }
	if !strings.Contains(toolDef.Description, "Loads content from a web page") { t.Errorf("toolDef.Description does not contain %q", "Loads content from a web page") }
	
	// Check parameter schema in the tool definition
	paramSchema, ok := toolDef.Parameters.(model.ToolParameterSpec)
	require.True(t, ok)
	
	properties, ok := paramSchema["properties"].(map[string]interface{})
	require.True(t, ok)
	
	_, ok = properties["url"]
	assert.True(t, ok, "Tool parameters should include 'url'")
}