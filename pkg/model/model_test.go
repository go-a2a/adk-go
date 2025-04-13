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

package model_test

import (
	"testing"

	"github.com/bytedance/sonic"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/go-a2a/adk-go/pkg/model"
)

func TestModelProvider(t *testing.T) {
	// Test that model provider constants are defined
	if got, want := model.ModelProviderGoogle, model.ModelProvider("google"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelProviderGoogle = %v, want %v", got, want)
	}
	if got, want := model.ModelProviderOpenAI, model.ModelProvider("openai"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelProviderOpenAI = %v, want %v", got, want)
	}
	if got, want := model.ModelProviderAnthropic, model.ModelProvider("anthropic"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelProviderAnthropic = %v, want %v", got, want)
	}
	if got, want := model.ModelProviderMock, model.ModelProvider("mock"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelProviderMock = %v, want %v", got, want)
	}
}

func TestModelCapability(t *testing.T) {
	// Test that model capability constants are defined
	if got, want := model.ModelCapabilityToolCalling, model.ModelCapability("tool_calling"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelCapabilityToolCalling = %v, want %v", got, want)
	}
	if got, want := model.ModelCapabilityVision, model.ModelCapability("vision"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelCapabilityVision = %v, want %v", got, want)
	}
	if got, want := model.ModelCapabilityJSON, model.ModelCapability("json"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelCapabilityJSON = %v, want %v", got, want)
	}
	if got, want := model.ModelCapabilityStreaming, model.ModelCapability("streaming"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelCapabilityStreaming = %v, want %v", got, want)
	}
	if got, want := model.ModelCapabilityFunctionCalling, model.ModelCapability("function_calling"); !cmp.Equal(got, want) {
		t.Errorf("model.ModelCapabilityFunctionCalling = %v, want %v", got, want)
	}
}

func TestDefaultGenerateOptions(t *testing.T) {
	options := model.DefaultGenerateOptions()

	if got, want := options.Temperature, 0.7; !cmp.Equal(got, want) {
		t.Errorf("options.Temperature = %v, want %v", got, want)
	}
	if got, want := options.TopP, 1.0; !cmp.Equal(got, want) {
		t.Errorf("options.TopP = %v, want %v", got, want)
	}
	if got, want := options.MaxTokens, 2048; !cmp.Equal(got, want) {
		t.Errorf("options.MaxTokens = %v, want %v", got, want)
	}
	if options.Stream {
		t.Errorf("Expected options.Stream to be false")
	}
}

func TestToolDefinitionFromJSON(t *testing.T) {
	jsonData := []byte(`{
		"name": "search",
		"description": "Search the web",
		"parameters": {
			"type": "object",
			"properties": {
				"query": {
					"type": "string",
					"description": "The search query"
				}
			},
			"required": ["query"]
		}
	}`)

	toolDef, err := model.ToolDefinitionFromJSON(jsonData)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if got, want := toolDef.Name, "search"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Name = %v, want %v", got, want)
	}
	if got, want := toolDef.Description, "Search the web"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Description = %v, want %v", got, want)
	}

	paramSchema := toolDef.Parameters
	// Use sonic to convert to JSON and back for comparison of nested maps
	paramJSON, err := sonic.Marshal(paramSchema)
	require.NoError(t, err)

	var expectedParams model.ToolParameterSpec
	err = sonic.Unmarshal([]byte(`{
		"type": "object",
		"properties": {
			"query": {
				"type": "string",
				"description": "The search query"
			}
		},
		"required": ["query"]
	}`), &expectedParams)
	require.NoError(t, err)

	expectedJSON, err := sonic.Marshal(expectedParams)
	require.NoError(t, err)

	assert.JSONEq(t, string(expectedJSON), string(paramJSON))
}

func TestToolDefinition_ToJSON(t *testing.T) {
	toolDef := model.ToolDefinition{
		Name:        "calculator",
		Description: "Perform calculations",
		Parameters: model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"expression": map[string]any{
					"type":        "string",
					"description": "The mathematical expression to evaluate",
				},
			},
			"required": []string{"expression"},
		},
	}

	jsonData, err := toolDef.ToJSON()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Parse JSON back into tool definition
	parsedDef, err := model.ToolDefinitionFromJSON(jsonData)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if got, want := parsedDef.Name, toolDef.Name; !cmp.Equal(got, want) {
		t.Errorf("parsedDef.Name = %v, want %v", got, want)
	}
	if got, want := parsedDef.Description, toolDef.Description; !cmp.Equal(got, want) {
		t.Errorf("parsedDef.Description = %v, want %v", got, want)
	}

	// Compare parameters (need to convert to JSON for deep comparison of maps)
	toolDefParamsJSON, err := sonic.Marshal(toolDef.Parameters)
	require.NoError(t, err)

	parsedDefParamsJSON, err := sonic.Marshal(parsedDef.Parameters)
	require.NoError(t, err)

	assert.JSONEq(t, string(toolDefParamsJSON), string(parsedDefParamsJSON))
}
