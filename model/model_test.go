// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"testing"

	"github.com/bytedance/sonic"
	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/model"
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
		t.Errorf("expected options.Stream to be false")
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
		t.Errorf("unexpected error: %v", err)
	}

	if got, want := toolDef.Name, "search"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Name = %v, want %v", got, want)
	}
	if got, want := toolDef.Description, "Search the web"; !cmp.Equal(got, want) {
		t.Errorf("toolDef.Description = %v, want %v", got, want)
	}

	paramSchema := toolDef.Parameters
	// Use sonic to convert to JSON and back for comparison of nested maps
	paramJSON, err := sonic.ConfigFastest.Marshal(paramSchema)
	if err != nil {
		t.Fatalf("Failed to marshal parameters: %v", err)
	}

	var expectedParams model.ToolParameterSpec
	err = sonic.ConfigFastest.Unmarshal([]byte(`{
		"type": "object",
		"properties": {
			"query": {
				"type": "string",
				"description": "The search query"
			}
		},
		"required": ["query"]
	}`), &expectedParams)
	if err != nil {
		t.Fatalf("Failed to unmarshal expected parameters: %v", err)
	}

	expectedJSON, err := sonic.ConfigFastest.Marshal(expectedParams)
	if err != nil {
		t.Fatalf("Failed to marshal expected parameters: %v", err)
	}

	// Compare JSON representations
	var gotMap, expectedMap map[string]any
	if err := sonic.ConfigFastest.Unmarshal(paramJSON, &gotMap); err != nil {
		t.Fatalf("Failed to unmarshal paramJSON: %v", err)
	}
	if err := sonic.ConfigFastest.Unmarshal(expectedJSON, &expectedMap); err != nil {
		t.Fatalf("Failed to unmarshal expectedJSON: %v", err)
	}

	if diff := cmp.Diff(expectedMap, gotMap); diff != "" {
		t.Errorf("parameter maps mismatch (-want +got):\n%s", diff)
	}
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
		t.Errorf("unexpected error: %v", err)
	}

	// Parse JSON back into tool definition
	parsedDef, err := model.ToolDefinitionFromJSON(jsonData)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if got, want := parsedDef.Name, toolDef.Name; !cmp.Equal(got, want) {
		t.Errorf("parsedDef.Name = %v, want %v", got, want)
	}
	if got, want := parsedDef.Description, toolDef.Description; !cmp.Equal(got, want) {
		t.Errorf("parsedDef.Description = %v, want %v", got, want)
	}

	// Compare parameters (need to convert to JSON for deep comparison of maps)
	toolDefParamsJSON, err := sonic.ConfigFastest.Marshal(toolDef.Parameters)
	if err != nil {
		t.Fatalf("Failed to marshal toolDef parameters: %v", err)
	}

	parsedDefParamsJSON, err := sonic.ConfigFastest.Marshal(parsedDef.Parameters)
	if err != nil {
		t.Fatalf("Failed to marshal parsedDef parameters: %v", err)
	}

	// Compare JSON representations
	var origMap, parsedMap map[string]any
	if err := sonic.ConfigFastest.Unmarshal(toolDefParamsJSON, &origMap); err != nil {
		t.Fatalf("Failed to unmarshal toolDefParamsJSON: %v", err)
	}
	if err := sonic.ConfigFastest.Unmarshal(parsedDefParamsJSON, &parsedMap); err != nil {
		t.Fatalf("Failed to unmarshal parsedDefParamsJSON: %v", err)
	}

	if diff := cmp.Diff(origMap, parsedMap); diff != "" {
		t.Errorf("parameter maps mismatch (-want +got):\n%s", diff)
	}
}
