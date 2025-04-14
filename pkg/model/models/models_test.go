// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package models_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/model/models"
)

func TestRegistry(t *testing.T) {
	registry := models.NewRegistry()

	// Test registration
	err := registry.Register("test-model", func(modelID string) (model.Model, error) {
		return models.NewMockModel(modelID), nil
	})
	if err != nil {
		t.Fatalf("Failed to register model: %v", err)
	}

	// Test model resolution
	factory, err := registry.Resolve("test-model")
	if err != nil {
		t.Fatalf("Failed to resolve model: %v", err)
	}

	m, err := factory("test-model")
	if err != nil {
		t.Fatalf("Failed to create model: %v", err)
	}

	if got, want := m.ModelID(), "test-model"; got != want {
		t.Errorf("m.ModelID() = %q, want %q", got, want)
	}

	// Test model caching
	m1, err := registry.GetModel("test-model")
	if err != nil {
		t.Fatalf("Failed to get model: %v", err)
	}

	m2, err := registry.GetModel("test-model")
	if err != nil {
		t.Fatalf("Failed to get model: %v", err)
	}

	// Verify both instances are from cache
	if m1 != m2 {
		t.Errorf("m1 != m2, expected the same instance from cache")
	}

	// Test model not found
	_, err = registry.Resolve("unknown-model")
	if err == nil {
		t.Error("Expected error for unknown model, got nil")
	}
}

func TestMockModel(t *testing.T) {
	mockModel := models.NewMockModel("mock-test")

	// Test Generate
	ctx := context.Background()
	messages := []message.Message{
		message.NewUserMessage("Hello"),
	}

	resp, err := mockModel.Generate(ctx, messages)
	if err != nil {
		t.Fatalf("mockModel.Generate failed: %v", err)
	}

	if got, want := resp.Role, message.RoleAssistant; got != want {
		t.Errorf("resp.Role = %v, want %v", got, want)
	}

	// Test with predefined response
	mockModel.SetResponse("Hello", "Custom response")
	resp, err = mockModel.Generate(ctx, messages)
	if err != nil {
		t.Fatalf("mockModel.Generate failed: %v", err)
	}

	if got, want := resp.Content, "Custom response"; got != want {
		t.Errorf("resp.Content = %q, want %q", got, want)
	}

	// Test error case
	testErr := errors.New("test error")
	mockModel.SetError(testErr)
	_, err = mockModel.Generate(ctx, messages)
	if err != testErr {
		t.Errorf("expected error %v, got %v", testErr, err)
	}
}

func TestNewModelFromID(t *testing.T) {
	// Test creating models from IDs
	testCases := []struct {
		name     string
		modelID  string
		provider model.ModelProvider
	}{
		{"Gemini", "gemini-1.5-flash", model.ModelProviderGoogle},
		{"Claude", "claude-3-opus", model.ModelProviderAnthropic},
		{"GPT", "gpt-4", model.ModelProviderOpenAI},
		{"Mock", "mock-model", model.ModelProviderMock},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := models.NewModelFromID(tc.modelID)
			if err != nil {
				t.Fatalf("NewModelFromID(%q) failed: %v", tc.modelID, err)
			}

			if got, want := m.ModelID(), tc.modelID; !cmp.Equal(got, want) {
				t.Errorf("m.ModelID() = %q, want %q", got, want)
			}

			if got, want := m.Provider(), tc.provider; !cmp.Equal(got, want) {
				t.Errorf("m.Provider() = %v, want %v", got, want)
			}
		})
	}
}

func TestGetSupportedModelProviders(t *testing.T) {
	providers := models.GetSupportedModelProviders()

	expected := []model.ModelProvider{
		model.ModelProviderGoogle,
		model.ModelProviderOpenAI,
		model.ModelProviderAnthropic,
		model.ModelProviderMock,
	}

	if diff := cmp.Diff(expected, providers); diff != "" {
		t.Errorf("GetSupportedModelProviders() mismatch (-want +got):\n%s", diff)
	}
}

func TestNewModelFromProvider(t *testing.T) {
	testCases := []struct {
		name     string
		provider model.ModelProvider
	}{
		{"Google", model.ModelProviderGoogle},
		{"OpenAI", model.ModelProviderOpenAI},
		{"Anthropic", model.ModelProviderAnthropic},
		{"Mock", model.ModelProviderMock},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := models.NewModelFromProvider(tc.provider)
			if err != nil {
				t.Fatalf("NewModelFromProvider(%v) failed: %v", tc.provider, err)
			}

			if got, want := m.Provider(), tc.provider; !cmp.Equal(got, want) {
				t.Errorf("m.Provider() = %v, want %v", got, want)
			}
		})
	}
}
