// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/types"
)

func TestGemini_Generate(t *testing.T) {
	t.Skip()

	gemini, err := model.NewGemini(t.Context(), os.Getenv(model.EnvGoogleAPIKey), "gemini-2.0-flash")
	if err != nil {
		t.Fatalf("NewGemini: %v", err)
	}

	got, err := gemini.GenerateContent(t.Context(), &types.LLMRequest{})
	if err != nil {
		t.Fatalf("unexpected error on Generate: %v", err)
	}
	t.Logf("got: %#v", got.Content.Parts[0].Text)

	if got.Content.Parts[0].Text != "hello" {
		t.Fatalf("want text 'hello', got %q", got.Content.Parts[0].Text)
	}
	if got.Partial {
		t.Fatalf("unary response should not be partial")
	}
}

func TestGemini_StreamGenerate_UnarySuccess(t *testing.T) {
	// t.Skip()

	gemini, err := model.NewGemini(t.Context(), os.Getenv(model.EnvGoogleAPIKey), "gemini-2.0-flash")
	if err != nil {
		t.Fatalf("NewGemini: %v", err)
	}

	seq := gemini.StreamGenerateContent(t.Context(), &types.LLMRequest{})
	var got []*types.LLMResponse
	for r, err := range seq {
		if err != nil {
			t.Fatalf("unexpected error on StreamGenerate: %v", err)
		}
		for _, part := range r.Content.Parts {
			t.Logf("part: %#v", part.Text)
		}
		got = append(got, r)
	}

	if len(got) == 0 {
		t.Fatalf("got %d but want at least 1 response", len(got))
	}
	if got[0].Content.Parts[0].Text == "" {
		t.Fatal("want non empty text")
	}
	if !got[0].Partial {
		t.Fatalf("response should not be partial")
	}
}

func TestGemini_StreamGenerate_StreamAggregation(t *testing.T) {
	t.Skip()

	gemini, err := model.NewGemini(t.Context(), os.Getenv(model.EnvGoogleAPIKey), "gemini-2.0-flash")
	if err != nil {
		t.Fatalf("NewGemini: %v", err)
	}

	seq := gemini.StreamGenerateContent(t.Context(), &types.LLMRequest{})
	var texts []string
	for r, err := range seq {
		if err != nil {
			t.Fatalf("unexpected error on StreamGenerate: %v", err)
		}
		if r != nil && r.Content != nil && len(r.Content.Parts) > 0 && r.Content.Parts[0].Text != "" {
			if !r.Partial { // aggregated flush
				texts = append(texts, r.Content.Parts[0].Text)
			}
		}
	}

	want := []string{"Hello"}
	if !reflect.DeepEqual(texts, want) {
		t.Fatalf("want %v, got %v", want, texts)
	}
}
