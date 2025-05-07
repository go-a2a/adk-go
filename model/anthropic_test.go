// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model_test

import (
	"reflect"
	"testing"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/types"
)

func TestClaude_Generate(t *testing.T) {
	t.Skip()

	claude, err := model.NewClaude(t.Context(), anthropic.ModelClaude3_7SonnetLatest, model.ClaudeModeAnthropic)
	if err != nil {
		t.Fatalf("NewClaude: %v", err)
	}

	req := &types.LLMRequest{
		Contents: []*genai.Content{
			{
				Role: model.RoleUser,
				Parts: []*genai.Part{
					genai.NewPartFromText(`Handle the requests as specified in the System Instruction.`),
				},
			},
		},
	}
	got, err := claude.GenerateContent(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error on Generate: %v", err)
	}
	t.Logf("got: %#v", got.Content.Parts[0].Text)

	if got.Partial {
		t.Fatalf("unary response should not be partial")
	}
}

func TestClaude_StreamGenerate_UnarySuccess(t *testing.T) {
	t.Skip()

	claude, err := model.NewClaude(t.Context(), anthropic.ModelClaude3_7SonnetLatest, model.ClaudeModeAnthropic)
	if err != nil {
		t.Fatalf("NewClaude: %v", err)
	}

	req := &types.LLMRequest{
		Contents: []*genai.Content{
			{
				Role: model.RoleUser,
				Parts: []*genai.Part{
					genai.NewPartFromText(`Handle the requests as specified in the System Instruction.`),
				},
			},
		},
	}
	seq := claude.StreamGenerateContent(t.Context(), req)
	var got []*types.LLMResponse
	for r, err := range seq {
		if err != nil {
			t.Fatalf("unexpected error on StreamGenerate: %v", err)
		}
		t.Logf("r.Content: %#v", r.Content.Parts[0])
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

func TestClaude_StreamGenerate_StreamAggregation(t *testing.T) {
	t.Skip()

	claude, err := model.NewClaude(t.Context(), anthropic.ModelClaude3_7SonnetLatest, model.ClaudeModeAnthropic)
	if err != nil {
		t.Fatalf("NewClaude: %v", err)
	}

	req := &types.LLMRequest{
		Contents: []*genai.Content{
			{
				Role: model.RoleUser,
				Parts: []*genai.Part{
					genai.NewPartFromText(`Handle the requests as specified in the System Instruction.`),
				},
			},
		},
	}
	seq := claude.StreamGenerateContent(t.Context(), req)
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
	t.Logf("texts: %#v", texts)

	want := []string{"Hello"}
	if !reflect.DeepEqual(texts, want) {
		t.Fatalf("want %v, got %v", want, texts)
	}
}
