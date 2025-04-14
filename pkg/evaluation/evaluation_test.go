// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package evaluation

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// mockAgent implements AgentRunner for testing
type mockAgent struct {
	responses map[string]string
	toolUses  map[string][]ToolUse
	callback  ToolCallback
}

func newMockAgent() *mockAgent {
	return &mockAgent{
		responses: map[string]string{
			"Hello":            "Hi there!",
			"What time is it?": "It's 3:00 PM.",
		},
		toolUses: map[string][]ToolUse{
			"What time is it?": {
				{
					ToolName: "get_time",
					ToolInput: map[string]any{
						"timezone": "UTC",
					},
				},
			},
		},
	}
}

func (m *mockAgent) Run(ctx context.Context, query string) (string, []ToolUse, error) {
	response, ok := m.responses[query]
	if !ok {
		response = "I don't know how to respond to that."
	}

	toolUses, ok := m.toolUses[query]
	if !ok {
		toolUses = []ToolUse{}
	}

	// Apply callback to tool uses if set
	if m.callback != nil {
		for i, tool := range toolUses {
			if output, handled := m.callback(tool.ToolName, tool.ToolInput); handled {
				toolUses[i].ToolOutput = output
			}
		}
	}

	return response, toolUses, nil
}

func (m *mockAgent) SetBeforeToolCallback(callback ToolCallback) {
	m.callback = callback
}

func TestTrajectoryEvaluator_Evaluate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	evaluator := NewTrajectoryEvaluator(logger)

	dataset := EvaluationDataset{
		Session{
			Query{
				Text: "What time is it?",
				ExpectedTools: []ToolUse{
					{
						ToolName: "get_time",
						ToolInput: map[string]any{
							"timezone": "UTC",
						},
					},
				},
				ActualTools: []ToolUse{
					{
						ToolName: "get_time",
						ToolInput: map[string]any{
							"timezone": "UTC",
						},
					},
				},
			},
		},
	}

	score, err := evaluator.Evaluate(dataset, false)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	expected := 1.0
	if !cmp.Equal(score, expected) {
		t.Errorf("Evaluate() got = %v, want %v", score, expected)
	}
}

func TestResponseEvaluator_EvaluateCoherence(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	client := NewSimpleEvaluationClient(logger)

	tests := []struct {
		name     string
		query    string
		response string
		want     float64
	}{
		{
			name:     "Empty response",
			query:    "Hello",
			response: "",
			want:     0.0,
		},
		{
			name:     "Good response",
			query:    "What is the capital of France?",
			response: "The capital of France is Paris. It's known for the Eiffel Tower.",
			want:     4.5, // Approximate - coherence scoring is complex
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.EvaluateCoherence(tt.query, tt.response)
			if err != nil {
				t.Fatalf("EvaluateCoherence() error = %v", err)
			}

			// Use approximate comparison for coherence scores
			if got == 0 && tt.want != 0 || got > 0 && (got < tt.want*0.5 || got > tt.want*1.5) {
				t.Errorf("EvaluateCoherence() got = %v, want approximately %v", got, tt.want)
			}
		})
	}
}

func TestEvaluationGenerator_GenerateResponses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	generator := NewEvaluationGenerator(logger)
	agent := newMockAgent()

	dataset := EvaluationDataset{
		Session{
			Query{
				Text:          "Hello",
				ExpectedTools: []ToolUse{},
			},
			Query{
				Text: "What time is it?",
				ExpectedTools: []ToolUse{
					{
						ToolName: "get_time",
						ToolInput: map[string]any{
							"timezone": "UTC",
						},
					},
				},
			},
		},
	}

	resultDataset, err := generator.GenerateResponses(context.Background(), dataset, agent, 1)
	if err != nil {
		t.Fatalf("GenerateResponses() error = %v", err)
	}

	// Verify responses were generated
	if len(resultDataset) != len(dataset) {
		t.Errorf("GenerateResponses() dataset length = %v, want %v", len(resultDataset), len(dataset))
	}

	if len(resultDataset[0]) != len(dataset[0]) {
		t.Errorf("GenerateResponses() session length = %v, want %v", len(resultDataset[0]), len(dataset[0]))
	}

	// Check specific responses
	if resultDataset[0][0].Response != "Hi there!" {
		t.Errorf("GenerateResponses() first response = %v, want %v", resultDataset[0][0].Response, "Hi there!")
	}

	if resultDataset[0][1].Response != "It's 3:00 PM." {
		t.Errorf("GenerateResponses() second response = %v, want %v", resultDataset[0][1].Response, "It's 3:00 PM.")
	}

	// Check tool uses
	if len(resultDataset[0][1].ActualTools) != 1 || resultDataset[0][1].ActualTools[0].ToolName != "get_time" {
		t.Errorf("GenerateResponses() tool use incorrect")
	}
}
