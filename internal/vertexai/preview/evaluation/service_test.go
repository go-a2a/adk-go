// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package evaluation

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name      string
		projectID string
		location  string
		wantErr   bool
	}{
		{
			name:      "valid parameters",
			projectID: "test-project",
			location:  "us-central1",
			wantErr:   false,
		},
		{
			name:      "empty project ID",
			projectID: "",
			location:  "us-central1",
			wantErr:   true,
		},
		{
			name:      "empty location",
			projectID: "test-project",
			location:  "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			service, err := NewService(ctx, tt.projectID, tt.location)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if service == nil {
					t.Error("NewService() returned nil service without error")
					return
				}

				if service.projectID != tt.projectID {
					t.Errorf("NewService() projectID = %v, want %v", service.projectID, tt.projectID)
				}

				if service.location != tt.location {
					t.Errorf("NewService() location = %v, want %v", service.location, tt.location)
				}

				// Clean up
				if err := service.Close(); err != nil {
					t.Errorf("Failed to close service: %v", err)
				}
			}
		})
	}
}

func TestService_validateTask(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name    string
		task    *EvalTask
		wantErr bool
	}{
		{
			name: "valid task",
			task: &EvalTask{
				Dataset: &Dataset{
					Data: []DataRecord{
						{
							Input:     "What is 2+2?",
							Response:  "4",
							Reference: "The answer is 4",
						},
					},
				},
				Metrics: []MetricConfig{
					{Type: MetricTypeBLEU},
				},
			},
			wantErr: false,
		},
		{
			name: "nil dataset",
			task: &EvalTask{
				Metrics: []MetricConfig{
					{Type: MetricTypeBLEU},
				},
			},
			wantErr: true,
		},
		{
			name: "empty dataset",
			task: &EvalTask{
				Dataset: &Dataset{
					Data: []DataRecord{},
				},
				Metrics: []MetricConfig{
					{Type: MetricTypeBLEU},
				},
			},
			wantErr: true,
		},
		{
			name: "no metrics",
			task: &EvalTask{
				Dataset: &Dataset{
					Data: []DataRecord{
						{Response: "test", Reference: "test"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "BLEU metric missing reference",
			task: &EvalTask{
				Dataset: &Dataset{
					Data: []DataRecord{
						{Response: "test"}, // Missing reference
					},
				},
				Metrics: []MetricConfig{
					{Type: MetricTypeBLEU},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateTask(tt.task)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTask() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_computeBLEUScore(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name      string
		candidate string
		reference string
		wantScore float64
	}{
		{
			name:      "identical strings",
			candidate: "hello world",
			reference: "hello world",
			wantScore: 1.0,
		},
		{
			name:      "partial overlap",
			candidate: "hello there",
			reference: "hello world",
			wantScore: 0.5, // 1 word overlap out of 2
		},
		{
			name:      "no overlap",
			candidate: "foo bar",
			reference: "hello world",
			wantScore: 0.0,
		},
		{
			name:      "empty candidate",
			candidate: "",
			reference: "hello world",
			wantScore: 0.0,
		},
		{
			name:      "empty reference",
			candidate: "hello world",
			reference: "",
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := service.computeBLEUScore(tt.candidate, tt.reference)
			if score != tt.wantScore {
				t.Errorf("computeBLEUScore() = %v, want %v", score, tt.wantScore)
			}
		})
	}
}

func TestService_computeROUGE1(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name      string
		candidate string
		reference string
		wantScore float64
	}{
		{
			name:      "identical strings",
			candidate: "hello world",
			reference: "hello world",
			wantScore: 1.0,
		},
		{
			name:      "partial overlap",
			candidate: "hello there",
			reference: "hello world",
			wantScore: 0.5, // 1 word overlap out of 2 in reference
		},
		{
			name:      "no overlap",
			candidate: "foo bar",
			reference: "hello world",
			wantScore: 0.0,
		},
		{
			name:      "repeated words",
			candidate: "hello hello",
			reference: "hello world hello",
			wantScore: 2.0 / 3.0, // 2 hello matches out of 3 reference words
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := service.computeROUGE1(tt.candidate, tt.reference)
			if score != tt.wantScore {
				t.Errorf("computeROUGE1() = %v, want %v", score, tt.wantScore)
			}
		})
	}
}

func TestService_getBigrams(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name     string
		text     string
		expected []string
	}{
		{
			name:     "normal text",
			text:     "hello world test",
			expected: []string{"hello world", "world test"},
		},
		{
			name:     "two words",
			text:     "hello world",
			expected: []string{"hello world"},
		},
		{
			name:     "one word",
			text:     "hello",
			expected: []string{},
		},
		{
			name:     "empty text",
			text:     "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.getBigrams(tt.text)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("getBigrams() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestService_longestCommonSubsequence(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name     string
		seq1     []string
		seq2     []string
		expected int
	}{
		{
			name:     "identical sequences",
			seq1:     []string{"a", "b", "c"},
			seq2:     []string{"a", "b", "c"},
			expected: 3,
		},
		{
			name:     "partial overlap",
			seq1:     []string{"a", "b", "c"},
			seq2:     []string{"a", "x", "c"},
			expected: 2,
		},
		{
			name:     "no overlap",
			seq1:     []string{"a", "b", "c"},
			seq2:     []string{"x", "y", "z"},
			expected: 0,
		},
		{
			name:     "empty sequences",
			seq1:     []string{},
			seq2:     []string{},
			expected: 0,
		},
		{
			name:     "one empty sequence",
			seq1:     []string{"a", "b"},
			seq2:     []string{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.longestCommonSubsequence(tt.seq1, tt.seq2)
			if result != tt.expected {
				t.Errorf("longestCommonSubsequence() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestService_computeToolCallScore(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name      string
		actual    []ToolCall
		expected  []ToolCall
		wantScore float64
	}{
		{
			name: "perfect match",
			actual: []ToolCall{
				{Name: "func1", Arguments: map[string]any{"arg1": "value1"}},
			},
			expected: []ToolCall{
				{Name: "func1", Arguments: map[string]any{"arg1": "value1"}},
			},
			wantScore: 1.0,
		},
		{
			name: "name mismatch",
			actual: []ToolCall{
				{Name: "func2", Arguments: map[string]any{"arg1": "value1"}},
			},
			expected: []ToolCall{
				{Name: "func1", Arguments: map[string]any{"arg1": "value1"}},
			},
			wantScore: 0.0,
		},
		{
			name: "argument mismatch",
			actual: []ToolCall{
				{Name: "func1", Arguments: map[string]any{"arg1": "value2"}},
			},
			expected: []ToolCall{
				{Name: "func1", Arguments: map[string]any{"arg1": "value1"}},
			},
			wantScore: 0.0,
		},
		{
			name:      "empty expected",
			actual:    []ToolCall{},
			expected:  []ToolCall{},
			wantScore: 1.0,
		},
		{
			name:   "no actual calls",
			actual: []ToolCall{},
			expected: []ToolCall{
				{Name: "func1", Arguments: map[string]any{"arg1": "value1"}},
			},
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := service.computeToolCallScore(tt.actual, tt.expected)
			if score != tt.wantScore {
				t.Errorf("computeToolCallScore() = %v, want %v", score, tt.wantScore)
			}
		})
	}
}

func TestService_formatPromptTemplate(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name     string
		template string
		record   DataRecord
		expected string
	}{
		{
			name:     "basic replacement",
			template: "Input: {{.Input}}, Response: {{.Response}}",
			record: DataRecord{
				Input:    "What is 2+2?",
				Response: "4",
			},
			expected: "Input: What is 2+2?, Response: 4",
		},
		{
			name:     "all fields",
			template: "{{.Input}} {{.Response}} {{.Reference}} {{.Context}} {{.ImageURL}}",
			record: DataRecord{
				Input:     "input",
				Response:  "response",
				Reference: "reference",
				Context:   "context",
				ImageURL:  "http://example.com/image.jpg",
			},
			expected: "input response reference context http://example.com/image.jpg",
		},
		{
			name:     "missing fields",
			template: "{{.Input}} {{.Response}}",
			record: DataRecord{
				Response: "response",
			},
			expected: " response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.formatPromptTemplate(tt.template, tt.record)
			if result != tt.expected {
				t.Errorf("formatPromptTemplate() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestService_calculateOverallScore(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name     string
		task     *EvalTask
		results  []MetricResult
		expected float64
	}{
		{
			name: "equal weights",
			task: &EvalTask{
				Metrics: []MetricConfig{
					{Type: MetricTypeBLEU, Weight: 1.0},
					{Type: MetricTypeROUGE1, Weight: 1.0},
				},
			},
			results: []MetricResult{
				{Score: 0.8},
				{Score: 0.6},
			},
			expected: 0.7,
		},
		{
			name: "different weights",
			task: &EvalTask{
				Metrics: []MetricConfig{
					{Type: MetricTypeBLEU, Weight: 2.0},
					{Type: MetricTypeROUGE1, Weight: 1.0},
				},
			},
			results: []MetricResult{
				{Score: 0.9}, // Weight 2.0
				{Score: 0.6}, // Weight 1.0
			},
			expected: 0.8, // (0.9*2 + 0.6*1) / (2+1) = 2.4/3 = 0.8
		},
		{
			name: "with errors",
			task: &EvalTask{
				Metrics: []MetricConfig{
					{Type: MetricTypeBLEU, Weight: 1.0},
					{Type: MetricTypeROUGE1, Weight: 1.0},
				},
			},
			results: []MetricResult{
				{Score: 0.8},
				{Score: 0.6, Error: "failed"},
			},
			expected: 0.8, // Only first result counted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.calculateOverallScore(tt.task, tt.results)
			if result != tt.expected {
				t.Errorf("calculateOverallScore() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestService_getTemplateForMetric(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name       string
		metricType MetricType
		wantNil    bool
	}{
		{
			name:       "coherence metric",
			metricType: MetricTypeCoherence,
			wantNil:    false,
		},
		{
			name:       "fluency metric",
			metricType: MetricTypeFluency,
			wantNil:    false,
		},
		{
			name:       "safety metric",
			metricType: MetricTypeSafety,
			wantNil:    false,
		},
		{
			name:       "unsupported metric",
			metricType: MetricTypeBLEU,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := service.getTemplateForMetric(tt.metricType)
			if (template == nil) != tt.wantNil {
				t.Errorf("getTemplateForMetric() returned nil = %v, wantNil %v", template == nil, tt.wantNil)
			}
		})
	}
}

func TestPromptTemplates(t *testing.T) {
	// Test that all pointwise templates are available
	pointwiseTemplates := []struct {
		name     string
		template *PromptTemplate
	}{
		{"SummarizationQuality", PromptTemplates.Pointwise.SummarizationQuality},
		{"Groundedness", PromptTemplates.Pointwise.Groundedness},
		{"InstructionFollowing", PromptTemplates.Pointwise.InstructionFollowing},
		{"Coherence", PromptTemplates.Pointwise.Coherence},
		{"Fluency", PromptTemplates.Pointwise.Fluency},
		{"Safety", PromptTemplates.Pointwise.Safety},
		{"Verbosity", PromptTemplates.Pointwise.Verbosity},
		{"Helpfulness", PromptTemplates.Pointwise.Helpfulness},
		{"Fulfillment", PromptTemplates.Pointwise.Fulfillment},
	}

	for _, tt := range pointwiseTemplates {
		t.Run(tt.name, func(t *testing.T) {
			if tt.template == nil {
				t.Errorf("Template %s is nil", tt.name)
				return
			}

			if tt.template.Template == "" {
				t.Errorf("Template %s has empty template string", tt.name)
			}

			if tt.template.Description == "" {
				t.Errorf("Template %s has empty description", tt.name)
			}

			if tt.template.ScoreRange == nil {
				t.Errorf("Template %s has nil score range", tt.name)
			}
		})
	}

	// Test that all pairwise templates are available
	pairwiseTemplates := []struct {
		name     string
		template *PromptTemplate
	}{
		{"PreferenceComparison", PromptTemplates.Pairwise.PreferenceComparison},
		{"QualityComparison", PromptTemplates.Pairwise.QualityComparison},
	}

	for _, tt := range pairwiseTemplates {
		t.Run(tt.name, func(t *testing.T) {
			if tt.template == nil {
				t.Errorf("Template %s is nil", tt.name)
				return
			}

			if tt.template.Template == "" {
				t.Errorf("Template %s has empty template string", tt.name)
			}
		})
	}
}

func TestGetTemplate(t *testing.T) {
	tests := []struct {
		name     string
		category string
		template string
		wantNil  bool
	}{
		{
			name:     "valid pointwise template",
			category: "pointwise",
			template: "coherence",
			wantNil:  false,
		},
		{
			name:     "valid pairwise template",
			category: "pairwise",
			template: "preference_comparison",
			wantNil:  false,
		},
		{
			name:     "invalid category",
			category: "invalid",
			template: "coherence",
			wantNil:  true,
		},
		{
			name:     "invalid template name",
			category: "pointwise",
			template: "invalid",
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := GetTemplate(tt.category, tt.template)
			if (template == nil) != tt.wantNil {
				t.Errorf("GetTemplate() returned nil = %v, wantNil %v", template == nil, tt.wantNil)
			}
		})
	}
}

func TestListTemplates(t *testing.T) {
	templates := ListTemplates()

	// Check that we have both categories
	if _, exists := templates["pointwise"]; !exists {
		t.Error("ListTemplates() missing pointwise category")
	}

	if _, exists := templates["pairwise"]; !exists {
		t.Error("ListTemplates() missing pairwise category")
	}

	// Check that pointwise has expected templates
	pointwise := templates["pointwise"]
	expectedPointwise := []string{
		"summarization_quality",
		"groundedness",
		"instruction_following",
		"coherence",
		"fluency",
		"safety",
		"verbosity",
		"helpfulness",
		"fulfillment",
		"image_description_quality",
		"multimodal_coherence",
	}

	if diff := cmp.Diff(expectedPointwise, pointwise); diff != "" {
		t.Errorf("ListTemplates() pointwise mismatch (-want +got):\n%s", diff)
	}

	// Check that pairwise has expected templates
	pairwise := templates["pairwise"]
	expectedPairwise := []string{
		"preference_comparison",
		"quality_comparison",
	}

	if diff := cmp.Diff(expectedPairwise, pairwise); diff != "" {
		t.Errorf("ListTemplates() pairwise mismatch (-want +got):\n%s", diff)
	}
}

// Benchmark tests for performance
func BenchmarkComputeBLEUScore(b *testing.B) {
	service := &Service{}
	candidate := "the quick brown fox jumps over the lazy dog"
	reference := "a quick brown fox jumps over a lazy dog"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.computeBLEUScore(candidate, reference)
	}
}

func BenchmarkComputeROUGE1(b *testing.B) {
	service := &Service{}
	candidate := "the quick brown fox jumps over the lazy dog"
	reference := "a quick brown fox jumps over a lazy dog"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.computeROUGE1(candidate, reference)
	}
}

func BenchmarkLongestCommonSubsequence(b *testing.B) {
	service := &Service{}
	seq1 := []string{"the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"}
	seq2 := []string{"a", "quick", "brown", "fox", "jumps", "over", "a", "lazy", "dog"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.longestCommonSubsequence(seq1, seq2)
	}
}

// Integration test that would require actual API keys (skipped by default)
func TestService_EvaluateIntegration(t *testing.T) {
	t.Skip("Integration test requires API keys - enable manually for testing")

	ctx := context.Background()
	service, err := NewService(ctx, "your-project-id", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create a simple evaluation task
	task := &EvalTask{
		Name: "integration_test",
		Dataset: &Dataset{
			Data: []DataRecord{
				{
					Input:     "What is the capital of France?",
					Response:  "Paris",
					Reference: "Paris is the capital of France.",
				},
			},
		},
		Metrics: []MetricConfig{
			{Type: MetricTypeBLEU},
			{Type: MetricTypeROUGE1},
			{Type: MetricTypeExactMatch},
		},
	}

	result, err := service.Evaluate(ctx, task, "test_run")
	if err != nil {
		t.Fatalf("Failed to evaluate: %v", err)
	}

	if result.TaskName != task.Name {
		t.Errorf("Expected task name %s, got %s", task.Name, result.TaskName)
	}

	if len(result.MetricResults) != 3 {
		t.Errorf("Expected 3 metric results, got %d", len(result.MetricResults))
	}

	t.Logf("Evaluation results: Overall score = %.3f, Duration = %v",
		result.OverallScore, result.Duration)
}
