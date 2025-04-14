// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package evaluation

import (
	"time"
)

// EvaluationConfig defines configuration parameters for evaluations.
type EvaluationConfig struct {
	// MinToolTrajectoryScore is the minimum required score for tool usage accuracy.
	MinToolTrajectoryScore float64 `json:"min_tool_trajectory_score"`

	// MinResponseEvaluationScore is the minimum required score for response quality.
	MinResponseEvaluationScore float64 `json:"min_response_evaluation_score"`

	// MinResponseMatchScore is the minimum required score for response match.
	MinResponseMatchScore float64 `json:"min_response_match_score"`

	// Runs is the number of evaluation runs to perform.
	Runs int `json:"runs"`
}

// DefaultEvaluationConfig returns a default configuration for evaluations.
func DefaultEvaluationConfig() EvaluationConfig {
	return EvaluationConfig{
		MinToolTrajectoryScore:     0.8,
		MinResponseEvaluationScore: 3.0, // Assuming scale of 0-5
		MinResponseMatchScore:      0.7,
		Runs:                       1,
	}
}

// ToolUse represents a tool invocation.
type ToolUse struct {
	ToolName   string         `json:"tool_name"`
	ToolInput  map[string]any `json:"tool_input"`
	ToolOutput any            `json:"tool_output,omitempty"`
}

// Query represents a test query with expected results.
type Query struct {
	Text           string    `json:"query"`
	ExpectedTools  []ToolUse `json:"expected_tool_use"`
	Reference      string    `json:"reference,omitempty"`
	Response       string    `json:"response,omitempty"`
	ActualTools    []ToolUse `json:"actual_tool_use,omitempty"`
	EvaluationTime time.Time `json:"evaluation_time,omitempty"`
}

// Session represents a sequence of queries and responses.
type Session []Query

// EvaluationDataset represents a collection of sessions for evaluation.
type EvaluationDataset []Session

// EvaluationResult contains results from an evaluation run.
type EvaluationResult struct {
	ToolTrajectoryScore     float64           `json:"tool_trajectory_score"`
	ResponseEvaluationScore float64           `json:"response_evaluation_score"`
	ResponseMatchScore      float64           `json:"response_match_score"`
	Details                 map[string]any    `json:"details,omitempty"`
	Failures                []map[string]any  `json:"failures,omitempty"`
	Config                  EvaluationConfig  `json:"config"`
	Dataset                 EvaluationDataset `json:"dataset"`
	Timestamp               time.Time         `json:"timestamp"`
}
