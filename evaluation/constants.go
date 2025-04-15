// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package evaluation

// Constants used for evaluation data fields.
const (
	// QueryField is the key for user query in evaluation data.
	QueryField = "query"

	// ExpectedToolUseField is the key for expected tool usage.
	ExpectedToolUseField = "expected_tool_use"

	// ResponseField is the key for agent response.
	ResponseField = "response"

	// ReferenceField is the key for reference (ideal) response.
	ReferenceField = "reference"

	// ToolNameField is the key for tool name.
	ToolNameField = "tool_name"

	// ToolInputField is the key for tool input.
	ToolInputField = "tool_input"

	// MockToolOutputField is the key for mock tool output.
	MockToolOutputField = "mock_tool_output"
)

// Constants for evaluation metrics.
const (
	// ToolTrajectoryScoreKey is the metric for tool usage accuracy.
	ToolTrajectoryScoreKey = "tool_trajectory_score"

	// ResponseEvaluationScoreKey is the metric for response quality.
	ResponseEvaluationScoreKey = "response_evaluation_score"

	// ResponseMatchScoreKey is the metric for response match to reference.
	ResponseMatchScoreKey = "response_match_score"
)
