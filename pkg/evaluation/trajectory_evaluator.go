// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package evaluation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
)

// TrajectoryEvaluator evaluates tool use trajectories.
type TrajectoryEvaluator struct {
	Logger *slog.Logger
}

// NewTrajectoryEvaluator creates a new TrajectoryEvaluator.
func NewTrajectoryEvaluator(logger *slog.Logger) *TrajectoryEvaluator {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &TrajectoryEvaluator{
		Logger: logger,
	}
}

// Evaluate calculates tool use accuracy across a dataset.
func (e *TrajectoryEvaluator) Evaluate(dataset EvaluationDataset, printDetails bool) (float64, error) {
	if len(dataset) == 0 {
		return 0.0, fmt.Errorf("empty evaluation dataset")
	}
	
	var totalScore float64
	var totalRows int
	var failures []map[string]interface{}
	
	for sessionIdx, session := range dataset {
		for queryIdx, query := range session {
			score, failure := e.evaluateRow(query)
			totalScore += score
			totalRows++
			
			if failure != nil && printDetails {
				failure["session_index"] = sessionIdx
				failure["query_index"] = queryIdx
				failures = append(failures, failure)
			}
		}
	}
	
	meanScore := 0.0
	if totalRows > 0 {
		meanScore = totalScore / float64(totalRows)
	}
	
	if printDetails {
		e.reportFailures(failures)
	}
	
	return meanScore, nil
}

// evaluateRow evaluates a single query row, comparing expected vs actual tool use.
func (e *TrajectoryEvaluator) evaluateRow(query Query) (float64, map[string]interface{}) {
	// Clean expected tool use by removing mock outputs
	expectedTools := removeToolOutputs(query.ExpectedTools)
	actualTools := removeToolOutputs(query.ActualTools)
	
	// Check if tools match
	if len(expectedTools) != len(actualTools) {
		return 0.0, map[string]interface{}{
			"query":          query.Text,
			"expected_tools": expectedTools,
			"actual_tools":   actualTools,
			"reason":         "different number of tools",
		}
	}
	
	// Check each tool
	for i, expectedTool := range expectedTools {
		if i >= len(actualTools) {
			return 0.0, map[string]interface{}{
				"query":          query.Text,
				"expected_tools": expectedTools,
				"actual_tools":   actualTools,
				"reason":         "missing actual tool",
			}
		}
		
		actualTool := actualTools[i]
		if !areToolsEqual(expectedTool, actualTool) {
			return 0.0, map[string]interface{}{
				"query":          query.Text,
				"expected_tool":  expectedTool,
				"actual_tool":    actualTool,
				"reason":         "tools don't match",
			}
		}
	}
	
	return 1.0, nil
}

// areToolsEqual checks if two tool uses are equivalent.
func areToolsEqual(expected, actual ToolUse) bool {
	if expected.ToolName != actual.ToolName {
		return false
	}
	
	// Compare tool inputs - we need to do a deep comparison
	return reflect.DeepEqual(expected.ToolInput, actual.ToolInput)
}

// removeToolOutputs removes tool outputs from a list of tool uses.
func removeToolOutputs(tools []ToolUse) []ToolUse {
	result := make([]ToolUse, len(tools))
	for i, tool := range tools {
		result[i] = ToolUse{
			ToolName:  tool.ToolName,
			ToolInput: tool.ToolInput,
			// Explicitly omit ToolOutput
		}
	}
	return result
}

// reportFailures prints detailed information about failures.
func (e *TrajectoryEvaluator) reportFailures(failures []map[string]interface{}) {
	if len(failures) == 0 {
		return
	}
	
	e.Logger.Info("Tool trajectory failures:", slog.Int("count", len(failures)))
	
	for i, failure := range failures {
		jsonData, err := json.MarshalIndent(failure, "", "  ")
		if err != nil {
			e.Logger.Error("Failed to marshal failure", slog.String("error", err.Error()))
			continue
		}
		
		e.Logger.Info(fmt.Sprintf("Failure %d:", i+1), slog.String("details", string(jsonData)))
	}
}