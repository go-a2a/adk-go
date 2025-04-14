// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package evaluation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AgentEvaluator evaluates agent performance.
type AgentEvaluator struct {
	Logger             *slog.Logger
	EvaluationGenerator *EvaluationGenerator
	ResponseEvaluator   *ResponseEvaluator
	TrajectoryEvaluator *TrajectoryEvaluator
}

// NewAgentEvaluator creates a new AgentEvaluator.
func NewAgentEvaluator(
	logger *slog.Logger,
	evalGenerator *EvaluationGenerator,
	respEvaluator *ResponseEvaluator,
	trajEvaluator *TrajectoryEvaluator,
) *AgentEvaluator {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &AgentEvaluator{
		Logger:             logger,
		EvaluationGenerator: evalGenerator,
		ResponseEvaluator:   respEvaluator,
		TrajectoryEvaluator: trajEvaluator,
	}
}

// Evaluate runs a comprehensive agent evaluation.
func (e *AgentEvaluator) Evaluate(
	ctx context.Context,
	testFiles []string,
	agent AgentRunner,
	configDir string,
	printDetails bool,
) ([]EvaluationResult, error) {
	var results []EvaluationResult
	
	for _, testFile := range testFiles {
		// Load the dataset
		dataset, err := e.loadDataset(testFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load dataset %s: %w", testFile, err)
		}
		
		// Find configuration for this test
		config, err := e.findConfigForTestFile(testFile, configDir)
		if err != nil {
			e.Logger.Warn("Using default configuration", 
				slog.String("test_file", testFile),
				slog.String("error", err.Error()))
			config = DefaultEvaluationConfig()
		}
		
		// Generate agent responses
		evaluatedDataset, err := e.EvaluationGenerator.GenerateResponses(
			ctx, dataset, agent, config.Runs)
		if err != nil {
			return nil, fmt.Errorf("failed to generate responses for %s: %w", testFile, err)
		}
		
		// Evaluate response scores
		responseScores, err := e.ResponseEvaluator.Evaluate(
			evaluatedDataset, []string{}, printDetails)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate responses for %s: %w", testFile, err)
		}
		
		// Evaluate tool trajectory
		trajectoryScore, err := e.TrajectoryEvaluator.Evaluate(
			evaluatedDataset, printDetails)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate trajectory for %s: %w", testFile, err)
		}
		
		// Create and validate result
		result := EvaluationResult{
			ToolTrajectoryScore:     trajectoryScore,
			ResponseEvaluationScore: responseScores[ResponseEvaluationScoreKey],
			ResponseMatchScore:      responseScores[ResponseMatchScoreKey],
			Config:                  config,
			Dataset:                 evaluatedDataset,
			Timestamp:               time.Now(),
		}
		
		if !e.assertPerformance(result) && printDetails {
			e.Logger.Error("Performance assertion failed", 
				slog.Float64("tool_trajectory_score", trajectoryScore),
				slog.Float64("min_tool_trajectory_score", config.MinToolTrajectoryScore),
				slog.Float64("response_evaluation_score", responseScores[ResponseEvaluationScoreKey]),
				slog.Float64("min_response_evaluation_score", config.MinResponseEvaluationScore),
				slog.Float64("response_match_score", responseScores[ResponseMatchScoreKey]),
				slog.Float64("min_response_match_score", config.MinResponseMatchScore))
		}
		
		results = append(results, result)
	}
	
	return results, nil
}

// loadDataset loads an evaluation dataset from a file.
func (e *AgentEvaluator) loadDataset(filepath string) (EvaluationDataset, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	
	var dataset EvaluationDataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return nil, fmt.Errorf("failed to parse dataset: %w", err)
	}
	
	return dataset, nil
}

// findConfigForTestFile attempts to find a configuration file for a test.
func (e *AgentEvaluator) findConfigForTestFile(testFile, configDir string) (EvaluationConfig, error) {
	if configDir == "" {
		return EvaluationConfig{}, fmt.Errorf("no config directory specified")
	}
	
	// Extract filename without extension
	baseName := filepath.Base(testFile)
	ext := filepath.Ext(baseName)
	baseName = strings.TrimSuffix(baseName, ext)
	
	// Look for a config file with the same basename
	configPath := filepath.Join(configDir, baseName+".json")
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return EvaluationConfig{}, fmt.Errorf("failed to read config file: %w", err)
	}
	
	var config EvaluationConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return EvaluationConfig{}, fmt.Errorf("failed to parse config: %w", err)
	}
	
	return config, nil
}

// assertPerformance checks if evaluation results meet the required thresholds.
func (e *AgentEvaluator) assertPerformance(result EvaluationResult) bool {
	if result.ToolTrajectoryScore < result.Config.MinToolTrajectoryScore {
		return false
	}
	
	if result.ResponseEvaluationScore < result.Config.MinResponseEvaluationScore {
		return false
	}
	
	if result.ResponseMatchScore < result.Config.MinResponseMatchScore {
		return false
	}
	
	return true
}