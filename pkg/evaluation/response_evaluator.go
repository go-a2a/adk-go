// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package evaluation

import (
	"fmt"
	"log/slog"
	"strings"
)

// ResponseEvaluator evaluates agent responses.
type ResponseEvaluator struct {
	Logger     *slog.Logger
	EvalClient EvaluationClient
}

// EvaluationClient is an interface for evaluation services.
type EvaluationClient interface {
	// EvaluateCoherence evaluates response coherence on a scale of 0-5.
	EvaluateCoherence(query, response string) (float64, error)
	
	// EvaluateResponseMatch evaluates response similarity against a reference on a scale of 0-1.
	EvaluateResponseMatch(response, reference string) (float64, error)
}

// NewResponseEvaluator creates a new ResponseEvaluator.
func NewResponseEvaluator(logger *slog.Logger, evalClient EvaluationClient) *ResponseEvaluator {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &ResponseEvaluator{
		Logger:     logger,
		EvalClient: evalClient,
	}
}

// Evaluate evaluates responses in the dataset.
func (e *ResponseEvaluator) Evaluate(dataset EvaluationDataset, metrics []string, printDetails bool) (map[string]float64, error) {
	if len(dataset) == 0 {
		return nil, fmt.Errorf("empty evaluation dataset")
	}
	
	// Determine which metrics to use if not specified
	if len(metrics) == 0 {
		metrics = e.getMetrics(dataset)
	}
	
	results := make(map[string]float64)
	var coherenceScores []float64
	var matchScores []float64
	
	for _, session := range dataset {
		for _, query := range session {
			// Skip rows without responses
			if query.Response == "" {
				continue
			}
			
			// Evaluate coherence if requested
			if contains(metrics, ResponseEvaluationScoreKey) {
				score, err := e.EvalClient.EvaluateCoherence(query.Text, query.Response)
				if err != nil {
					e.Logger.Error("Failed to evaluate coherence", 
						slog.String("query", query.Text),
						slog.String("error", err.Error()))
					continue
				}
				coherenceScores = append(coherenceScores, score)
			}
			
			// Evaluate response match if requested and reference exists
			if contains(metrics, ResponseMatchScoreKey) && query.Reference != "" {
				score, err := e.EvalClient.EvaluateResponseMatch(query.Response, query.Reference)
				if err != nil {
					e.Logger.Error("Failed to evaluate response match", 
						slog.String("query", query.Text),
						slog.String("error", err.Error()))
					continue
				}
				matchScores = append(matchScores, score)
			}
		}
	}
	
	// Calculate mean scores
	if len(coherenceScores) > 0 {
		results[ResponseEvaluationScoreKey] = mean(coherenceScores)
	}
	
	if len(matchScores) > 0 {
		results[ResponseMatchScoreKey] = mean(matchScores)
	}
	
	if printDetails {
		e.printResults(results)
	}
	
	return results, nil
}

// getMetrics determines which metrics to use based on dataset content.
func (e *ResponseEvaluator) getMetrics(dataset EvaluationDataset) []string {
	var metrics []string
	hasReference := false
	
	// Check if dataset has references
	for _, session := range dataset {
		for _, query := range session {
			if query.Reference != "" {
				hasReference = true
				break
			}
		}
		if hasReference {
			break
		}
	}
	
	// Always include coherence score
	metrics = append(metrics, ResponseEvaluationScoreKey)
	
	// Add response match if references exist
	if hasReference {
		metrics = append(metrics, ResponseMatchScoreKey)
	}
	
	return metrics
}

// printResults prints evaluation results.
func (e *ResponseEvaluator) printResults(results map[string]float64) {
	var lines []string
	
	lines = append(lines, "Response evaluation results:")
	
	if score, ok := results[ResponseEvaluationScoreKey]; ok {
		lines = append(lines, fmt.Sprintf("- Response coherence score: %.2f / 5.0", score))
	}
	
	if score, ok := results[ResponseMatchScoreKey]; ok {
		lines = append(lines, fmt.Sprintf("- Response match score: %.2f / 1.0", score))
	}
	
	e.Logger.Info(strings.Join(lines, "\n"))
}

// mean calculates the average of a slice of float64 values.
func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}
	
	var sum float64
	for _, v := range values {
		sum += v
	}
	
	return sum / float64(len(values))
}

// contains checks if a string is in a slice.
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}