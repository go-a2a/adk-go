// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

// Package evaluation provides tools for evaluating agent performance.
// It supports evaluating tool usage accuracy, response quality, and other metrics.
package evaluation

import (
	"context"
	"log/slog"
)

// NewDefaultEvaluator creates a new AgentEvaluator with default components.
func NewDefaultEvaluator(logger *slog.Logger) *AgentEvaluator {
	if logger == nil {
		logger = slog.Default()
	}

	// Create the evaluation client
	evalClient := NewSimpleEvaluationClient(logger)

	// Create the component evaluators
	evalGenerator := NewEvaluationGenerator(logger)
	respEvaluator := NewResponseEvaluator(logger, evalClient)
	trajEvaluator := NewTrajectoryEvaluator(logger)

	// Create and return the agent evaluator
	return NewAgentEvaluator(logger, evalGenerator, respEvaluator, trajEvaluator)
}

// RunEvaluation is a convenience function to run an evaluation with minimal setup.
func RunEvaluation(
	ctx context.Context,
	testFiles []string,
	agent AgentRunner,
	configDir string,
	printDetails bool,
) ([]EvaluationResult, error) {
	logger := slog.Default()
	evaluator := NewDefaultEvaluator(logger)

	return evaluator.Evaluate(ctx, testFiles, agent, configDir, printDetails)
}
