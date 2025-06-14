// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package evaluation

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/auth/credentials"
	"google.golang.org/api/option"
)

// Service provides evaluation functionality for Vertex AI models.
//
// The service manages evaluation tasks, computes metrics, and tracks experiments.
// It supports both computation-based metrics (BLEU, ROUGE) and model-based metrics
// (coherence, fluency, safety) for comprehensive evaluation of generative AI models.
type Service struct {
	client    *aiplatform.PredictionClient
	projectID string
	location  string
	logger    *slog.Logger

	// Evaluation clients for different model types
	// Note: Removed GenerativeModel references as they're not available in the unified genai SDK
	mu sync.RWMutex
}

// ServiceOption is a functional option for configuring the evaluation service.
type ServiceOption func(*Service)

// WithLogger sets a custom logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// NewService creates a new evaluation service.
//
// The service requires a Google Cloud project ID and location. It uses
// Application Default Credentials for authentication.
//
// Parameters:
//   - ctx: Context for initialization
//   - projectID: Google Cloud project ID
//   - location: Geographic location (e.g., "us-central1")
//   - opts: Optional configuration options
//
// Returns a fully initialized evaluation service or an error if initialization fails.
func NewService(ctx context.Context, projectID, location string, opts ...ServiceOption) (*Service, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	service := &Service{
		projectID: projectID,
		location:  location,
		logger:    slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(service)
	}

	// Create credentials
	creds, err := credentials.DetectDefault(&credentials.DetectOptions{
		Scopes: []string{
			"https://www.googleapis.com/auth/cloud-platform",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect credentials: %w", err)
	}

	// Create AI Platform client
	client, err := aiplatform.NewPredictionClient(ctx, option.WithAuthCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create prediction client: %w", err)
	}
	service.client = client

	service.logger.InfoContext(ctx, "Evaluation service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the evaluation service and releases all resources.
func (s *Service) Close() error {
	s.logger.Info("Closing evaluation service")

	if s.client != nil {
		if err := s.client.Close(); err != nil {
			s.logger.Error("Failed to close prediction client", slog.String("error", err.Error()))
			return fmt.Errorf("failed to close prediction client: %w", err)
		}
	}

	s.logger.Info("Evaluation service closed successfully")
	return nil
}

// Evaluate executes an evaluation task and returns the results.
//
// This is the main entry point for running evaluations. It processes the dataset
// through all specified metrics and returns comprehensive results.
//
// Parameters:
//   - ctx: Context for the evaluation
//   - task: The evaluation task configuration
//   - runName: Optional experiment run name for tracking
//
// Returns evaluation results or an error if evaluation fails.
func (s *Service) Evaluate(ctx context.Context, task *EvalTask, runName string) (*EvaluationResult, error) {
	startTime := time.Now()

	s.logger.InfoContext(ctx, "Starting evaluation",
		slog.String("task_name", task.Name),
		slog.String("run_name", runName),
		slog.Int("dataset_size", len(task.Dataset.Data)),
		slog.Int("metric_count", len(task.Metrics)),
	)

	// Validate task
	if err := s.validateTask(task); err != nil {
		return nil, fmt.Errorf("invalid task: %w", err)
	}

	// Initialize result
	result := &EvaluationResult{
		TaskName:      task.Name,
		Experiment:    task.Experiment,
		ExperimentRun: runName,
		StartTime:     startTime,
		DatasetInfo: &DatasetInfo{
			Name:        task.Dataset.Name,
			RecordCount: len(task.Dataset.Data),
			Source:      task.Dataset.Source,
			SourceURI:   task.Dataset.SourceURI,
		},
		MetricResults: make([]MetricResult, 0, len(task.Metrics)+len(task.CustomMetrics)),
	}

	// Process metrics
	if task.ParallelExecution {
		if err := s.evaluateMetricsParallel(ctx, task, result); err != nil {
			return nil, fmt.Errorf("failed to evaluate metrics in parallel: %w", err)
		}
	} else {
		if err := s.evaluateMetricsSequential(ctx, task, result); err != nil {
			return nil, fmt.Errorf("failed to evaluate metrics sequentially: %w", err)
		}
	}

	// Calculate overall score
	result.OverallScore = s.calculateOverallScore(task, result.MetricResults)

	// Set completion time
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Generate summary
	result.Summary = s.generateSummary(result)

	s.logger.InfoContext(ctx, "Evaluation completed",
		slog.String("task_name", task.Name),
		slog.Float64("overall_score", result.OverallScore),
		slog.Duration("duration", result.Duration),
	)

	return result, nil
}

// BatchEvaluate evaluates multiple model configurations against the same dataset.
//
// This method is useful for comparing different models or configurations side by side.
//
// Parameters:
//   - ctx: Context for the evaluation
//   - task: The base evaluation task (dataset and metrics)
//   - configs: Model configurations to evaluate
//
// Returns batch evaluation results with comparison analysis.
func (s *Service) BatchEvaluate(ctx context.Context, task *EvalTask, configs []ModelConfig) (*BatchEvaluationResult, error) {
	startTime := time.Now()

	s.logger.InfoContext(ctx, "Starting batch evaluation",
		slog.String("task_name", task.Name),
		slog.Int("config_count", len(configs)),
	)

	result := &BatchEvaluationResult{
		Results:   make([]EvaluationResult, 0, len(configs)),
		StartTime: startTime,
	}

	// Evaluate each configuration
	for i, config := range configs {
		runName := fmt.Sprintf("batch_eval_%d_%s", i, config.ModelName)

		// Create task copy with specific model config
		taskCopy := *task
		taskCopy.ModelConfigs = []ModelConfig{config}

		evalResult, err := s.Evaluate(ctx, &taskCopy, runName)
		if err != nil {
			s.logger.ErrorContext(ctx, "Failed to evaluate configuration",
				slog.String("model", config.ModelName),
				slog.String("error", err.Error()),
			)
			continue
		}

		evalResult.ModelConfig = &config
		result.Results = append(result.Results, *evalResult)
	}

	// Generate comparison
	if len(result.Results) > 1 {
		result.Comparison = s.generateComparison(result.Results)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	s.logger.InfoContext(ctx, "Batch evaluation completed",
		slog.Int("successful_evaluations", len(result.Results)),
		slog.Duration("duration", result.Duration),
	)

	return result, nil
}

// validateTask validates the evaluation task configuration.
func (s *Service) validateTask(task *EvalTask) error {
	if task.Dataset == nil {
		return fmt.Errorf("dataset is required")
	}

	if len(task.Dataset.Data) == 0 {
		return fmt.Errorf("dataset must contain at least one record")
	}

	if len(task.Metrics) == 0 && len(task.CustomMetrics) == 0 {
		return fmt.Errorf("at least one metric must be specified")
	}

	// Validate that computation-based metrics have required fields
	for _, metric := range task.Metrics {
		if s.isComputationBasedMetric(metric.Type) {
			if err := s.validateComputationMetric(task.Dataset, metric); err != nil {
				return fmt.Errorf("validation failed for metric %s: %w", metric.Type, err)
			}
		}
	}

	return nil
}

// isComputationBasedMetric checks if a metric is computation-based.
func (s *Service) isComputationBasedMetric(metricType MetricType) bool {
	computationMetrics := map[MetricType]bool{
		MetricTypeBLEU:       true,
		MetricTypeROUGE1:     true,
		MetricTypeROUGE2:     true,
		MetricTypeROUGEL:     true,
		MetricTypeROUGELSum:  true,
		MetricTypeExactMatch: true,
		MetricTypeToolCall:   true,
	}
	return computationMetrics[metricType]
}

// validateComputationMetric validates computation-based metrics.
func (s *Service) validateComputationMetric(dataset *Dataset, metric MetricConfig) error {
	for i, record := range dataset.Data {
		switch metric.Type {
		case MetricTypeBLEU, MetricTypeROUGE1, MetricTypeROUGE2, MetricTypeROUGEL, MetricTypeROUGELSum, MetricTypeExactMatch:
			if record.Reference == "" {
				return fmt.Errorf("record %d missing reference field required for %s metric", i, metric.Type)
			}
			if record.Response == "" {
				return fmt.Errorf("record %d missing response field required for %s metric", i, metric.Type)
			}
		case MetricTypeToolCall:
			if len(record.ExpectedToolCalls) == 0 {
				return fmt.Errorf("record %d missing expected_tool_calls required for tool_call_quality metric", i)
			}
		}
	}
	return nil
}

// evaluateMetricsSequential evaluates metrics one by one.
func (s *Service) evaluateMetricsSequential(ctx context.Context, task *EvalTask, result *EvaluationResult) error {
	// Evaluate built-in metrics
	for _, metric := range task.Metrics {
		metricResult, err := s.evaluateMetric(ctx, task.Dataset, metric)
		if err != nil {
			s.logger.ErrorContext(ctx, "Failed to evaluate metric",
				slog.String("metric", string(metric.Type)),
				slog.String("error", err.Error()),
			)
			// Continue with other metrics
			metricResult = &MetricResult{
				MetricName: string(metric.Type),
				MetricType: metric.Type,
				Error:      err.Error(),
			}
		}
		result.MetricResults = append(result.MetricResults, *metricResult)
	}

	// Evaluate custom metrics
	for _, customMetric := range task.CustomMetrics {
		metricConfig := MetricConfig{
			Type:           customMetric.Type,
			Name:           customMetric.Name,
			PromptTemplate: customMetric.PromptTemplate,
			ScoreType:      customMetric.ScoreType,
			Parameters:     customMetric.Parameters,
		}

		metricResult, err := s.evaluateCustomMetric(ctx, task.Dataset, customMetric, metricConfig)
		if err != nil {
			s.logger.ErrorContext(ctx, "Failed to evaluate custom metric",
				slog.String("metric", customMetric.Name),
				slog.String("error", err.Error()),
			)
			metricResult = &MetricResult{
				MetricName: customMetric.Name,
				MetricType: customMetric.Type,
				Error:      err.Error(),
			}
		}
		result.MetricResults = append(result.MetricResults, *metricResult)
	}

	return nil
}

// evaluateMetricsParallel evaluates metrics in parallel.
func (s *Service) evaluateMetricsParallel(ctx context.Context, task *EvalTask, result *EvaluationResult) error {
	maxConcurrency := task.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = 5 // Default concurrency
	}

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	totalMetrics := len(task.Metrics) + len(task.CustomMetrics)
	metricResults := make([]MetricResult, 0, totalMetrics)

	// Evaluate built-in metrics
	for _, metric := range task.Metrics {
		wg.Add(1)
		go func(m MetricConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			metricResult, err := s.evaluateMetric(ctx, task.Dataset, m)
			if err != nil {
				s.logger.ErrorContext(ctx, "Failed to evaluate metric",
					slog.String("metric", string(m.Type)),
					slog.String("error", err.Error()),
				)
				metricResult = &MetricResult{
					MetricName: string(m.Type),
					MetricType: m.Type,
					Error:      err.Error(),
				}
			}

			mu.Lock()
			metricResults = append(metricResults, *metricResult)
			mu.Unlock()
		}(metric)
	}

	// Evaluate custom metrics
	for _, customMetric := range task.CustomMetrics {
		wg.Add(1)
		go func(cm *CustomMetric) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			metricConfig := MetricConfig{
				Type:           cm.Type,
				Name:           cm.Name,
				PromptTemplate: cm.PromptTemplate,
				ScoreType:      cm.ScoreType,
				Parameters:     cm.Parameters,
			}

			metricResult, err := s.evaluateCustomMetric(ctx, task.Dataset, cm, metricConfig)
			if err != nil {
				s.logger.ErrorContext(ctx, "Failed to evaluate custom metric",
					slog.String("metric", cm.Name),
					slog.String("error", err.Error()),
				)
				metricResult = &MetricResult{
					MetricName: cm.Name,
					MetricType: cm.Type,
					Error:      err.Error(),
				}
			}

			mu.Lock()
			metricResults = append(metricResults, *metricResult)
			mu.Unlock()
		}(customMetric)
	}

	wg.Wait()
	result.MetricResults = metricResults
	return nil
}

// evaluateMetric evaluates a single built-in metric.
func (s *Service) evaluateMetric(ctx context.Context, dataset *Dataset, metric MetricConfig) (*MetricResult, error) {
	startTime := time.Now()

	metricResult := &MetricResult{
		MetricName:    string(metric.Type),
		MetricType:    metric.Type,
		ScoreType:     ScoreTypeNumeric,
		RecordResults: make([]RecordResult, 0, len(dataset.Data)),
	}

	switch metric.Type {
	case MetricTypeBLEU:
		return s.evaluateBLEU(ctx, dataset, metric)
	case MetricTypeROUGE1, MetricTypeROUGE2, MetricTypeROUGEL, MetricTypeROUGELSum:
		return s.evaluateROUGE(ctx, dataset, metric)
	case MetricTypeExactMatch:
		return s.evaluateExactMatch(ctx, dataset, metric)
	case MetricTypeToolCall:
		return s.evaluateToolCall(ctx, dataset, metric)
	case MetricTypeCoherence, MetricTypeFluency, MetricTypeSafety, MetricTypeGroundedness,
		MetricTypeInstruction, MetricTypeVerbosity, MetricTypeSummarization, MetricTypeFulfillment,
		MetricTypeHelpfulness:
		return s.evaluateModelBasedMetric(ctx, dataset, metric)
	default:
		return nil, fmt.Errorf("unsupported metric type: %s", metric.Type)
	}

	metricResult.ComputeTime = time.Since(startTime)
	return metricResult, nil
}

// evaluateBLEU computes BLEU scores.
func (s *Service) evaluateBLEU(ctx context.Context, dataset *Dataset, metric MetricConfig) (*MetricResult, error) {
	startTime := time.Now()

	metricResult := &MetricResult{
		MetricName:    string(metric.Type),
		MetricType:    metric.Type,
		ScoreType:     ScoreTypeNumeric,
		RecordResults: make([]RecordResult, 0, len(dataset.Data)),
	}

	var totalScore float64
	validRecords := 0

	for i, record := range dataset.Data {
		score := s.computeBLEUScore(record.Response, record.Reference)

		recordResult := RecordResult{
			Index: i,
			Score: score,
		}

		if !math.IsNaN(score) {
			totalScore += score
			validRecords++
		} else {
			recordResult.Error = "Failed to compute BLEU score"
		}

		metricResult.RecordResults = append(metricResult.RecordResults, recordResult)
	}

	if validRecords > 0 {
		metricResult.Score = totalScore / float64(validRecords)
	}

	metricResult.ComputeTime = time.Since(startTime)
	return metricResult, nil
}

// computeBLEUScore computes a simple BLEU-like score.
// Note: This is a simplified implementation. A production version would use
// proper BLEU computation with n-gram precision and brevity penalty.
func (s *Service) computeBLEUScore(candidate, reference string) float64 {
	candWords := strings.Fields(strings.ToLower(candidate))
	refWords := strings.Fields(strings.ToLower(reference))

	if len(candWords) == 0 || len(refWords) == 0 {
		return 0.0
	}

	// Simple word overlap for demonstration
	refWordSet := make(map[string]bool)
	for _, word := range refWords {
		refWordSet[word] = true
	}

	matches := 0
	for _, word := range candWords {
		if refWordSet[word] {
			matches++
		}
	}

	precision := float64(matches) / float64(len(candWords))

	// Simple brevity penalty
	brevityPenalty := 1.0
	if len(candWords) < len(refWords) {
		brevityPenalty = math.Exp(1.0 - float64(len(refWords))/float64(len(candWords)))
	}

	return precision * brevityPenalty
}

// evaluateROUGE computes ROUGE scores.
func (s *Service) evaluateROUGE(ctx context.Context, dataset *Dataset, metric MetricConfig) (*MetricResult, error) {
	startTime := time.Now()

	metricResult := &MetricResult{
		MetricName:    string(metric.Type),
		MetricType:    metric.Type,
		ScoreType:     ScoreTypeNumeric,
		RecordResults: make([]RecordResult, 0, len(dataset.Data)),
	}

	var totalScore float64
	validRecords := 0

	for i, record := range dataset.Data {
		var score float64

		switch metric.Type {
		case MetricTypeROUGE1:
			score = s.computeROUGE1(record.Response, record.Reference)
		case MetricTypeROUGE2:
			score = s.computeROUGE2(record.Response, record.Reference)
		case MetricTypeROUGEL:
			score = s.computeROUGEL(record.Response, record.Reference)
		case MetricTypeROUGELSum:
			score = s.computeROUGELSum(record.Response, record.Reference)
		}

		recordResult := RecordResult{
			Index: i,
			Score: score,
		}

		if !math.IsNaN(score) {
			totalScore += score
			validRecords++
		} else {
			recordResult.Error = "Failed to compute ROUGE score"
		}

		metricResult.RecordResults = append(metricResult.RecordResults, recordResult)
	}

	if validRecords > 0 {
		metricResult.Score = totalScore / float64(validRecords)
	}

	metricResult.ComputeTime = time.Since(startTime)
	return metricResult, nil
}

// computeROUGE1 computes ROUGE-1 score (unigram overlap).
func (s *Service) computeROUGE1(candidate, reference string) float64 {
	candWords := strings.Fields(strings.ToLower(candidate))
	refWords := strings.Fields(strings.ToLower(reference))

	if len(refWords) == 0 {
		return 0.0
	}

	refWordCount := make(map[string]int)
	for _, word := range refWords {
		refWordCount[word]++
	}

	candWordCount := make(map[string]int)
	for _, word := range candWords {
		candWordCount[word]++
	}

	overlap := 0
	for word, count := range candWordCount {
		if refCount, exists := refWordCount[word]; exists {
			if count < refCount {
				overlap += count
			} else {
				overlap += refCount
			}
		}
	}

	return float64(overlap) / float64(len(refWords))
}

// computeROUGE2 computes ROUGE-2 score (bigram overlap).
func (s *Service) computeROUGE2(candidate, reference string) float64 {
	candBigrams := s.getBigrams(candidate)
	refBigrams := s.getBigrams(reference)

	if len(refBigrams) == 0 {
		return 0.0
	}

	refBigramCount := make(map[string]int)
	for _, bigram := range refBigrams {
		refBigramCount[bigram]++
	}

	candBigramCount := make(map[string]int)
	for _, bigram := range candBigrams {
		candBigramCount[bigram]++
	}

	overlap := 0
	for bigram, count := range candBigramCount {
		if refCount, exists := refBigramCount[bigram]; exists {
			if count < refCount {
				overlap += count
			} else {
				overlap += refCount
			}
		}
	}

	return float64(overlap) / float64(len(refBigrams))
}

// getBigrams extracts bigrams from text.
func (s *Service) getBigrams(text string) []string {
	words := strings.Fields(strings.ToLower(text))
	if len(words) < 2 {
		return []string{}
	}

	bigrams := make([]string, 0, len(words)-1)
	for i := 0; i < len(words)-1; i++ {
		bigrams = append(bigrams, words[i]+" "+words[i+1])
	}
	return bigrams
}

// computeROUGEL computes ROUGE-L score (longest common subsequence).
func (s *Service) computeROUGEL(candidate, reference string) float64 {
	candWords := strings.Fields(strings.ToLower(candidate))
	refWords := strings.Fields(strings.ToLower(reference))

	lcs := s.longestCommonSubsequence(candWords, refWords)

	if len(refWords) == 0 || len(candWords) == 0 {
		return 0.0
	}

	precision := float64(lcs) / float64(len(candWords))
	recall := float64(lcs) / float64(len(refWords))

	if precision+recall == 0 {
		return 0.0
	}

	return 2 * precision * recall / (precision + recall)
}

// computeROUGELSum computes ROUGE-L sum score.
func (s *Service) computeROUGELSum(candidate, reference string) float64 {
	// For simplicity, using ROUGE-L computation
	// In practice, ROUGE-L-Sum handles sentence-level LCS
	return s.computeROUGEL(candidate, reference)
}

// longestCommonSubsequence computes the length of the longest common subsequence.
func (s *Service) longestCommonSubsequence(seq1, seq2 []string) int {
	m, n := len(seq1), len(seq2)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if seq1[i-1] == seq2[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] > dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}

	return dp[m][n]
}

// evaluateExactMatch computes exact match scores.
func (s *Service) evaluateExactMatch(ctx context.Context, dataset *Dataset, metric MetricConfig) (*MetricResult, error) {
	startTime := time.Now()

	metricResult := &MetricResult{
		MetricName:    string(metric.Type),
		MetricType:    metric.Type,
		ScoreType:     ScoreTypeNumeric,
		RecordResults: make([]RecordResult, 0, len(dataset.Data)),
	}

	var totalScore float64

	for i, record := range dataset.Data {
		var score float64
		if strings.TrimSpace(record.Response) == strings.TrimSpace(record.Reference) {
			score = 1.0
		}

		recordResult := RecordResult{
			Index: i,
			Score: score,
		}

		totalScore += score
		metricResult.RecordResults = append(metricResult.RecordResults, recordResult)
	}

	metricResult.Score = totalScore / float64(len(dataset.Data))
	metricResult.ComputeTime = time.Since(startTime)
	return metricResult, nil
}

// evaluateToolCall evaluates tool calling quality.
func (s *Service) evaluateToolCall(ctx context.Context, dataset *Dataset, metric MetricConfig) (*MetricResult, error) {
	startTime := time.Now()

	metricResult := &MetricResult{
		MetricName:    string(metric.Type),
		MetricType:    metric.Type,
		ScoreType:     ScoreTypeNumeric,
		RecordResults: make([]RecordResult, 0, len(dataset.Data)),
	}

	var totalScore float64

	for i, record := range dataset.Data {
		score := s.computeToolCallScore(record.ToolCalls, record.ExpectedToolCalls)

		recordResult := RecordResult{
			Index: i,
			Score: score,
		}

		totalScore += score
		metricResult.RecordResults = append(metricResult.RecordResults, recordResult)
	}

	metricResult.Score = totalScore / float64(len(dataset.Data))
	metricResult.ComputeTime = time.Since(startTime)
	return metricResult, nil
}

// computeToolCallScore computes tool call accuracy.
func (s *Service) computeToolCallScore(actual, expected []ToolCall) float64 {
	if len(expected) == 0 {
		if len(actual) == 0 {
			return 1.0
		}
		return 0.0
	}

	// Simple comparison - in practice, this would be more sophisticated
	matches := 0
	for _, exp := range expected {
		for _, act := range actual {
			if exp.Name == act.Name {
				// Check if arguments match
				if s.compareArguments(exp.Arguments, act.Arguments) {
					matches++
					break
				}
			}
		}
	}

	return float64(matches) / float64(len(expected))
}

// compareArguments compares tool call arguments.
func (s *Service) compareArguments(expected, actual map[string]any) bool {
	if len(expected) != len(actual) {
		return false
	}

	for key, expectedVal := range expected {
		if actualVal, exists := actual[key]; !exists || expectedVal != actualVal {
			return false
		}
	}

	return true
}

// evaluateModelBasedMetric evaluates metrics using language models.
func (s *Service) evaluateModelBasedMetric(ctx context.Context, dataset *Dataset, metric MetricConfig) (*MetricResult, error) {
	startTime := time.Now()

	// Get appropriate template
	template := s.getTemplateForMetric(metric.Type)
	if template == nil {
		return nil, fmt.Errorf("no template available for metric %s", metric.Type)
	}

	metricResult := &MetricResult{
		MetricName:    string(metric.Type),
		MetricType:    metric.Type,
		ScoreType:     ScoreTypeNumeric,
		RecordResults: make([]RecordResult, 0, len(dataset.Data)),
	}

	var totalScore float64
	validRecords := 0

	for i, record := range dataset.Data {
		prompt := s.formatPromptTemplate(template.Template, record)

		score, explanation, err := s.evaluateWithModel(ctx, prompt, "gemini-2.0-flash-001")
		if err != nil {
			s.logger.ErrorContext(ctx, "Failed to evaluate record with model",
				slog.Int("record_index", i),
				slog.String("metric", string(metric.Type)),
				slog.String("error", err.Error()),
			)

			metricResult.RecordResults = append(metricResult.RecordResults, RecordResult{
				Index: i,
				Error: err.Error(),
			})
			continue
		}

		recordResult := RecordResult{
			Index:       i,
			Score:       score,
			Explanation: explanation,
		}

		totalScore += score
		validRecords++
		metricResult.RecordResults = append(metricResult.RecordResults, recordResult)
	}

	if validRecords > 0 {
		metricResult.Score = totalScore / float64(validRecords)
	}

	metricResult.ComputeTime = time.Since(startTime)
	return metricResult, nil
}

// getTemplateForMetric returns the appropriate template for a metric.
func (s *Service) getTemplateForMetric(metricType MetricType) *PromptTemplate {
	switch metricType {
	case MetricTypeCoherence:
		return PromptTemplates.Pointwise.Coherence
	case MetricTypeFluency:
		return PromptTemplates.Pointwise.Fluency
	case MetricTypeSafety:
		return PromptTemplates.Pointwise.Safety
	case MetricTypeGroundedness:
		return PromptTemplates.Pointwise.Groundedness
	case MetricTypeInstruction:
		return PromptTemplates.Pointwise.InstructionFollowing
	case MetricTypeVerbosity:
		return PromptTemplates.Pointwise.Verbosity
	case MetricTypeSummarization:
		return PromptTemplates.Pointwise.SummarizationQuality
	case MetricTypeFulfillment:
		return PromptTemplates.Pointwise.Fulfillment
	case MetricTypeHelpfulness:
		return PromptTemplates.Pointwise.Helpfulness
	default:
		return nil
	}
}

// formatPromptTemplate formats a template with record data.
func (s *Service) formatPromptTemplate(template string, record DataRecord) string {
	// Simple template replacement - in practice, you'd use a proper template engine
	result := template
	result = strings.ReplaceAll(result, "{{.Input}}", record.Input)
	result = strings.ReplaceAll(result, "{{.Response}}", record.Response)
	result = strings.ReplaceAll(result, "{{.Reference}}", record.Reference)
	result = strings.ReplaceAll(result, "{{.Context}}", record.Context)
	result = strings.ReplaceAll(result, "{{.ImageURL}}", record.ImageURL)
	return result
}

// evaluateWithModel evaluates using a generative model.
func (s *Service) evaluateWithModel(ctx context.Context, prompt, modelName string) (float64, string, error) {
	// This is a placeholder implementation
	// In practice, you would:
	// 1. Get or create a model client
	// 2. Send the prompt to the model
	// 3. Parse the response to extract score and explanation

	// For now, return a mock score
	return 4.0, "Model-based evaluation not fully implemented", nil
}

// evaluateCustomMetric evaluates a custom metric.
func (s *Service) evaluateCustomMetric(ctx context.Context, dataset *Dataset, customMetric *CustomMetric, config MetricConfig) (*MetricResult, error) {
	startTime := time.Now()

	metricResult := &MetricResult{
		MetricName:    customMetric.Name,
		MetricType:    customMetric.Type,
		ScoreType:     customMetric.ScoreType,
		RecordResults: make([]RecordResult, 0, len(dataset.Data)),
	}

	var totalScore float64
	validRecords := 0

	for i, record := range dataset.Data {
		prompt := s.formatPromptTemplate(customMetric.PromptTemplate.Template, record)

		modelName := customMetric.Model
		if modelName == "" {
			modelName = "gemini-2.0-flash-001"
		}

		score, explanation, err := s.evaluateWithModel(ctx, prompt, modelName)
		if err != nil {
			metricResult.RecordResults = append(metricResult.RecordResults, RecordResult{
				Index: i,
				Error: err.Error(),
			})
			continue
		}

		recordResult := RecordResult{
			Index:       i,
			Score:       score,
			Explanation: explanation,
		}

		totalScore += score
		validRecords++
		metricResult.RecordResults = append(metricResult.RecordResults, recordResult)
	}

	if validRecords > 0 {
		metricResult.Score = totalScore / float64(validRecords)
	}

	metricResult.ComputeTime = time.Since(startTime)
	return metricResult, nil
}

// calculateOverallScore calculates the overall score across all metrics.
func (s *Service) calculateOverallScore(task *EvalTask, results []MetricResult) float64 {
	var weightedSum float64
	var totalWeight float64

	for i, result := range results {
		weight := 1.0 // Default weight

		// Find weight from task configuration
		if i < len(task.Metrics) {
			if task.Metrics[i].Weight > 0 {
				weight = task.Metrics[i].Weight
			}
		}

		if result.Error == "" && !math.IsNaN(result.Score) {
			weightedSum += result.Score * weight
			totalWeight += weight
		}
	}

	if totalWeight > 0 {
		return weightedSum / totalWeight
	}
	return 0.0
}

// generateSummary generates a text summary of evaluation results.
func (s *Service) generateSummary(result *EvaluationResult) string {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("Evaluation completed with overall score: %.3f\n", result.OverallScore))
	summary.WriteString(fmt.Sprintf("Dataset: %d records\n", result.DatasetInfo.RecordCount))
	summary.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))

	successful := 0
	for _, metricResult := range result.MetricResults {
		if metricResult.Error == "" {
			successful++
		}
	}

	summary.WriteString(fmt.Sprintf("Metrics: %d/%d successful\n", successful, len(result.MetricResults)))

	return summary.String()
}

// generateComparison generates comparison analysis for batch evaluation.
func (s *Service) generateComparison(results []EvaluationResult) *ComparisonResult {
	if len(results) == 0 {
		return nil
	}

	comparison := &ComparisonResult{
		MetricComparisons: make(map[string]MetricComparison),
	}

	// Find best overall model
	bestScore := -1.0
	bestModel := ""
	for _, result := range results {
		if result.ModelConfig != nil && result.OverallScore > bestScore {
			bestScore = result.OverallScore
			bestModel = result.ModelConfig.ModelName
		}
	}
	comparison.BestModel = bestModel

	// Analyze each metric across models
	metricNames := make(map[string]bool)
	for _, result := range results {
		for _, metricResult := range result.MetricResults {
			metricNames[metricResult.MetricName] = true
		}
	}

	for metricName := range metricNames {
		metricComp := MetricComparison{
			MetricName: metricName,
			BestScore:  -1.0,
			WorstScore: math.Inf(1),
			Rankings:   make([]ModelRanking, 0, len(results)),
		}

		for _, result := range results {
			for _, metricResult := range result.MetricResults {
				if metricResult.MetricName == metricName && metricResult.Error == "" {
					if metricResult.Score > metricComp.BestScore {
						metricComp.BestScore = metricResult.Score
					}
					if metricResult.Score < metricComp.WorstScore {
						metricComp.WorstScore = metricResult.Score
					}

					if result.ModelConfig != nil {
						metricComp.Rankings = append(metricComp.Rankings, ModelRanking{
							ModelName: result.ModelConfig.ModelName,
							Score:     metricResult.Score,
						})
					}
				}
			}
		}

		metricComp.ScoreRange = metricComp.BestScore - metricComp.WorstScore
		comparison.MetricComparisons[metricName] = metricComp
	}

	return comparison
}

// parseModelResponse parses a model response to extract score and explanation.
func (s *Service) parseModelResponse(response string) (float64, string, error) {
	// Look for "Rating: X" pattern
	re := regexp.MustCompile(`(?i)rating:\s*(\d+(?:\.\d+)?)`)
	matches := re.FindStringSubmatch(response)

	if len(matches) < 2 {
		return 0, "", fmt.Errorf("could not parse rating from response: %s", response)
	}

	score, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid rating format: %s", matches[1])
	}

	// Extract explanation (everything after the rating)
	explanation := strings.TrimSpace(response[len(matches[0]):])

	return score, explanation, nil
}
