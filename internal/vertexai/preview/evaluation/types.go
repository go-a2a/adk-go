// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package evaluation

import (
	"time"

	"google.golang.org/genai"
)

// MetricType represents the type of evaluation metric.
type MetricType string

const (
	// Computation-based metrics
	MetricTypeBLEU       MetricType = "bleu"
	MetricTypeROUGE1     MetricType = "rouge_1"
	MetricTypeROUGE2     MetricType = "rouge_2"
	MetricTypeROUGEL     MetricType = "rouge_l"
	MetricTypeROUGELSum  MetricType = "rouge_l_sum"
	MetricTypeExactMatch MetricType = "exact_match"
	MetricTypeToolCall   MetricType = "tool_call_quality"

	// Model-based metrics
	MetricTypeCoherence     MetricType = "coherence"
	MetricTypeFluency       MetricType = "fluency"
	MetricTypeSafety        MetricType = "safety"
	MetricTypeGroundedness  MetricType = "groundedness"
	MetricTypeInstruction   MetricType = "instruction_following"
	MetricTypeVerbosity     MetricType = "verbosity"
	MetricTypeSummarization MetricType = "summarization_quality"
	MetricTypeFulfillment   MetricType = "fulfillment"
	MetricTypeHelpfulness   MetricType = "helpfulness"

	// Multi-modal metrics
	MetricTypeImageDescription    MetricType = "image_description_quality"
	MetricTypeMultimodalCoherence MetricType = "multimodal_coherence"

	// Custom metrics
	MetricTypePointwise MetricType = "pointwise"
	MetricTypePairwise  MetricType = "pairwise"
	MetricTypeCustom    MetricType = "custom"
)

// ScoreType represents the type of score returned by a metric.
type ScoreType string

const (
	ScoreTypeNumeric     ScoreType = "numeric"
	ScoreTypeCategorical ScoreType = "categorical"
	ScoreTypeBoolean     ScoreType = "boolean"
)

// DataRecord represents a single evaluation data record.
type DataRecord struct {
	// Input is the prompt or input provided to the model
	Input string `json:"input,omitempty"`

	// Response is the model-generated response to evaluate
	Response string `json:"response"`

	// Reference is the reference/ground truth response (required for computation-based metrics)
	Reference string `json:"reference,omitempty"`

	// Context provides additional context for evaluation
	Context string `json:"context,omitempty"`

	// ImageURL is the URL to an image for multi-modal evaluation
	ImageURL string `json:"image_url,omitempty"`

	// VideoURL is the URL to a video for multi-modal evaluation
	VideoURL string `json:"video_url,omitempty"`

	// Metadata contains additional metadata for the record
	Metadata map[string]any `json:"metadata,omitempty"`

	// ToolCalls contains tool calling information for tool evaluation
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	// ExpectedToolCalls contains expected tool calls for comparison
	ExpectedToolCalls []ToolCall `json:"expected_tool_calls,omitempty"`
}

// ToolCall represents a tool call made by the model.
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// Dataset represents an evaluation dataset.
type Dataset struct {
	// Data contains the evaluation records
	Data []DataRecord `json:"data"`

	// Name is the dataset name for tracking
	Name string `json:"name,omitempty"`

	// Description provides dataset context
	Description string `json:"description,omitempty"`

	// Source indicates the data source (e.g., "gcs", "local", "bigquery")
	Source string `json:"source,omitempty"`

	// SourceURI is the URI of the data source
	SourceURI string `json:"source_uri,omitempty"`
}

// MetricConfig configures an evaluation metric.
type MetricConfig struct {
	// Type is the metric type
	Type MetricType `json:"type"`

	// Name is a custom name for the metric instance
	Name string `json:"name,omitempty"`

	// Weight is the weight for aggregated scoring
	Weight float64 `json:"weight,omitempty"`

	// Parameters contains metric-specific parameters
	Parameters map[string]any `json:"parameters,omitempty"`

	// PromptTemplate is the template for model-based metrics
	PromptTemplate *PromptTemplate `json:"prompt_template,omitempty"`

	// ScoreType indicates the expected score type
	ScoreType ScoreType `json:"score_type,omitempty"`

	// Threshold is the threshold for binary classification metrics
	Threshold float64 `json:"threshold,omitempty"`
}

// PromptTemplate represents an evaluation prompt template.
type PromptTemplate struct {
	// Template is the prompt template text
	Template string `json:"template"`

	// Variables defines template variables
	Variables []string `json:"variables,omitempty"`

	// Description describes the template purpose
	Description string `json:"description,omitempty"`

	// ScoreRange defines the expected score range
	ScoreRange *ScoreRange `json:"score_range,omitempty"`
}

// ScoreRange defines the range for numeric scores.
type ScoreRange struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// CustomMetric defines a custom evaluation metric.
type CustomMetric struct {
	// Name is the metric name
	Name string `json:"name"`

	// Description describes the metric
	Description string `json:"description"`

	// Type is the metric type (pointwise or pairwise)
	Type MetricType `json:"type"`

	// PromptTemplate is the evaluation prompt
	PromptTemplate *PromptTemplate `json:"prompt_template"`

	// ScoreType indicates the score type
	ScoreType ScoreType `json:"score_type"`

	// Model is the model to use for evaluation
	Model string `json:"model,omitempty"`

	// Parameters contains metric-specific parameters
	Parameters map[string]any `json:"parameters,omitempty"`
}

// EvalTask represents an evaluation task configuration.
type EvalTask struct {
	// Dataset is the evaluation dataset
	Dataset *Dataset `json:"dataset"`

	// Metrics are the evaluation metrics to compute
	Metrics []MetricConfig `json:"metrics"`

	// CustomMetrics are custom evaluation metrics
	CustomMetrics []*CustomMetric `json:"custom_metrics,omitempty"`

	// Experiment is the experiment name for tracking
	Experiment string `json:"experiment,omitempty"`

	// ExperimentRun is the experiment run name
	ExperimentRun string `json:"experiment_run,omitempty"`

	// Name is the task name
	Name string `json:"name,omitempty"`

	// Description describes the evaluation task
	Description string `json:"description,omitempty"`

	// ModelConfigs are model configurations to evaluate
	ModelConfigs []ModelConfig `json:"model_configs,omitempty"`

	// ParallelExecution enables parallel metric computation
	ParallelExecution bool `json:"parallel_execution,omitempty"`

	// MaxConcurrency limits concurrent metric evaluations
	MaxConcurrency int `json:"max_concurrency,omitempty"`
}

// ModelConfig represents a model configuration for evaluation.
type ModelConfig struct {
	// ModelName is the model identifier
	ModelName string `json:"model_name"`

	// Temperature controls randomness
	Temperature float64 `json:"temperature,omitempty"`

	// TopP controls nucleus sampling
	TopP float64 `json:"top_p,omitempty"`

	// TopK controls top-k sampling
	TopK int `json:"top_k,omitempty"`

	// MaxTokens limits response length
	MaxTokens int `json:"max_tokens,omitempty"`

	// SystemInstruction provides system-level instruction
	SystemInstruction string `json:"system_instruction,omitempty"`

	// Tools available to the model
	Tools []genai.Tool `json:"tools,omitempty"`

	// Additional parameters
	Parameters map[string]any `json:"parameters,omitempty"`
}

// MetricResult represents the result of a single metric evaluation.
type MetricResult struct {
	// MetricName is the name of the metric
	MetricName string `json:"metric_name"`

	// MetricType is the type of the metric
	MetricType MetricType `json:"metric_type"`

	// Score is the computed score
	Score float64 `json:"score"`

	// ScoreType indicates the score type
	ScoreType ScoreType `json:"score_type"`

	// Details contains detailed metric information
	Details map[string]any `json:"details,omitempty"`

	// RecordResults contains per-record results
	RecordResults []RecordResult `json:"record_results,omitempty"`

	// Error contains any evaluation error
	Error string `json:"error,omitempty"`

	// ComputeTime is the time taken to compute the metric
	ComputeTime time.Duration `json:"compute_time"`
}

// RecordResult represents the evaluation result for a single record.
type RecordResult struct {
	// Index is the record index in the dataset
	Index int `json:"index"`

	// Score is the score for this record
	Score float64 `json:"score"`

	// Explanation provides reasoning for model-based metrics
	Explanation string `json:"explanation,omitempty"`

	// Details contains additional result details
	Details map[string]any `json:"details,omitempty"`

	// Error contains any record-specific error
	Error string `json:"error,omitempty"`
}

// EvaluationResult represents the complete evaluation results.
type EvaluationResult struct {
	// TaskName is the evaluation task name
	TaskName string `json:"task_name"`

	// Experiment is the experiment name
	Experiment string `json:"experiment,omitempty"`

	// ExperimentRun is the experiment run name
	ExperimentRun string `json:"experiment_run,omitempty"`

	// MetricResults contains results for each metric
	MetricResults []MetricResult `json:"metric_results"`

	// OverallScore is the aggregated score across metrics
	OverallScore float64 `json:"overall_score"`

	// ModelConfig is the model configuration used
	ModelConfig *ModelConfig `json:"model_config,omitempty"`

	// DatasetInfo contains dataset metadata
	DatasetInfo *DatasetInfo `json:"dataset_info"`

	// StartTime is when evaluation started
	StartTime time.Time `json:"start_time"`

	// EndTime is when evaluation completed
	EndTime time.Time `json:"end_time"`

	// Duration is the total evaluation time
	Duration time.Duration `json:"duration"`

	// Summary provides a text summary of results
	Summary string `json:"summary,omitempty"`

	// Metadata contains additional result metadata
	Metadata map[string]any `json:"metadata,omitempty"`
}

// DatasetInfo contains metadata about the evaluation dataset.
type DatasetInfo struct {
	// Name is the dataset name
	Name string `json:"name"`

	// RecordCount is the number of records
	RecordCount int `json:"record_count"`

	// Source is the data source
	Source string `json:"source,omitempty"`

	// SourceURI is the source URI
	SourceURI string `json:"source_uri,omitempty"`

	// Schema describes the dataset schema
	Schema map[string]string `json:"schema,omitempty"`
}

// BatchEvaluationResult represents results from batch evaluation.
type BatchEvaluationResult struct {
	// Results contains results for each model configuration
	Results []EvaluationResult `json:"results"`

	// Comparison contains comparative analysis
	Comparison *ComparisonResult `json:"comparison,omitempty"`

	// StartTime is when batch evaluation started
	StartTime time.Time `json:"start_time"`

	// EndTime is when batch evaluation completed
	EndTime time.Time `json:"end_time"`

	// Duration is the total batch evaluation time
	Duration time.Duration `json:"duration"`
}

// ComparisonResult provides comparative analysis of multiple evaluations.
type ComparisonResult struct {
	// BestModel is the model with the highest overall score
	BestModel string `json:"best_model"`

	// MetricComparisons contains per-metric comparisons
	MetricComparisons map[string]MetricComparison `json:"metric_comparisons"`

	// StatisticalSignificance indicates if differences are significant
	StatisticalSignificance map[string]bool `json:"statistical_significance,omitempty"`

	// Summary provides a text summary of the comparison
	Summary string `json:"summary,omitempty"`
}

// MetricComparison provides comparison for a specific metric.
type MetricComparison struct {
	// MetricName is the metric being compared
	MetricName string `json:"metric_name"`

	// BestScore is the best score achieved
	BestScore float64 `json:"best_score"`

	// WorstScore is the worst score achieved
	WorstScore float64 `json:"worst_score"`

	// ScoreRange is the range of scores
	ScoreRange float64 `json:"score_range"`

	// Rankings contains model rankings for this metric
	Rankings []ModelRanking `json:"rankings"`
}

// ModelRanking represents a model's ranking for a metric.
type ModelRanking struct {
	// ModelName is the model identifier
	ModelName string `json:"model_name"`

	// Score is the model's score for this metric
	Score float64 `json:"score"`

	// Rank is the model's rank (1-based)
	Rank int `json:"rank"`
}
