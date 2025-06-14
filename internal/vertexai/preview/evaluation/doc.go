// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package evaluation provides Gen AI evaluation functionality for Vertex AI.
//
// This package is a port of the Python vertexai.preview.evaluation module, providing comprehensive
// support for evaluating generative AI models and applications using various metrics and evaluation
// frameworks. It enables developers to assess model performance, compare prompt templates, track
// experiments, and evaluate the quality of generated content.
//
// # Core Features
//
// The package provides comprehensive evaluation capabilities including:
//   - EvalTask: Core evaluation task management with dataset and metrics configuration
//   - Built-in Metrics: BLEU, ROUGE, coherence, fluency, safety, groundedness evaluation
//   - Custom Metrics: Support for custom pointwise and pairwise evaluation metrics
//   - Prompt Templates: Pre-defined evaluation templates for common use cases
//   - Experiment Tracking: Integration with Vertex AI Experiments for result tracking
//   - Multi-modal Evaluation: Support for text, image, and multimodal content evaluation
//
// # Supported Metrics
//
// Built-in computation-based metrics:
//   - BLEU: Bilingual Evaluation Understudy for translation quality
//   - ROUGE: Recall-Oriented Understudy for Gisting Evaluation (ROUGE-1, ROUGE-2, ROUGE-L, ROUGE-L-Sum)
//   - Exact Match: Exact string matching evaluation
//   - Tool Call Quality: Evaluation of function calling accuracy
//
// Model-based metrics:
//   - Coherence: Logical consistency and flow of generated content
//   - Fluency: Natural language quality and readability
//   - Safety: Harmful content detection and safety assessment
//   - Groundedness: Factual accuracy based on reference content
//   - Instruction Following: Adherence to given instructions
//   - Verbosity: Length and conciseness assessment
//   - Summarization Quality: Quality of text summarization
//
// # Architecture
//
// The package provides:
//   - EvaluationService: Core service for managing evaluation operations
//   - EvalTask: Evaluation task configuration and execution
//   - MetricConfig: Configuration for individual metrics
//   - PromptTemplate: Pre-defined and custom evaluation prompt templates
//   - EvaluationResult: Comprehensive evaluation results with metrics and analysis
//   - Dataset: Support for evaluation datasets from various sources
//
// # Usage
//
// Basic evaluation workflow:
//
//	service, err := evaluation.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Create evaluation dataset
//	dataset := &evaluation.Dataset{
//		Data: []evaluation.DataRecord{
//			{
//				Reference: "The capital of France is Paris.",
//				Response:  "Paris is the capital of France.",
//				Input:     "What is the capital of France?",
//			},
//			// More records...
//		},
//	}
//
//	// Configure evaluation metrics
//	metrics := []evaluation.MetricConfig{
//		{Type: evaluation.MetricTypeBLEU},
//		{Type: evaluation.MetricTypeROUGEL},
//		{Type: evaluation.MetricTypeCoherence},
//		{Type: evaluation.MetricTypeFluency},
//	}
//
//	// Create and run evaluation task
//	task := &evaluation.EvalTask{
//		Dataset:    dataset,
//		Metrics:    metrics,
//		Experiment: "my-experiment",
//	}
//
//	result, err := service.Evaluate(ctx, task, "eval-run-1")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Access evaluation results
//	fmt.Printf("BLEU Score: %.3f\n", result.GetMetricScore("bleu"))
//	fmt.Printf("ROUGE-L Score: %.3f\n", result.GetMetricScore("rouge_l"))
//
// # Custom Metrics
//
// Define custom evaluation metrics:
//
//	customMetric := &evaluation.CustomMetric{
//		Name:        "custom_quality",
//		Description: "Custom quality assessment",
//		Type:        evaluation.MetricTypePointwise,
//		PromptTemplate: &evaluation.PromptTemplate{
//			Template: "Rate the quality of this response on a scale of 1-10: {{.Response}}",
//		},
//		ScoreType: evaluation.ScoreTypeNumeric,
//	}
//
//	task.CustomMetrics = []*evaluation.CustomMetric{customMetric}
//
// # Prompt Templates
//
// Use pre-defined prompt templates:
//
//	template := evaluation.PromptTemplates.Pointwise.SummarizationQuality
//
//	metric := &evaluation.MetricConfig{
//		Type:           evaluation.MetricTypeCustom,
//		PromptTemplate: template,
//	}
//
// # Experiment Integration
//
// Track evaluations in Vertex AI Experiments:
//
//	task.Experiment = "model-comparison-experiment"
//	task.ExperimentRun = "gemini-vs-claude"
//
//	result, err := service.EvaluateWithExperiment(ctx, task)
//
// # Multi-modal Evaluation
//
// Evaluate multi-modal content:
//
//	dataset := &evaluation.Dataset{
//		Data: []evaluation.DataRecord{
//			{
//				Input: "Describe this image",
//				Response: "A sunset over the ocean",
//				Reference: "A beautiful sunset scene over calm ocean waters",
//				ImageURL: "gs://my-bucket/sunset.jpg",
//			},
//		},
//	}
//
//	metrics := []evaluation.MetricConfig{
//		{Type: evaluation.MetricTypeImageDescriptionQuality},
//		{Type: evaluation.MetricTypeMultimodalCoherence},
//	}
//
// # Batch Evaluation
//
// Evaluate multiple models or configurations:
//
//	configs := []evaluation.ModelConfig{
//		{ModelName: "gemini-2.0-flash-001", Temperature: 0.1},
//		{ModelName: "gemini-2.0-flash-001", Temperature: 0.9},
//	}
//
//	results, err := service.BatchEvaluate(ctx, task, configs)
//
// # Performance Considerations
//
// The package provides several optimizations:
//   - Parallel metric computation for large datasets
//   - Caching of model-based metric evaluations
//   - Streaming evaluation for large datasets
//   - Batch processing for improved throughput
//
// # Error Handling
//
// The package provides detailed error information for evaluation operations,
// including metric computation errors, dataset validation errors, and experiment
// tracking failures.
//
// # Thread Safety
//
// All service operations are safe for concurrent use across multiple goroutines.
// Evaluation tasks can be run in parallel for improved performance.
package evaluation
