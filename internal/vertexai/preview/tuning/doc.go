// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package tuning provides fine-tuning functionality for Vertex AI models.
//
// This package is a port of the Python vertexai.preview.tuning module, providing comprehensive
// support for supervised fine-tuning and parameter-efficient tuning methods including LoRA
// (Low-Rank Adaptation) and QLoRA. It enables developers to customize foundational models
// by training them on domain-specific data with significantly reduced computational requirements.
//
// # Core Features
//
// The package provides comprehensive fine-tuning capabilities including:
//   - Supervised Fine-Tuning (SFT): Full fine-tuning with labeled examples
//   - LoRA Tuning: Parameter-efficient fine-tuning using Low-Rank Adaptation
//   - QLoRA Tuning: Quantized LoRA for even greater memory efficiency
//   - PEFT Methods: Parameter-Efficient Fine-Tuning techniques
//   - Evaluation Metrics: Comprehensive evaluation during and after tuning
//   - Hyperparameter Optimization: Automated tuning of learning parameters
//   - Model Registry Integration: Automatic versioning and deployment
//
// # Supported Methods
//
// Fine-tuning approaches supported:
//   - Full Fine-Tuning: Traditional approach updating all model parameters
//   - LoRA (Low-Rank Adaptation): Updates only rank decomposition matrices
//   - QLoRA: Quantized LoRA with 4-bit quantization for memory efficiency
//   - Adapters: Lightweight adapter layers inserted into transformer blocks
//   - Prefix Tuning: Learning continuous task-specific vectors
//   - P-Tuning v2: Deep prompt tuning with trainable embeddings
//
// # Model Support
//
// Compatible models for fine-tuning:
//   - Gemini Models: gemini-2.0-flash-001, gemini-2.0-pro-001
//   - Llama Models: Available through Model Garden
//   - Custom Models: Support for custom base models
//   - Multi-modal Models: Text, image, and multimodal fine-tuning
//
// # Architecture
//
// The package provides:
//   - TuningService: Core service for managing fine-tuning operations
//   - TuningJob: Individual fine-tuning job configuration and execution
//   - TuningConfig: Configuration for tuning parameters and methods
//   - DatasetConfig: Training and validation dataset configuration
//   - EvaluationConfig: Evaluation metrics and validation configuration
//   - HyperparameterConfig: Learning rate, batch size, and optimization settings
//
// # Usage
//
// Basic supervised fine-tuning workflow:
//
//	service, err := tuning.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Configure training dataset
//	dataset := &tuning.DatasetConfig{
//		TrainingData: &tuning.DataSource{
//			Type: tuning.DataSourceGCS,
//			URI:  "gs://my-bucket/training_data.jsonl",
//		},
//		ValidationData: &tuning.DataSource{
//			Type: tuning.DataSourceGCS,
//			URI:  "gs://my-bucket/validation_data.jsonl",
//		},
//		DataFormat: tuning.DataFormatJSONL,
//	}
//
//	// Configure tuning parameters
//	config := &tuning.TuningConfig{
//		SourceModel:     "gemini-2.0-flash-001",
//		TuningMethod:    tuning.MethodLoRA,
//		Dataset:         dataset,
//		Hyperparameters: &tuning.HyperparameterConfig{
//			LearningRateMultiplier: 1.0,
//			Epochs:                 3,
//			AdapterSize:            16,
//		},
//		EvaluationConfig: &tuning.EvaluationConfig{
//			EvaluateSteps: 100,
//			Metrics:       []string{"loss", "accuracy", "perplexity"},
//		},
//	}
//
//	// Start fine-tuning job
//	job, err := service.CreateTuningJob(ctx, "my-tuning-job", config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Monitor training progress
//	err = service.WaitForCompletion(ctx, job.Name, 2*time.Hour)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Get the fine-tuned model
//	model, err := service.GetTunedModel(ctx, job.Name)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # LoRA Fine-Tuning
//
// Parameter-efficient fine-tuning with LoRA:
//
//	// LoRA configuration for efficient tuning
//	loraConfig := &tuning.LoRAConfig{
//		Rank:         16,    // Low-rank dimension
//		Alpha:        32,    // LoRA scaling parameter
//		DropoutRate:  0.1,   // Dropout for regularization
//		TargetModules: []string{"q_proj", "v_proj", "k_proj", "o_proj"},
//		BiasTraining: tuning.BiasNone,
//	}
//
//	config := &tuning.TuningConfig{
//		SourceModel:  "gemini-2.0-flash-001",
//		TuningMethod: tuning.MethodLoRA,
//		Dataset:      dataset,
//		LoRAConfig:   loraConfig,
//		Hyperparameters: &tuning.HyperparameterConfig{
//			LearningRate:    2e-4,
//			BatchSize:       4,
//			GradientAccumulation: 4,
//			Epochs:          3,
//			WarmupSteps:     100,
//			WeightDecay:     0.01,
//		},
//	}
//
//	job, err := service.CreateTuningJob(ctx, "lora-tuning", config)
//
// # QLoRA Fine-Tuning
//
// Memory-efficient quantized LoRA:
//
//	qloraConfig := &tuning.QLoRAConfig{
//		LoRAConfig: &tuning.LoRAConfig{
//			Rank:  16,
//			Alpha: 32,
//		},
//		QuantizationConfig: &tuning.QuantizationConfig{
//			LoadIn4Bit:          true,
//			BNB4BitComputeDtype: "float16",
//			BNB4BitQuantType:    "nf4",
//			BNB4BitUseDoubleQuant: true,
//		},
//	}
//
//	config.QLoRAConfig = qloraConfig
//	config.TuningMethod = tuning.MethodQLoRA
//
// # Dataset Configuration
//
// Configuring training datasets:
//
//	// JSONL format for text generation
//	dataset := &tuning.DatasetConfig{
//		TrainingData: &tuning.DataSource{
//			Type: tuning.DataSourceGCS,
//			URI:  "gs://bucket/train.jsonl",
//		},
//		ValidationData: &tuning.DataSource{
//			Type: tuning.DataSourceGCS,
//			URI:  "gs://bucket/val.jsonl",
//		},
//		DataFormat: tuning.DataFormatJSONL,
//		Schema: &tuning.DataSchema{
//			InputColumn:  "input_text",
//			OutputColumn: "output_text",
//		},
//	}
//
//	// CSV format for classification
//	csvDataset := &tuning.DatasetConfig{
//		TrainingData: &tuning.DataSource{
//			Type: tuning.DataSourceGCS,
//			URI:  "gs://bucket/train.csv",
//		},
//		DataFormat: tuning.DataFormatCSV,
//		Schema: &tuning.DataSchema{
//			InputColumn:  "text",
//			OutputColumn: "label",
//		},
//	}
//
//	// BigQuery dataset
//	bqDataset := &tuning.DatasetConfig{
//		TrainingData: &tuning.DataSource{
//			Type:    tuning.DataSourceBigQuery,
//			URI:     "project.dataset.training_table",
//			SQLQuery: "SELECT input_text, output_text FROM project.dataset.training_table WHERE split = 'train'",
//		},
//		DataFormat: tuning.DataFormatBigQuery,
//	}
//
// # Evaluation and Monitoring
//
// Comprehensive evaluation during training:
//
//	evalConfig := &tuning.EvaluationConfig{
//		EvaluateSteps: 100,
//		SaveSteps:     500,
//		LoggingSteps:  10,
//		Metrics: []string{
//			"loss",
//			"accuracy",
//			"perplexity",
//			"bleu",
//			"rouge",
//		},
//		EarlyStoppingPatience: 3,
//		EarlyStoppingThreshold: 0.001,
//		ValidationSplit: 0.1,
//	}
//
//	// Monitor training progress
//	progress, err := service.GetTrainingProgress(ctx, job.Name)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("Epoch: %d/%d, Loss: %.4f, Accuracy: %.4f\n",
//		progress.CurrentEpoch, progress.TotalEpochs,
//		progress.TrainingLoss, progress.ValidationAccuracy)
//
// # Hyperparameter Optimization
//
// Automated hyperparameter tuning:
//
//	hpConfig := &tuning.HyperparameterOptimizationConfig{
//		ParameterSpecs: []tuning.ParameterSpec{
//			{
//				Name:      "learning_rate",
//				Type:      tuning.ParameterTypeDouble,
//				MinValue:  1e-5,
//				MaxValue:  1e-3,
//				ScaleType: tuning.ScaleTypeLog,
//			},
//			{
//				Name:     "batch_size",
//				Type:     tuning.ParameterTypeInteger,
//				MinValue: 2,
//				MaxValue: 16,
//			},
//		},
//		MaxTrials:    20,
//		Objective:    "minimize",
//		MetricName:   "validation_loss",
//		Algorithm:    tuning.AlgorithmBayesian,
//	}
//
//	hpJob, err := service.CreateHyperparameterTuningJob(ctx, "hp-tuning", config, hpConfig)
//
// # Model Management
//
// Managing fine-tuned models:
//
//	// List all tuning jobs
//	jobs, err := service.ListTuningJobs(ctx, &tuning.ListOptions{
//		Filter: "state=SUCCEEDED",
//	})
//
//	// Get tuned model information
//	model, err := service.GetTunedModel(ctx, "my-tuning-job")
//
//	// Deploy tuned model
//	endpoint, err := service.DeployModel(ctx, model.Name, &tuning.DeploymentConfig{
//		MachineType:     "n1-standard-4",
//		MinReplicas:     1,
//		MaxReplicas:     5,
//		TrafficSplit:    100,
//	})
//
//	// Use tuned model for inference
//	response, err := service.Predict(ctx, endpoint.Name, &tuning.PredictRequest{
//		Instances: []map[string]any{
//			{"input_text": "What is machine learning?"},
//		},
//	})
//
// # Advanced Features
//
// Advanced fine-tuning capabilities:
//
//   - Multi-GPU Training: Distributed training across multiple GPUs
//   - Gradient Checkpointing: Memory optimization for large models
//   - Mixed Precision: FP16/BF16 training for faster convergence
//   - Custom Loss Functions: Domain-specific optimization objectives
//   - Curriculum Learning: Progressive difficulty in training data
//   - Knowledge Distillation: Transfer knowledge from larger models
//   - Few-Shot Learning: Effective tuning with minimal data
//
// # Data Preprocessing
//
// Built-in data preprocessing capabilities:
//
//	preprocessConfig := &tuning.PreprocessConfig{
//		Tokenization: &tuning.TokenizationConfig{
//			MaxLength:    512,
//			Truncation:   true,
//			Padding:      "max_length",
//			AddSpecialTokens: true,
//		},
//		TextProcessing: &tuning.TextProcessingConfig{
//			LowerCase:      false,
//			RemoveHTML:     true,
//			NormalizeWhitespace: true,
//		},
//		Augmentation: &tuning.AugmentationConfig{
//			SynonymReplacement: true,
//			BackTranslation:    false,
//			Paraphrasing:       true,
//		},
//	}
//
// # Performance Optimization
//
// The package provides several optimizations:
//   - Efficient data loading with parallel processing
//   - Memory-mapped datasets for large-scale training
//   - Gradient accumulation for effective large batch training
//   - Dynamic loss scaling for mixed precision training
//   - Checkpointing for fault tolerance and resumability
//   - Resource monitoring and optimization recommendations
//
// # Error Handling
//
// The package provides detailed error information for tuning operations,
// including data validation errors, resource constraint violations, and
// training convergence issues.
//
// # Thread Safety
//
// All service operations are safe for concurrent use across multiple goroutines.
// Individual tuning jobs run in isolated environments for reliability and
// resource management.
package tuning
