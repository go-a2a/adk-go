// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tuning

import (
	"time"
)

// TuningMethod represents the fine-tuning method to use.
type TuningMethod string

const (
	MethodSFT          TuningMethod = "supervised_fine_tuning"
	MethodLoRA         TuningMethod = "lora"
	MethodQLoRA        TuningMethod = "qlora"
	MethodPEFT         TuningMethod = "parameter_efficient_fine_tuning"
	MethodPrefixTuning TuningMethod = "prefix_tuning"
	MethodPTuningV2    TuningMethod = "p_tuning_v2"
	MethodAdapters     TuningMethod = "adapters"
	MethodFull         TuningMethod = "full_fine_tuning"
)

// DataSourceType represents the type of data source.
type DataSourceType string

const (
	DataSourceGCS      DataSourceType = "gcs"
	DataSourceBigQuery DataSourceType = "bigquery"
	DataSourceLocal    DataSourceType = "local"
	DataSourceURL      DataSourceType = "url"
)

// DataFormat represents the format of training data.
type DataFormat string

const (
	DataFormatJSONL    DataFormat = "jsonl"
	DataFormatCSV      DataFormat = "csv"
	DataFormatTSV      DataFormat = "tsv"
	DataFormatParquet  DataFormat = "parquet"
	DataFormatBigQuery DataFormat = "bigquery"
)

// TuningJobState represents the state of a tuning job.
type TuningJobState string

const (
	StateQueued    TuningJobState = "QUEUED"
	StateRunning   TuningJobState = "RUNNING"
	StateSucceeded TuningJobState = "SUCCEEDED"
	StateFailed    TuningJobState = "FAILED"
	StateCancelled TuningJobState = "CANCELLED"
	StatePaused    TuningJobState = "PAUSED"
)

// BiasTraining represents bias training configuration for LoRA.
type BiasTraining string

const (
	BiasNone BiasTraining = "none"
	BiasAll  BiasTraining = "all"
	BiasLoRA BiasTraining = "lora_only"
)

// ParameterType represents hyperparameter types for optimization.
type ParameterType string

const (
	ParameterTypeDouble      ParameterType = "DOUBLE"
	ParameterTypeInteger     ParameterType = "INTEGER"
	ParameterTypeCategorical ParameterType = "CATEGORICAL"
	ParameterTypeDiscrete    ParameterType = "DISCRETE"
)

// ScaleType represents parameter scaling for optimization.
type ScaleType string

const (
	ScaleTypeLinear  ScaleType = "UNIT_LINEAR_SCALE"
	ScaleTypeLog     ScaleType = "UNIT_LOG_SCALE"
	ScaleTypeReverse ScaleType = "UNIT_REVERSE_LOG_SCALE"
)

// OptimizationAlgorithm represents hyperparameter optimization algorithms.
type OptimizationAlgorithm string

const (
	AlgorithmBayesian OptimizationAlgorithm = "BAYESIAN_OPTIMIZATION"
	AlgorithmGrid     OptimizationAlgorithm = "GRID_SEARCH"
	AlgorithmRandom   OptimizationAlgorithm = "RANDOM_SEARCH"
)

// DataSource represents a data source configuration.
type DataSource struct {
	// Type is the data source type
	Type DataSourceType `json:"type"`

	// URI is the data source URI (GCS path, BigQuery table, etc.)
	URI string `json:"uri"`

	// SQLQuery for BigQuery data sources
	SQLQuery string `json:"sql_query,omitempty"`

	// Headers for CSV/TSV files
	Headers bool `json:"headers,omitempty"`

	// Encoding for text files
	Encoding string `json:"encoding,omitempty"`
}

// DataSchema represents the schema for training data.
type DataSchema struct {
	// InputColumn is the column containing input text
	InputColumn string `json:"input_column"`

	// OutputColumn is the column containing target output
	OutputColumn string `json:"output_column"`

	// ContextColumn is the column containing additional context
	ContextColumn string `json:"context_column,omitempty"`

	// IDColumn is the column containing unique identifiers
	IDColumn string `json:"id_column,omitempty"`

	// WeightColumn is the column containing sample weights
	WeightColumn string `json:"weight_column,omitempty"`
}

// DatasetConfig represents dataset configuration for fine-tuning.
type DatasetConfig struct {
	// TrainingData is the training dataset
	TrainingData *DataSource `json:"training_data"`

	// ValidationData is the validation dataset
	ValidationData *DataSource `json:"validation_data,omitempty"`

	// TestData is the test dataset
	TestData *DataSource `json:"test_data,omitempty"`

	// DataFormat is the format of the data
	DataFormat DataFormat `json:"data_format"`

	// Schema defines the data schema
	Schema *DataSchema `json:"schema"`

	// PreprocessConfig defines preprocessing options
	PreprocessConfig *PreprocessConfig `json:"preprocess_config,omitempty"`

	// MaxSamples limits the number of training samples
	MaxSamples int `json:"max_samples,omitempty"`

	// ShuffleData indicates whether to shuffle training data
	ShuffleData bool `json:"shuffle_data"`

	// ValidationSplit is the fraction of training data to use for validation
	ValidationSplit float64 `json:"validation_split,omitempty"`
}

// PreprocessConfig defines data preprocessing options.
type PreprocessConfig struct {
	// Tokenization configuration
	Tokenization *TokenizationConfig `json:"tokenization,omitempty"`

	// TextProcessing configuration
	TextProcessing *TextProcessingConfig `json:"text_processing,omitempty"`

	// Augmentation configuration
	Augmentation *AugmentationConfig `json:"augmentation,omitempty"`

	// FilterConfig for data filtering
	FilterConfig *FilterConfig `json:"filter_config,omitempty"`
}

// TokenizationConfig defines tokenization settings.
type TokenizationConfig struct {
	// MaxLength is the maximum sequence length
	MaxLength int `json:"max_length"`

	// Truncation indicates whether to truncate long sequences
	Truncation bool `json:"truncation"`

	// Padding strategy
	Padding string `json:"padding"`

	// AddSpecialTokens indicates whether to add special tokens
	AddSpecialTokens bool `json:"add_special_tokens"`

	// PaddingToken for padding sequences
	PaddingToken string `json:"padding_token,omitempty"`

	// TruncationStrategy for handling long sequences
	TruncationStrategy string `json:"truncation_strategy,omitempty"`
}

// TextProcessingConfig defines text processing options.
type TextProcessingConfig struct {
	// LowerCase indicates whether to convert to lowercase
	LowerCase bool `json:"lower_case"`

	// RemoveHTML indicates whether to remove HTML tags
	RemoveHTML bool `json:"remove_html"`

	// NormalizeWhitespace indicates whether to normalize whitespace
	NormalizeWhitespace bool `json:"normalize_whitespace"`

	// RemoveEmptyLines indicates whether to remove empty lines
	RemoveEmptyLines bool `json:"remove_empty_lines"`

	// StripAccents indicates whether to remove accents
	StripAccents bool `json:"strip_accents"`
}

// AugmentationConfig defines data augmentation options.
type AugmentationConfig struct {
	// SynonymReplacement indicates whether to use synonym replacement
	SynonymReplacement bool `json:"synonym_replacement"`

	// BackTranslation indicates whether to use back translation
	BackTranslation bool `json:"back_translation"`

	// Paraphrasing indicates whether to use paraphrasing
	Paraphrasing bool `json:"paraphrasing"`

	// NoiseInjection indicates whether to inject noise
	NoiseInjection bool `json:"noise_injection"`

	// AugmentationRatio is the ratio of augmented samples
	AugmentationRatio float64 `json:"augmentation_ratio"`
}

// FilterConfig defines data filtering options.
type FilterConfig struct {
	// MinLength is the minimum text length
	MinLength int `json:"min_length,omitempty"`

	// MaxLength is the maximum text length
	MaxLength int `json:"max_length,omitempty"`

	// ExcludeProfanity indicates whether to exclude profanity
	ExcludeProfanity bool `json:"exclude_profanity"`

	// ExcludePII indicates whether to exclude personally identifiable information
	ExcludePII bool `json:"exclude_pii"`
}

// HyperparameterConfig represents hyperparameter configuration.
type HyperparameterConfig struct {
	// LearningRate is the learning rate
	LearningRate float64 `json:"learning_rate,omitempty"`

	// LearningRateMultiplier is the learning rate multiplier
	LearningRateMultiplier float64 `json:"learning_rate_multiplier,omitempty"`

	// BatchSize is the training batch size
	BatchSize int `json:"batch_size,omitempty"`

	// GradientAccumulation is the number of steps to accumulate gradients
	GradientAccumulation int `json:"gradient_accumulation,omitempty"`

	// Epochs is the number of training epochs
	Epochs int `json:"epochs,omitempty"`

	// MaxSteps is the maximum number of training steps
	MaxSteps int `json:"max_steps,omitempty"`

	// WarmupSteps is the number of warmup steps
	WarmupSteps int `json:"warmup_steps,omitempty"`

	// WarmupRatio is the warmup ratio
	WarmupRatio float64 `json:"warmup_ratio,omitempty"`

	// WeightDecay is the weight decay coefficient
	WeightDecay float64 `json:"weight_decay,omitempty"`

	// AdamEpsilon is the epsilon value for Adam optimizer
	AdamEpsilon float64 `json:"adam_epsilon,omitempty"`

	// AdamBeta1 is the beta1 value for Adam optimizer
	AdamBeta1 float64 `json:"adam_beta1,omitempty"`

	// AdamBeta2 is the beta2 value for Adam optimizer
	AdamBeta2 float64 `json:"adam_beta2,omitempty"`

	// LRScheduler is the learning rate scheduler
	LRScheduler string `json:"lr_scheduler,omitempty"`

	// AdapterSize is the adapter size for LoRA
	AdapterSize int `json:"adapter_size,omitempty"`

	// DropoutRate is the dropout rate
	DropoutRate float64 `json:"dropout_rate,omitempty"`

	// GradientClipping is the gradient clipping threshold
	GradientClipping float64 `json:"gradient_clipping,omitempty"`

	// MixedPrecision indicates whether to use mixed precision training
	MixedPrecision bool `json:"mixed_precision"`

	// Seed is the random seed for reproducibility
	Seed int `json:"seed,omitempty"`
}

// LoRAConfig represents LoRA-specific configuration.
type LoRAConfig struct {
	// Rank is the rank of LoRA adaptation
	Rank int `json:"rank"`

	// Alpha is the LoRA scaling parameter
	Alpha int `json:"alpha"`

	// DropoutRate is the dropout rate for LoRA
	DropoutRate float64 `json:"dropout_rate"`

	// TargetModules are the modules to apply LoRA to
	TargetModules []string `json:"target_modules"`

	// BiasTraining configures bias training
	BiasTraining BiasTraining `json:"bias_training"`

	// TaskType is the task type for LoRA
	TaskType string `json:"task_type,omitempty"`

	// MergePeftWeights indicates whether to merge PEFT weights
	MergePeftWeights bool `json:"merge_peft_weights"`
}

// QuantizationConfig represents quantization configuration for QLoRA.
type QuantizationConfig struct {
	// LoadIn4Bit indicates whether to load model in 4-bit
	LoadIn4Bit bool `json:"load_in_4bit"`

	// LoadIn8Bit indicates whether to load model in 8-bit
	LoadIn8Bit bool `json:"load_in_8bit"`

	// BNB4BitComputeDtype is the compute dtype for 4-bit quantization
	BNB4BitComputeDtype string `json:"bnb_4bit_compute_dtype,omitempty"`

	// BNB4BitQuantType is the quantization type for 4-bit
	BNB4BitQuantType string `json:"bnb_4bit_quant_type,omitempty"`

	// BNB4BitUseDoubleQuant indicates whether to use double quantization
	BNB4BitUseDoubleQuant bool `json:"bnb_4bit_use_double_quant"`

	// LLMIntMaxMemory is the maximum memory for quantization
	LLMIntMaxMemory map[string]string `json:"llm_int_max_memory,omitempty"`
}

// QLoRAConfig represents QLoRA-specific configuration.
type QLoRAConfig struct {
	// LoRAConfig is the underlying LoRA configuration
	LoRAConfig *LoRAConfig `json:"lora_config"`

	// QuantizationConfig is the quantization configuration
	QuantizationConfig *QuantizationConfig `json:"quantization_config"`
}

// EvaluationConfig represents evaluation configuration.
type EvaluationConfig struct {
	// EvaluateSteps is the number of steps between evaluations
	EvaluateSteps int `json:"evaluate_steps"`

	// SaveSteps is the number of steps between model saves
	SaveSteps int `json:"save_steps"`

	// LoggingSteps is the number of steps between logging
	LoggingSteps int `json:"logging_steps"`

	// Metrics are the evaluation metrics to compute
	Metrics []string `json:"metrics"`

	// EarlyStoppingPatience is the patience for early stopping
	EarlyStoppingPatience int `json:"early_stopping_patience,omitempty"`

	// EarlyStoppingThreshold is the threshold for early stopping
	EarlyStoppingThreshold float64 `json:"early_stopping_threshold,omitempty"`

	// ValidationSplit is the validation split ratio
	ValidationSplit float64 `json:"validation_split,omitempty"`

	// MetricForBestModel is the metric to use for selecting best model
	MetricForBestModel string `json:"metric_for_best_model,omitempty"`

	// GreaterIsBetter indicates whether higher metric values are better
	GreaterIsBetter bool `json:"greater_is_better"`

	// LoadBestModelAtEnd indicates whether to load best model at end
	LoadBestModelAtEnd bool `json:"load_best_model_at_end"`
}

// ResourceConfig represents compute resource configuration.
type ResourceConfig struct {
	// MachineType is the machine type for training
	MachineType string `json:"machine_type,omitempty"`

	// AcceleratorType is the accelerator type (GPU/TPU)
	AcceleratorType string `json:"accelerator_type,omitempty"`

	// AcceleratorCount is the number of accelerators
	AcceleratorCount int `json:"accelerator_count,omitempty"`

	// DiskType is the disk type
	DiskType string `json:"disk_type,omitempty"`

	// DiskSizeGB is the disk size in GB
	DiskSizeGB int `json:"disk_size_gb,omitempty"`

	// EnableCheckpointing indicates whether to enable checkpointing
	EnableCheckpointing bool `json:"enable_checkpointing"`

	// MaxRuntime is the maximum runtime for the job
	MaxRuntime time.Duration `json:"max_runtime,omitempty"`
}

// TuningConfig represents the complete tuning configuration.
type TuningConfig struct {
	// SourceModel is the base model to fine-tune
	SourceModel string `json:"source_model"`

	// TuningMethod is the fine-tuning method to use
	TuningMethod TuningMethod `json:"tuning_method"`

	// Dataset configuration
	Dataset *DatasetConfig `json:"dataset"`

	// Hyperparameters configuration
	Hyperparameters *HyperparameterConfig `json:"hyperparameters,omitempty"`

	// LoRAConfig for LoRA fine-tuning
	LoRAConfig *LoRAConfig `json:"lora_config,omitempty"`

	// QLoRAConfig for QLoRA fine-tuning
	QLoRAConfig *QLoRAConfig `json:"qlora_config,omitempty"`

	// EvaluationConfig for evaluation settings
	EvaluationConfig *EvaluationConfig `json:"evaluation_config,omitempty"`

	// ResourceConfig for compute resources
	ResourceConfig *ResourceConfig `json:"resource_config,omitempty"`

	// OutputDirectory for saving results
	OutputDirectory string `json:"output_directory,omitempty"`

	// DisplayName for the tuning job
	DisplayName string `json:"display_name,omitempty"`

	// Description of the tuning job
	Description string `json:"description,omitempty"`

	// Labels for organization
	Labels map[string]string `json:"labels,omitempty"`
}

// TuningJob represents a fine-tuning job.
type TuningJob struct {
	// Name is the unique identifier
	Name string `json:"name"`

	// DisplayName is the human-readable name
	DisplayName string `json:"display_name"`

	// Description describes the job
	Description string `json:"description"`

	// State is the current job state
	State TuningJobState `json:"state"`

	// Config is the tuning configuration
	Config *TuningConfig `json:"config"`

	// CreateTime is when the job was created
	CreateTime time.Time `json:"create_time"`

	// StartTime is when the job started
	StartTime time.Time `json:"start_time,omitzero"`

	// EndTime is when the job completed
	EndTime time.Time `json:"end_time,omitzero"`

	// UpdateTime is when the job was last updated
	UpdateTime time.Time `json:"update_time"`

	// TunedModel is the resulting model
	TunedModel *TunedModel `json:"tuned_model,omitempty"`

	// TrainingProgress contains training progress information
	TrainingProgress *TrainingProgress `json:"training_progress,omitempty"`

	// Error contains error information if the job failed
	Error string `json:"error,omitempty"`

	// Labels for organization
	Labels map[string]string `json:"labels,omitempty"`
}

// TunedModel represents a fine-tuned model.
type TunedModel struct {
	// Name is the model identifier
	Name string `json:"name"`

	// DisplayName is the human-readable name
	DisplayName string `json:"display_name"`

	// Description describes the model
	Description string `json:"description"`

	// SourceModel is the base model that was fine-tuned
	SourceModel string `json:"source_model"`

	// TuningMethod is the method used for fine-tuning
	TuningMethod TuningMethod `json:"tuning_method"`

	// ModelPath is the path to the model artifacts
	ModelPath string `json:"model_path"`

	// CreateTime is when the model was created
	CreateTime time.Time `json:"create_time"`

	// UpdateTime is when the model was last updated
	UpdateTime time.Time `json:"update_time"`

	// EvaluationMetrics contains final evaluation metrics
	EvaluationMetrics map[string]float64 `json:"evaluation_metrics,omitempty"`

	// Metadata contains additional model information
	Metadata map[string]any `json:"metadata,omitempty"`

	// Labels for organization
	Labels map[string]string `json:"labels,omitempty"`
}

// TrainingProgress represents training progress information.
type TrainingProgress struct {
	// CurrentEpoch is the current training epoch
	CurrentEpoch int `json:"current_epoch"`

	// TotalEpochs is the total number of epochs
	TotalEpochs int `json:"total_epochs"`

	// CurrentStep is the current training step
	CurrentStep int `json:"current_step"`

	// TotalSteps is the total number of steps
	TotalSteps int `json:"total_steps"`

	// TrainingLoss is the current training loss
	TrainingLoss float64 `json:"training_loss"`

	// ValidationLoss is the current validation loss
	ValidationLoss float64 `json:"validation_loss,omitempty"`

	// ValidationAccuracy is the current validation accuracy
	ValidationAccuracy float64 `json:"validation_accuracy,omitempty"`

	// LearningRate is the current learning rate
	LearningRate float64 `json:"learning_rate"`

	// ElapsedTime is the time elapsed since training started
	ElapsedTime time.Duration `json:"elapsed_time"`

	// EstimatedTimeRemaining is the estimated remaining time
	EstimatedTimeRemaining time.Duration `json:"estimated_time_remaining,omitempty"`

	// Metrics contains additional training metrics
	Metrics map[string]float64 `json:"metrics,omitempty"`

	// LastUpdateTime is when progress was last updated
	LastUpdateTime time.Time `json:"last_update_time"`
}

// ParameterSpec represents a hyperparameter specification for optimization.
type ParameterSpec struct {
	// Name is the parameter name
	Name string `json:"name"`

	// Type is the parameter type
	Type ParameterType `json:"type"`

	// MinValue is the minimum value (for numeric parameters)
	MinValue float64 `json:"min_value,omitempty"`

	// MaxValue is the maximum value (for numeric parameters)
	MaxValue float64 `json:"max_value,omitempty"`

	// ScaleType is the scaling type (for numeric parameters)
	ScaleType ScaleType `json:"scale_type,omitempty"`

	// CategoricalValues are the possible values (for categorical parameters)
	CategoricalValues []string `json:"categorical_values,omitempty"`

	// DiscreteValues are the possible values (for discrete parameters)
	DiscreteValues []float64 `json:"discrete_values,omitempty"`
}

// HyperparameterOptimizationConfig represents hyperparameter optimization configuration.
type HyperparameterOptimizationConfig struct {
	// ParameterSpecs define the parameters to optimize
	ParameterSpecs []ParameterSpec `json:"parameter_specs"`

	// MaxTrials is the maximum number of trials
	MaxTrials int `json:"max_trials"`

	// MaxParallelTrials is the maximum number of parallel trials
	MaxParallelTrials int `json:"max_parallel_trials,omitempty"`

	// Objective is the optimization objective ("minimize" or "maximize")
	Objective string `json:"objective"`

	// MetricName is the metric to optimize
	MetricName string `json:"metric_name"`

	// Algorithm is the optimization algorithm
	Algorithm OptimizationAlgorithm `json:"algorithm"`

	// EarlyStoppingConfig for early trial termination
	EarlyStoppingConfig *EarlyStoppingConfig `json:"early_stopping_config,omitempty"`
}

// EarlyStoppingConfig represents early stopping configuration.
type EarlyStoppingConfig struct {
	// UseEarlyStopping indicates whether to use early stopping
	UseEarlyStopping bool `json:"use_early_stopping"`

	// MinTrials is the minimum number of trials before early stopping
	MinTrials int `json:"min_trials,omitempty"`

	// TopTrialRatio is the ratio of top trials to consider
	TopTrialRatio float64 `json:"top_trial_ratio,omitempty"`
}

// DeploymentConfig represents model deployment configuration.
type DeploymentConfig struct {
	// MachineType is the machine type for deployment
	MachineType string `json:"machine_type"`

	// MinReplicas is the minimum number of replicas
	MinReplicas int `json:"min_replicas"`

	// MaxReplicas is the maximum number of replicas
	MaxReplicas int `json:"max_replicas"`

	// TrafficSplit is the percentage of traffic to route to this deployment
	TrafficSplit int `json:"traffic_split"`

	// AutoScaling configuration
	AutoScaling *AutoScalingConfig `json:"auto_scaling,omitempty"`

	// DeploymentName is the name for the deployment
	DeploymentName string `json:"deployment_name,omitempty"`
}

// AutoScalingConfig represents auto-scaling configuration.
type AutoScalingConfig struct {
	// MetricName is the metric to scale on
	MetricName string `json:"metric_name"`

	// TargetValue is the target value for the metric
	TargetValue float64 `json:"target_value"`

	// MinReplicas is the minimum number of replicas
	MinReplicas int `json:"min_replicas"`

	// MaxReplicas is the maximum number of replicas
	MaxReplicas int `json:"max_replicas"`
}

// PredictRequest represents a prediction request.
type PredictRequest struct {
	// Instances are the input instances
	Instances []map[string]any `json:"instances"`

	// Parameters are additional parameters
	Parameters map[string]any `json:"parameters,omitempty"`
}

// PredictResponse represents a prediction response.
type PredictResponse struct {
	// Predictions are the output predictions
	Predictions []map[string]any `json:"predictions"`

	// Metadata contains response metadata
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ListOptions defines options for listing tuning jobs.
type ListOptions struct {
	// Filter expression for filtering results
	Filter string `json:"filter,omitempty"`

	// PageSize limits the number of results per page
	PageSize int `json:"page_size,omitempty"`

	// PageToken for pagination
	PageToken string `json:"page_token,omitempty"`

	// OrderBy specifies result ordering
	OrderBy string `json:"order_by,omitempty"`
}

// Endpoint represents a deployed model endpoint.
type Endpoint struct {
	// Name is the endpoint identifier
	Name string `json:"name"`

	// DisplayName is the human-readable name
	DisplayName string `json:"display_name"`

	// Description describes the endpoint
	Description string `json:"description"`

	// PredictURL is the prediction URL
	PredictURL string `json:"predict_url"`

	// CreateTime is when the endpoint was created
	CreateTime time.Time `json:"create_time"`

	// UpdateTime is when the endpoint was last updated
	UpdateTime time.Time `json:"update_time"`

	// Labels for organization
	Labels map[string]string `json:"labels,omitempty"`
}
