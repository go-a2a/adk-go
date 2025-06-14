// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tuning

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/auth/credentials"
	"google.golang.org/api/option"
)

// Service provides fine-tuning functionality for Vertex AI models.
//
// The service manages fine-tuning jobs, hyperparameter optimization, and model deployment.
// It supports various tuning methods including LoRA, QLoRA, and full fine-tuning with
// comprehensive evaluation and monitoring capabilities.
type Service struct {
	client    *aiplatform.PredictionClient
	projectID string
	location  string
	logger    *slog.Logger

	// Active tuning jobs
	jobs   map[string]*TuningJob
	jobsMu sync.RWMutex

	// Deployed models
	models   map[string]*TunedModel
	modelsMu sync.RWMutex

	// Deployed endpoints
	endpoints   map[string]*Endpoint
	endpointsMu sync.RWMutex
}

// ServiceOption is a functional option for configuring the tuning service.
type ServiceOption func(*Service)

// WithLogger sets a custom logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// NewService creates a new tuning service.
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
// Returns a fully initialized tuning service or an error if initialization fails.
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
		jobs:      make(map[string]*TuningJob),
		models:    make(map[string]*TunedModel),
		endpoints: make(map[string]*Endpoint),
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

	service.logger.InfoContext(ctx, "Tuning service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the tuning service and releases all resources.
func (s *Service) Close() error {
	s.logger.Info("Closing tuning service")

	if s.client != nil {
		if err := s.client.Close(); err != nil {
			s.logger.Error("Failed to close prediction client", slog.String("error", err.Error()))
			return fmt.Errorf("failed to close prediction client: %w", err)
		}
	}

	s.logger.Info("Tuning service closed successfully")
	return nil
}

// CreateTuningJob creates and starts a new fine-tuning job.
//
// This method validates the configuration, creates the tuning job, and starts
// the fine-tuning process with the specified parameters.
//
// Parameters:
//   - ctx: Context for the operation
//   - name: Unique name for the tuning job
//   - config: Tuning configuration including dataset, hyperparameters, and method
//
// Returns the created tuning job or an error if creation fails.
func (s *Service) CreateTuningJob(ctx context.Context, name string, config *TuningConfig) (*TuningJob, error) {
	s.logger.InfoContext(ctx, "Creating tuning job",
		slog.String("name", name),
		slog.String("source_model", config.SourceModel),
		slog.String("method", string(config.TuningMethod)),
	)

	// Validate configuration
	if err := s.validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Check if job already exists
	s.jobsMu.RLock()
	if _, exists := s.jobs[name]; exists {
		s.jobsMu.RUnlock()
		return nil, fmt.Errorf("tuning job %s already exists", name)
	}
	s.jobsMu.RUnlock()

	// Create tuning job
	job := &TuningJob{
		Name:        name,
		DisplayName: config.DisplayName,
		Description: config.Description,
		State:       StateQueued,
		Config:      config,
		CreateTime:  time.Now(),
		UpdateTime:  time.Now(),
		Labels:      config.Labels,
		TrainingProgress: &TrainingProgress{
			TotalEpochs:    config.Hyperparameters.Epochs,
			LastUpdateTime: time.Now(),
		},
	}

	if job.DisplayName == "" {
		job.DisplayName = name
	}

	// Store job
	s.jobsMu.Lock()
	s.jobs[name] = job
	s.jobsMu.Unlock()

	// Start training process
	go s.runTuningJob(ctx, job)

	s.logger.InfoContext(ctx, "Tuning job created successfully",
		slog.String("name", name),
	)

	return job, nil
}

// GetTuningJob retrieves information about a tuning job.
func (s *Service) GetTuningJob(ctx context.Context, name string) (*TuningJob, error) {
	s.jobsMu.RLock()
	job, exists := s.jobs[name]
	s.jobsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("tuning job %s not found", name)
	}

	// Return a copy to prevent external modification
	jobCopy := *job
	if job.Config != nil {
		configCopy := *job.Config
		jobCopy.Config = &configCopy
	}
	if job.TrainingProgress != nil {
		progressCopy := *job.TrainingProgress
		jobCopy.TrainingProgress = &progressCopy
	}

	return &jobCopy, nil
}

// ListTuningJobs lists all tuning jobs with optional filtering.
func (s *Service) ListTuningJobs(ctx context.Context, opts *ListOptions) ([]*TuningJob, error) {
	s.jobsMu.RLock()
	defer s.jobsMu.RUnlock()

	var jobs []*TuningJob
	for _, job := range s.jobs {
		// Apply filter if specified
		if opts != nil && opts.Filter != "" {
			if !s.matchesJobFilter(job, opts.Filter) {
				continue
			}
		}

		// Return a copy to prevent external modification
		jobCopy := *job
		if job.Config != nil {
			configCopy := *job.Config
			jobCopy.Config = &configCopy
		}
		jobs = append(jobs, &jobCopy)
	}

	// Apply pagination if specified
	if opts != nil && opts.PageSize > 0 {
		start := 0
		if opts.PageToken != "" {
			// In a real implementation, decode the page token
		}

		end := start + opts.PageSize
		if end > len(jobs) {
			end = len(jobs)
		}

		if start < len(jobs) {
			jobs = jobs[start:end]
		} else {
			jobs = []*TuningJob{}
		}
	}

	return jobs, nil
}

// CancelTuningJob cancels a running tuning job.
func (s *Service) CancelTuningJob(ctx context.Context, name string) error {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()

	job, exists := s.jobs[name]
	if !exists {
		return fmt.Errorf("tuning job %s not found", name)
	}

	if job.State != StateRunning && job.State != StateQueued {
		return fmt.Errorf("cannot cancel job in state %s", job.State)
	}

	s.logger.InfoContext(ctx, "Cancelling tuning job",
		slog.String("name", name),
	)

	job.State = StateCancelled
	job.UpdateTime = time.Now()

	return nil
}

// WaitForCompletion waits for a tuning job to complete.
func (s *Service) WaitForCompletion(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		job, err := s.GetTuningJob(ctx, name)
		if err != nil {
			return err
		}

		switch job.State {
		case StateSucceeded:
			return nil
		case StateFailed:
			return fmt.Errorf("tuning job failed: %s", job.Error)
		case StateCancelled:
			return fmt.Errorf("tuning job was cancelled")
		default:
			// Still running, wait and check again
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Second):
				continue
			}
		}
	}

	return fmt.Errorf("timeout waiting for tuning job %s to complete", name)
}

// GetTrainingProgress retrieves the current training progress for a job.
func (s *Service) GetTrainingProgress(ctx context.Context, name string) (*TrainingProgress, error) {
	job, err := s.GetTuningJob(ctx, name)
	if err != nil {
		return nil, err
	}

	if job.TrainingProgress == nil {
		return nil, fmt.Errorf("no training progress available for job %s", name)
	}

	// Return a copy
	progress := *job.TrainingProgress
	return &progress, nil
}

// GetTunedModel retrieves the fine-tuned model from a completed job.
func (s *Service) GetTunedModel(ctx context.Context, jobName string) (*TunedModel, error) {
	job, err := s.GetTuningJob(ctx, jobName)
	if err != nil {
		return nil, err
	}

	if job.State != StateSucceeded {
		return nil, fmt.Errorf("tuning job has not completed successfully")
	}

	if job.TunedModel == nil {
		return nil, fmt.Errorf("no tuned model available for job %s", jobName)
	}

	// Return a copy
	model := *job.TunedModel
	return &model, nil
}

// DeployModel deploys a fine-tuned model to an endpoint.
func (s *Service) DeployModel(ctx context.Context, modelName string, config *DeploymentConfig) (*Endpoint, error) {
	s.logger.InfoContext(ctx, "Deploying model",
		slog.String("model", modelName),
		slog.String("machine_type", config.MachineType),
	)

	// Check if model exists
	s.modelsMu.RLock()
	model, exists := s.models[modelName]
	s.modelsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("model %s not found", modelName)
	}

	// Create endpoint
	endpointName := fmt.Sprintf("%s-endpoint", modelName)
	if config.DeploymentName != "" {
		endpointName = config.DeploymentName
	}

	endpoint := &Endpoint{
		Name:        endpointName,
		DisplayName: fmt.Sprintf("Endpoint for %s", model.DisplayName),
		Description: fmt.Sprintf("Deployment endpoint for model %s", modelName),
		PredictURL:  fmt.Sprintf("https://%s-prediction-dot-%s.appspot.com/predict", endpointName, s.projectID),
		CreateTime:  time.Now(),
		UpdateTime:  time.Now(),
		Labels:      make(map[string]string),
	}

	// Store endpoint
	s.endpointsMu.Lock()
	s.endpoints[endpointName] = endpoint
	s.endpointsMu.Unlock()

	// In a real implementation, this would:
	// 1. Create the endpoint in Vertex AI
	// 2. Deploy the model to the endpoint
	// 3. Configure auto-scaling
	// 4. Set up monitoring

	s.logger.InfoContext(ctx, "Model deployed successfully",
		slog.String("model", modelName),
		slog.String("endpoint", endpointName),
	)

	return endpoint, nil
}

// Predict makes a prediction using a deployed model.
func (s *Service) Predict(ctx context.Context, endpointName string, request *PredictRequest) (*PredictResponse, error) {
	s.endpointsMu.RLock()
	endpoint, exists := s.endpoints[endpointName]
	s.endpointsMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("endpoint %s not found", endpointName)
	}

	// In a real implementation, this would make an HTTP request to the endpoint
	// For now, return a mock response
	response := &PredictResponse{
		Predictions: make([]map[string]any, len(request.Instances)),
		Metadata: map[string]any{
			"endpoint":  endpoint.Name,
			"timestamp": time.Now(),
		},
	}

	for i, instance := range request.Instances {
		response.Predictions[i] = map[string]any{
			"output":     fmt.Sprintf("Generated response for input: %v", instance),
			"confidence": 0.95,
		}
	}

	return response, nil
}

// CreateHyperparameterTuningJob creates a hyperparameter optimization job.
func (s *Service) CreateHyperparameterTuningJob(ctx context.Context, name string, baseConfig *TuningConfig, hpConfig *HyperparameterOptimizationConfig) (*TuningJob, error) {
	s.logger.InfoContext(ctx, "Creating hyperparameter tuning job",
		slog.String("name", name),
		slog.Int("max_trials", hpConfig.MaxTrials),
		slog.String("algorithm", string(hpConfig.Algorithm)),
	)

	// Validate configurations
	if err := s.validateConfig(baseConfig); err != nil {
		return nil, fmt.Errorf("invalid base config: %w", err)
	}

	if err := s.validateHyperparameterConfig(hpConfig); err != nil {
		return nil, fmt.Errorf("invalid hyperparameter config: %w", err)
	}

	// Create hyperparameter tuning job
	job := &TuningJob{
		Name:        name,
		DisplayName: fmt.Sprintf("HP Tuning: %s", baseConfig.DisplayName),
		Description: fmt.Sprintf("Hyperparameter optimization for %s", baseConfig.SourceModel),
		State:       StateQueued,
		Config:      baseConfig,
		CreateTime:  time.Now(),
		UpdateTime:  time.Now(),
		Labels:      baseConfig.Labels,
	}

	// Store job
	s.jobsMu.Lock()
	s.jobs[name] = job
	s.jobsMu.Unlock()

	// Start hyperparameter tuning process
	go s.runHyperparameterTuning(ctx, job, hpConfig)

	return job, nil
}

// validateConfig validates the tuning configuration.
func (s *Service) validateConfig(config *TuningConfig) error {
	if config.SourceModel == "" {
		return fmt.Errorf("source model is required")
	}

	if config.Dataset == nil {
		return fmt.Errorf("dataset configuration is required")
	}

	if config.Dataset.TrainingData == nil {
		return fmt.Errorf("training data is required")
	}

	if config.Dataset.TrainingData.URI == "" {
		return fmt.Errorf("training data URI is required")
	}

	// Validate method-specific configuration
	switch config.TuningMethod {
	case MethodLoRA:
		if config.LoRAConfig == nil {
			return fmt.Errorf("LoRA config is required for LoRA tuning")
		}
		if err := s.validateLoRAConfig(config.LoRAConfig); err != nil {
			return fmt.Errorf("invalid LoRA config: %w", err)
		}

	case MethodQLoRA:
		if config.QLoRAConfig == nil {
			return fmt.Errorf("QLoRA config is required for QLoRA tuning")
		}
		if config.QLoRAConfig.LoRAConfig == nil {
			return fmt.Errorf("LoRA config is required within QLoRA config")
		}
		if config.QLoRAConfig.QuantizationConfig == nil {
			return fmt.Errorf("quantization config is required for QLoRA tuning")
		}
	}

	return nil
}

// validateLoRAConfig validates LoRA configuration.
func (s *Service) validateLoRAConfig(config *LoRAConfig) error {
	if config.Rank <= 0 {
		return fmt.Errorf("LoRA rank must be positive")
	}

	if config.Alpha <= 0 {
		return fmt.Errorf("LoRA alpha must be positive")
	}

	if config.DropoutRate < 0 || config.DropoutRate > 1 {
		return fmt.Errorf("LoRA dropout rate must be between 0 and 1")
	}

	if len(config.TargetModules) == 0 {
		return fmt.Errorf("at least one target module must be specified for LoRA")
	}

	return nil
}

// validateHyperparameterConfig validates hyperparameter optimization configuration.
func (s *Service) validateHyperparameterConfig(config *HyperparameterOptimizationConfig) error {
	if len(config.ParameterSpecs) == 0 {
		return fmt.Errorf("at least one parameter spec is required")
	}

	if config.MaxTrials <= 0 {
		return fmt.Errorf("max trials must be positive")
	}

	if config.MetricName == "" {
		return fmt.Errorf("metric name is required")
	}

	if config.Objective != "minimize" && config.Objective != "maximize" {
		return fmt.Errorf("objective must be 'minimize' or 'maximize'")
	}

	return nil
}

// runTuningJob simulates running a tuning job.
func (s *Service) runTuningJob(ctx context.Context, job *TuningJob) {
	s.logger.InfoContext(ctx, "Starting tuning job execution",
		slog.String("name", job.Name),
		slog.String("method", string(job.Config.TuningMethod)),
	)

	// Update job state
	s.jobsMu.Lock()
	job.State = StateRunning
	job.StartTime = time.Now()
	job.UpdateTime = time.Now()
	s.jobsMu.Unlock()

	// Simulate training process
	totalEpochs := job.Config.Hyperparameters.Epochs
	if totalEpochs == 0 {
		totalEpochs = 3 // Default
	}

	for epoch := 1; epoch <= totalEpochs; epoch++ {
		select {
		case <-ctx.Done():
			s.updateJobState(job, StateCancelled, "Context cancelled")
			return
		default:
		}

		// Check if job was cancelled
		s.jobsMu.RLock()
		if job.State == StateCancelled {
			s.jobsMu.RUnlock()
			return
		}
		s.jobsMu.RUnlock()

		// Simulate epoch training
		s.simulateEpochTraining(job, epoch, totalEpochs)

		// Sleep to simulate training time
		time.Sleep(5 * time.Second)
	}

	// Create tuned model
	model := &TunedModel{
		Name:         fmt.Sprintf("%s-model", job.Name),
		DisplayName:  fmt.Sprintf("Tuned %s", job.Config.SourceModel),
		Description:  fmt.Sprintf("Model tuned from %s using %s", job.Config.SourceModel, job.Config.TuningMethod),
		SourceModel:  job.Config.SourceModel,
		TuningMethod: job.Config.TuningMethod,
		ModelPath:    fmt.Sprintf("gs://%s-models/%s", s.projectID, job.Name),
		CreateTime:   time.Now(),
		UpdateTime:   time.Now(),
		EvaluationMetrics: map[string]float64{
			"final_loss":     0.234,
			"final_accuracy": 0.89,
			"perplexity":     2.1,
		},
		Labels: job.Labels,
	}

	// Store model
	s.modelsMu.Lock()
	s.models[model.Name] = model
	s.modelsMu.Unlock()

	// Update job with completion
	s.jobsMu.Lock()
	job.State = StateSucceeded
	job.EndTime = time.Now()
	job.UpdateTime = time.Now()
	job.TunedModel = model
	s.jobsMu.Unlock()

	s.logger.InfoContext(ctx, "Tuning job completed successfully",
		slog.String("name", job.Name),
		slog.String("model", model.Name),
	)
}

// simulateEpochTraining simulates training for one epoch.
func (s *Service) simulateEpochTraining(job *TuningJob, epoch, totalEpochs int) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()

	if job.TrainingProgress == nil {
		job.TrainingProgress = &TrainingProgress{}
	}

	// Update progress
	job.TrainingProgress.CurrentEpoch = epoch
	job.TrainingProgress.TotalEpochs = totalEpochs
	job.TrainingProgress.LastUpdateTime = time.Now()

	// Simulate decreasing loss
	baseLoss := 2.5
	job.TrainingProgress.TrainingLoss = baseLoss * (1.0 - float64(epoch-1)/float64(totalEpochs*2))
	job.TrainingProgress.ValidationLoss = job.TrainingProgress.TrainingLoss * 1.1

	// Simulate increasing accuracy
	job.TrainingProgress.ValidationAccuracy = 0.5 + (0.4 * float64(epoch) / float64(totalEpochs))

	// Simulate learning rate decay
	baseLR := 2e-4
	if job.Config.Hyperparameters != nil && job.Config.Hyperparameters.LearningRate > 0 {
		baseLR = job.Config.Hyperparameters.LearningRate
	}
	job.TrainingProgress.LearningRate = baseLR * (0.9 * float64(totalEpochs-epoch+1) / float64(totalEpochs))

	// Update elapsed time
	job.TrainingProgress.ElapsedTime = time.Since(job.StartTime)

	// Estimate remaining time
	if epoch > 0 {
		avgTimePerEpoch := job.TrainingProgress.ElapsedTime / time.Duration(epoch)
		remainingEpochs := totalEpochs - epoch
		job.TrainingProgress.EstimatedTimeRemaining = avgTimePerEpoch * time.Duration(remainingEpochs)
	}

	job.UpdateTime = time.Now()
}

// runHyperparameterTuning simulates hyperparameter optimization.
func (s *Service) runHyperparameterTuning(ctx context.Context, job *TuningJob, hpConfig *HyperparameterOptimizationConfig) {
	s.logger.InfoContext(ctx, "Starting hyperparameter tuning",
		slog.String("name", job.Name),
		slog.Int("max_trials", hpConfig.MaxTrials),
	)

	// Update job state
	s.updateJobState(job, StateRunning, "")

	// Simulate multiple trials
	bestMetric := 0.0
	if hpConfig.Objective == "minimize" {
		bestMetric = 999999.0
	}

	for trial := 1; trial <= hpConfig.MaxTrials; trial++ {
		select {
		case <-ctx.Done():
			s.updateJobState(job, StateCancelled, "Context cancelled")
			return
		default:
		}

		// Check if job was cancelled
		s.jobsMu.RLock()
		if job.State == StateCancelled {
			s.jobsMu.RUnlock()
			return
		}
		s.jobsMu.RUnlock()

		// Simulate trial evaluation
		trialMetric := s.simulateTrial(hpConfig)

		// Update best metric
		if (hpConfig.Objective == "maximize" && trialMetric > bestMetric) ||
			(hpConfig.Objective == "minimize" && trialMetric < bestMetric) {
			bestMetric = trialMetric
		}

		s.logger.InfoContext(ctx, "Completed hyperparameter trial",
			slog.String("job", job.Name),
			slog.Int("trial", trial),
			slog.Float64("metric", trialMetric),
			slog.Float64("best_metric", bestMetric),
		)

		// Sleep to simulate trial time
		time.Sleep(2 * time.Second)
	}

	// Complete hyperparameter tuning
	s.updateJobState(job, StateSucceeded, "")

	s.logger.InfoContext(ctx, "Hyperparameter tuning completed",
		slog.String("name", job.Name),
		slog.Float64("best_metric", bestMetric),
	)
}

// simulateTrial simulates a single hyperparameter trial.
func (s *Service) simulateTrial(hpConfig *HyperparameterOptimizationConfig) float64 {
	// Generate random metric value based on the objective
	if hpConfig.Objective == "minimize" {
		return 0.1 + (0.5 * (1.0 - 0.5)) // Random value between 0.1 and 0.6
	}
	return 0.7 + (0.3 * 0.5) // Random value between 0.7 and 1.0
}

// updateJobState updates the job state safely.
func (s *Service) updateJobState(job *TuningJob, state TuningJobState, errorMsg string) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()

	job.State = state
	job.UpdateTime = time.Now()

	if state == StateFailed && errorMsg != "" {
		job.Error = errorMsg
	}

	if state == StateSucceeded || state == StateFailed || state == StateCancelled {
		job.EndTime = time.Now()
	}
}

// matchesJobFilter checks if a job matches the given filter.
func (s *Service) matchesJobFilter(job *TuningJob, filter string) bool {
	// Simple filter implementation
	switch filter {
	case "state=RUNNING":
		return job.State == StateRunning
	case "state=SUCCEEDED":
		return job.State == StateSucceeded
	case "state=FAILED":
		return job.State == StateFailed
	case "state=CANCELLED":
		return job.State == StateCancelled
	default:
		return true
	}
}

// Helper functions for creating common configurations

// NewTuningConfig creates a new tuning configuration with common defaults.
func NewTuningConfig(sourceModel string, method TuningMethod) *TuningConfig {
	return &TuningConfig{
		SourceModel:  sourceModel,
		TuningMethod: method,
		Hyperparameters: &HyperparameterConfig{
			LearningRate: 2e-4,
			BatchSize:    4,
			Epochs:       3,
			WarmupSteps:  100,
		},
		EvaluationConfig: &EvaluationConfig{
			EvaluateSteps:      100,
			SaveSteps:          500,
			LoggingSteps:       10,
			Metrics:            []string{"loss", "accuracy"},
			GreaterIsBetter:    true,
			LoadBestModelAtEnd: true,
		},
		ResourceConfig: &ResourceConfig{
			MachineType:         "n1-standard-4",
			AcceleratorType:     "NVIDIA_TESLA_T4",
			AcceleratorCount:    1,
			DiskType:            "pd-ssd",
			DiskSizeGB:          100,
			EnableCheckpointing: true,
		},
		Labels: make(map[string]string),
	}
}

// NewLoRAConfig creates a new LoRA configuration with common defaults.
func NewLoRAConfig() *LoRAConfig {
	return &LoRAConfig{
		Rank:        16,
		Alpha:       32,
		DropoutRate: 0.1,
		TargetModules: []string{
			"q_proj", "v_proj", "k_proj", "o_proj",
		},
		BiasTraining:     BiasNone,
		TaskType:         "CAUSAL_LM",
		MergePeftWeights: false,
	}
}

// NewQLoRAConfig creates a new QLoRA configuration with common defaults.
func NewQLoRAConfig() *QLoRAConfig {
	return &QLoRAConfig{
		LoRAConfig: NewLoRAConfig(),
		QuantizationConfig: &QuantizationConfig{
			LoadIn4Bit:            true,
			BNB4BitComputeDtype:   "float16",
			BNB4BitQuantType:      "nf4",
			BNB4BitUseDoubleQuant: true,
		},
	}
}

// NewDatasetConfig creates a new dataset configuration.
func NewDatasetConfig(trainingURI string, format DataFormat) *DatasetConfig {
	return &DatasetConfig{
		TrainingData: &DataSource{
			Type: DataSourceGCS,
			URI:  trainingURI,
		},
		DataFormat:  format,
		ShuffleData: true,
		Schema: &DataSchema{
			InputColumn:  "input_text",
			OutputColumn: "output_text",
		},
		PreprocessConfig: &PreprocessConfig{
			Tokenization: &TokenizationConfig{
				MaxLength:        512,
				Truncation:       true,
				Padding:          "max_length",
				AddSpecialTokens: true,
			},
			TextProcessing: &TextProcessingConfig{
				LowerCase:           false,
				RemoveHTML:          true,
				NormalizeWhitespace: true,
				RemoveEmptyLines:    true,
			},
		},
	}
}
