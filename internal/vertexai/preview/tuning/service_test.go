// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tuning

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name      string
		projectID string
		location  string
		wantErr   bool
	}{
		{
			name:      "valid parameters",
			projectID: "test-project",
			location:  "us-central1",
			wantErr:   false,
		},
		{
			name:      "empty project ID",
			projectID: "",
			location:  "us-central1",
			wantErr:   true,
		},
		{
			name:      "empty location",
			projectID: "test-project",
			location:  "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			service, err := NewService(ctx, tt.projectID, tt.location)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if service == nil {
					t.Error("NewService() returned nil service without error")
					return
				}

				if service.projectID != tt.projectID {
					t.Errorf("NewService() projectID = %v, want %v", service.projectID, tt.projectID)
				}

				if service.location != tt.location {
					t.Errorf("NewService() location = %v, want %v", service.location, tt.location)
				}

				// Clean up
				if err := service.Close(); err != nil {
					t.Errorf("Failed to close service: %v", err)
				}
			}
		})
	}
}

func TestService_validateConfig(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name    string
		config  *TuningConfig
		wantErr bool
	}{
		{
			name: "valid SFT config",
			config: &TuningConfig{
				SourceModel:  "gemini-2.0-flash-001",
				TuningMethod: MethodSFT,
				Dataset: &DatasetConfig{
					TrainingData: &DataSource{
						Type: DataSourceGCS,
						URI:  "gs://bucket/train.jsonl",
					},
					DataFormat: DataFormatJSONL,
				},
			},
			wantErr: false,
		},
		{
			name: "valid LoRA config",
			config: &TuningConfig{
				SourceModel:  "gemini-2.0-flash-001",
				TuningMethod: MethodLoRA,
				Dataset: &DatasetConfig{
					TrainingData: &DataSource{
						Type: DataSourceGCS,
						URI:  "gs://bucket/train.jsonl",
					},
					DataFormat: DataFormatJSONL,
				},
				LoRAConfig: &LoRAConfig{
					Rank:          16,
					Alpha:         32,
					DropoutRate:   0.1,
					TargetModules: []string{"q_proj", "v_proj"},
					BiasTraining:  BiasNone,
				},
			},
			wantErr: false,
		},
		{
			name: "missing source model",
			config: &TuningConfig{
				TuningMethod: MethodSFT,
				Dataset: &DatasetConfig{
					TrainingData: &DataSource{
						Type: DataSourceGCS,
						URI:  "gs://bucket/train.jsonl",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing dataset",
			config: &TuningConfig{
				SourceModel:  "gemini-2.0-flash-001",
				TuningMethod: MethodSFT,
			},
			wantErr: true,
		},
		{
			name: "missing training data",
			config: &TuningConfig{
				SourceModel:  "gemini-2.0-flash-001",
				TuningMethod: MethodSFT,
				Dataset:      &DatasetConfig{},
			},
			wantErr: true,
		},
		{
			name: "LoRA without LoRA config",
			config: &TuningConfig{
				SourceModel:  "gemini-2.0-flash-001",
				TuningMethod: MethodLoRA,
				Dataset: &DatasetConfig{
					TrainingData: &DataSource{
						Type: DataSourceGCS,
						URI:  "gs://bucket/train.jsonl",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "QLoRA without QLoRA config",
			config: &TuningConfig{
				SourceModel:  "gemini-2.0-flash-001",
				TuningMethod: MethodQLoRA,
				Dataset: &DatasetConfig{
					TrainingData: &DataSource{
						Type: DataSourceGCS,
						URI:  "gs://bucket/train.jsonl",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_validateLoRAConfig(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name    string
		config  *LoRAConfig
		wantErr bool
	}{
		{
			name: "valid LoRA config",
			config: &LoRAConfig{
				Rank:          16,
				Alpha:         32,
				DropoutRate:   0.1,
				TargetModules: []string{"q_proj", "v_proj"},
				BiasTraining:  BiasNone,
			},
			wantErr: false,
		},
		{
			name: "zero rank",
			config: &LoRAConfig{
				Rank:          0,
				Alpha:         32,
				DropoutRate:   0.1,
				TargetModules: []string{"q_proj"},
				BiasTraining:  BiasNone,
			},
			wantErr: true,
		},
		{
			name: "negative alpha",
			config: &LoRAConfig{
				Rank:          16,
				Alpha:         -1,
				DropoutRate:   0.1,
				TargetModules: []string{"q_proj"},
				BiasTraining:  BiasNone,
			},
			wantErr: true,
		},
		{
			name: "invalid dropout rate",
			config: &LoRAConfig{
				Rank:          16,
				Alpha:         32,
				DropoutRate:   1.5,
				TargetModules: []string{"q_proj"},
				BiasTraining:  BiasNone,
			},
			wantErr: true,
		},
		{
			name: "no target modules",
			config: &LoRAConfig{
				Rank:         16,
				Alpha:        32,
				DropoutRate:  0.1,
				BiasTraining: BiasNone,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateLoRAConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateLoRAConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_CreateTuningJob(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	config := NewTuningConfig("gemini-2.0-flash-001", MethodLoRA)
	config.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)
	config.LoRAConfig = NewLoRAConfig()

	job, err := service.CreateTuningJob(ctx, "test-job", config)
	if err != nil {
		t.Fatalf("CreateTuningJob() error = %v", err)
	}

	if job.Name != "test-job" {
		t.Errorf("CreateTuningJob() name = %v, want test-job", job.Name)
	}

	if job.State != StateQueued {
		t.Errorf("CreateTuningJob() state = %v, want %v", job.State, StateQueued)
	}

	if job.Config.SourceModel != config.SourceModel {
		t.Errorf("CreateTuningJob() source model = %v, want %v", job.Config.SourceModel, config.SourceModel)
	}

	// Check that job is stored
	service.jobsMu.RLock()
	_, exists := service.jobs["test-job"]
	service.jobsMu.RUnlock()

	if !exists {
		t.Error("Job was not stored in jobs registry")
	}

	// Test creating duplicate job
	_, err = service.CreateTuningJob(ctx, "test-job", config)
	if err == nil {
		t.Error("CreateTuningJob() should return error for duplicate job name")
	}
}

func TestService_GetTuningJob(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create a job first
	config := NewTuningConfig("gemini-2.0-flash-001", MethodSFT)
	config.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)

	createdJob, err := service.CreateTuningJob(ctx, "test-job", config)
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	// Get the job
	retrievedJob, err := service.GetTuningJob(ctx, "test-job")
	if err != nil {
		t.Fatalf("GetTuningJob() error = %v", err)
	}

	if retrievedJob.Name != createdJob.Name {
		t.Errorf("GetTuningJob() name = %v, want %v", retrievedJob.Name, createdJob.Name)
	}

	if retrievedJob.Config.SourceModel != createdJob.Config.SourceModel {
		t.Errorf("GetTuningJob() source model = %v, want %v",
			retrievedJob.Config.SourceModel, createdJob.Config.SourceModel)
	}

	// Test getting non-existent job
	_, err = service.GetTuningJob(ctx, "non-existent")
	if err == nil {
		t.Error("GetTuningJob() should return error for non-existent job")
	}
}

func TestService_ListTuningJobs(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create multiple jobs
	configs := []struct {
		name   string
		method TuningMethod
	}{
		{"job-1", MethodSFT},
		{"job-2", MethodLoRA},
		{"job-3", MethodQLoRA},
	}

	for _, cfg := range configs {
		config := NewTuningConfig("gemini-2.0-flash-001", cfg.method)
		config.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)

		if cfg.method == MethodLoRA {
			config.LoRAConfig = NewLoRAConfig()
		}
		if cfg.method == MethodQLoRA {
			config.QLoRAConfig = NewQLoRAConfig()
		}

		_, err := service.CreateTuningJob(ctx, cfg.name, config)
		if err != nil {
			t.Fatalf("Failed to create job %s: %v", cfg.name, err)
		}
	}

	// List all jobs
	jobs, err := service.ListTuningJobs(ctx, nil)
	if err != nil {
		t.Fatalf("ListTuningJobs() error = %v", err)
	}

	if len(jobs) != 3 {
		t.Errorf("ListTuningJobs() returned %d jobs, want 3", len(jobs))
	}

	// Test with filter
	opts := &ListOptions{
		Filter: "state=QUEUED",
	}

	filteredJobs, err := service.ListTuningJobs(ctx, opts)
	if err != nil {
		t.Fatalf("ListTuningJobs() with filter error = %v", err)
	}

	if len(filteredJobs) != 3 {
		t.Errorf("ListTuningJobs() with filter returned %d jobs, want 3", len(filteredJobs))
	}

	// Test with pagination
	paginatedOpts := &ListOptions{
		PageSize: 2,
	}

	paginatedJobs, err := service.ListTuningJobs(ctx, paginatedOpts)
	if err != nil {
		t.Fatalf("ListTuningJobs() with pagination error = %v", err)
	}

	if len(paginatedJobs) != 2 {
		t.Errorf("ListTuningJobs() with pagination returned %d jobs, want 2", len(paginatedJobs))
	}
}

func TestService_CancelTuningJob(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create a job
	config := NewTuningConfig("gemini-2.0-flash-001", MethodSFT)
	config.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)

	_, err = service.CreateTuningJob(ctx, "test-job", config)
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	// Cancel the job
	err = service.CancelTuningJob(ctx, "test-job")
	if err != nil {
		t.Fatalf("CancelTuningJob() error = %v", err)
	}

	// Check job state
	job, err := service.GetTuningJob(ctx, "test-job")
	if err != nil {
		t.Fatalf("Failed to get job after cancellation: %v", err)
	}

	if job.State != StateCancelled {
		t.Errorf("CancelTuningJob() state = %v, want %v", job.State, StateCancelled)
	}

	// Test cancelling non-existent job
	err = service.CancelTuningJob(ctx, "non-existent")
	if err == nil {
		t.Error("CancelTuningJob() should return error for non-existent job")
	}
}

func TestService_WaitForCompletion(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create a job with fast completion
	config := NewTuningConfig("gemini-2.0-flash-001", MethodSFT)
	config.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)
	config.Hyperparameters.Epochs = 1

	job, err := service.CreateTuningJob(ctx, "fast-job", config)
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	// Wait for completion with reasonable timeout
	err = service.WaitForCompletion(ctx, job.Name, 30*time.Second)
	if err != nil {
		t.Errorf("WaitForCompletion() error = %v", err)
	}

	// Check final state
	finalJob, err := service.GetTuningJob(ctx, job.Name)
	if err != nil {
		t.Fatalf("Failed to get final job state: %v", err)
	}

	if finalJob.State != StateSucceeded {
		t.Errorf("WaitForCompletion() final state = %v, want %v", finalJob.State, StateSucceeded)
	}

	// Test timeout
	err = service.WaitForCompletion(ctx, "non-existent", 1*time.Second)
	if err == nil {
		t.Error("WaitForCompletion() should return error for non-existent job")
	}
}

func TestService_GetTrainingProgress(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create a job
	config := NewTuningConfig("gemini-2.0-flash-001", MethodSFT)
	config.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)

	job, err := service.CreateTuningJob(ctx, "progress-job", config)
	if err != nil {
		t.Fatalf("Failed to create job: %v", err)
	}

	// Wait a bit for training to start
	time.Sleep(1 * time.Second)

	// Get training progress
	progress, err := service.GetTrainingProgress(ctx, job.Name)
	if err != nil {
		t.Fatalf("GetTrainingProgress() error = %v", err)
	}

	if progress.TotalEpochs != 3 {
		t.Errorf("GetTrainingProgress() total epochs = %v, want 3", progress.TotalEpochs)
	}

	if progress.LastUpdateTime.IsZero() {
		t.Error("GetTrainingProgress() should have last update time")
	}

	// Test with non-existent job
	_, err = service.GetTrainingProgress(ctx, "non-existent")
	if err == nil {
		t.Error("GetTrainingProgress() should return error for non-existent job")
	}
}

func TestService_CreateHyperparameterTuningJob(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Base configuration
	baseConfig := NewTuningConfig("gemini-2.0-flash-001", MethodLoRA)
	baseConfig.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)
	baseConfig.LoRAConfig = NewLoRAConfig()

	// Hyperparameter optimization configuration
	hpConfig := &HyperparameterOptimizationConfig{
		ParameterSpecs: []ParameterSpec{
			{
				Name:      "learning_rate",
				Type:      ParameterTypeDouble,
				MinValue:  1e-5,
				MaxValue:  1e-3,
				ScaleType: ScaleTypeLog,
			},
			{
				Name:     "batch_size",
				Type:     ParameterTypeInteger,
				MinValue: 2,
				MaxValue: 16,
			},
		},
		MaxTrials:  5,
		Objective:  "maximize",
		MetricName: "accuracy",
		Algorithm:  AlgorithmBayesian,
	}

	// Create hyperparameter tuning job
	job, err := service.CreateHyperparameterTuningJob(ctx, "hp-job", baseConfig, hpConfig)
	if err != nil {
		t.Fatalf("CreateHyperparameterTuningJob() error = %v", err)
	}

	if job.Name != "hp-job" {
		t.Errorf("CreateHyperparameterTuningJob() name = %v, want hp-job", job.Name)
	}

	if job.State != StateQueued {
		t.Errorf("CreateHyperparameterTuningJob() state = %v, want %v", job.State, StateQueued)
	}

	// Wait a bit and check that job is running
	time.Sleep(1 * time.Second)

	updatedJob, err := service.GetTuningJob(ctx, "hp-job")
	if err != nil {
		t.Fatalf("Failed to get updated job: %v", err)
	}

	if updatedJob.State != StateRunning {
		t.Errorf("Hyperparameter job should be running, got state %v", updatedJob.State)
	}
}

func TestNewTuningConfig(t *testing.T) {
	config := NewTuningConfig("gemini-2.0-flash-001", MethodLoRA)

	if config.SourceModel != "gemini-2.0-flash-001" {
		t.Errorf("NewTuningConfig() source model = %v, want gemini-2.0-flash-001", config.SourceModel)
	}

	if config.TuningMethod != MethodLoRA {
		t.Errorf("NewTuningConfig() method = %v, want %v", config.TuningMethod, MethodLoRA)
	}

	if config.Hyperparameters == nil {
		t.Error("NewTuningConfig() should set default hyperparameters")
	}

	if config.Hyperparameters.LearningRate != 2e-4 {
		t.Errorf("NewTuningConfig() learning rate = %v, want 2e-4", config.Hyperparameters.LearningRate)
	}

	if config.EvaluationConfig == nil {
		t.Error("NewTuningConfig() should set default evaluation config")
	}

	if config.ResourceConfig == nil {
		t.Error("NewTuningConfig() should set default resource config")
	}
}

func TestNewLoRAConfig(t *testing.T) {
	config := NewLoRAConfig()

	if config.Rank != 16 {
		t.Errorf("NewLoRAConfig() rank = %v, want 16", config.Rank)
	}

	if config.Alpha != 32 {
		t.Errorf("NewLoRAConfig() alpha = %v, want 32", config.Alpha)
	}

	if config.DropoutRate != 0.1 {
		t.Errorf("NewLoRAConfig() dropout rate = %v, want 0.1", config.DropoutRate)
	}

	expectedModules := []string{"q_proj", "v_proj", "k_proj", "o_proj"}
	if diff := cmp.Diff(expectedModules, config.TargetModules); diff != "" {
		t.Errorf("NewLoRAConfig() target modules mismatch (-want +got):\n%s", diff)
	}

	if config.BiasTraining != BiasNone {
		t.Errorf("NewLoRAConfig() bias training = %v, want %v", config.BiasTraining, BiasNone)
	}
}

func TestNewQLoRAConfig(t *testing.T) {
	config := NewQLoRAConfig()

	if config.LoRAConfig == nil {
		t.Error("NewQLoRAConfig() should set LoRA config")
	}

	if config.QuantizationConfig == nil {
		t.Error("NewQLoRAConfig() should set quantization config")
	}

	if !config.QuantizationConfig.LoadIn4Bit {
		t.Error("NewQLoRAConfig() should enable 4-bit loading")
	}

	if config.QuantizationConfig.BNB4BitComputeDtype != "float16" {
		t.Errorf("NewQLoRAConfig() compute dtype = %v, want float16",
			config.QuantizationConfig.BNB4BitComputeDtype)
	}
}

func TestNewDatasetConfig(t *testing.T) {
	config := NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)

	if config.TrainingData == nil {
		t.Error("NewDatasetConfig() should set training data")
	}

	if config.TrainingData.URI != "gs://test-bucket/train.jsonl" {
		t.Errorf("NewDatasetConfig() URI = %v, want gs://test-bucket/train.jsonl",
			config.TrainingData.URI)
	}

	if config.DataFormat != DataFormatJSONL {
		t.Errorf("NewDatasetConfig() format = %v, want %v", config.DataFormat, DataFormatJSONL)
	}

	if !config.ShuffleData {
		t.Error("NewDatasetConfig() should enable data shuffling")
	}

	if config.Schema == nil {
		t.Error("NewDatasetConfig() should set default schema")
	}

	if config.PreprocessConfig == nil {
		t.Error("NewDatasetConfig() should set default preprocessing config")
	}
}

func TestService_simulateEpochTraining(t *testing.T) {
	service := &Service{}

	job := &TuningJob{
		Name:             "test-job",
		StartTime:        time.Now().Add(-10 * time.Second),
		TrainingProgress: &TrainingProgress{},
	}

	totalEpochs := 3
	epoch := 2

	service.simulateEpochTraining(job, epoch, totalEpochs)

	if job.TrainingProgress.CurrentEpoch != epoch {
		t.Errorf("simulateEpochTraining() current epoch = %v, want %v",
			job.TrainingProgress.CurrentEpoch, epoch)
	}

	if job.TrainingProgress.TotalEpochs != totalEpochs {
		t.Errorf("simulateEpochTraining() total epochs = %v, want %v",
			job.TrainingProgress.TotalEpochs, totalEpochs)
	}

	if job.TrainingProgress.TrainingLoss <= 0 {
		t.Error("simulateEpochTraining() should set positive training loss")
	}

	if job.TrainingProgress.ValidationAccuracy <= 0 {
		t.Error("simulateEpochTraining() should set positive validation accuracy")
	}

	if job.TrainingProgress.LearningRate <= 0 {
		t.Error("simulateEpochTraining() should set positive learning rate")
	}

	if job.TrainingProgress.ElapsedTime <= 0 {
		t.Error("simulateEpochTraining() should set positive elapsed time")
	}
}

func TestService_matchesJobFilter(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name     string
		job      *TuningJob
		filter   string
		expected bool
	}{
		{
			name:     "running job matches running filter",
			job:      &TuningJob{State: StateRunning},
			filter:   "state=RUNNING",
			expected: true,
		},
		{
			name:     "succeeded job matches succeeded filter",
			job:      &TuningJob{State: StateSucceeded},
			filter:   "state=SUCCEEDED",
			expected: true,
		},
		{
			name:     "failed job matches failed filter",
			job:      &TuningJob{State: StateFailed},
			filter:   "state=FAILED",
			expected: true,
		},
		{
			name:     "cancelled job matches cancelled filter",
			job:      &TuningJob{State: StateCancelled},
			filter:   "state=CANCELLED",
			expected: true,
		},
		{
			name:     "running job does not match succeeded filter",
			job:      &TuningJob{State: StateRunning},
			filter:   "state=SUCCEEDED",
			expected: false,
		},
		{
			name:     "no filter matches all",
			job:      &TuningJob{State: StateRunning},
			filter:   "",
			expected: true,
		},
		{
			name:     "unknown filter matches all",
			job:      &TuningJob{State: StateRunning},
			filter:   "unknown=value",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.matchesJobFilter(tt.job, tt.filter)
			if result != tt.expected {
				t.Errorf("matchesJobFilter() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkService_CreateTuningJob(b *testing.B) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		b.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	config := NewTuningConfig("gemini-2.0-flash-001", MethodSFT)
	config.Dataset = NewDatasetConfig("gs://test-bucket/train.jsonl", DataFormatJSONL)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jobName := fmt.Sprintf("bench-job-%d", i)
		_, err := service.CreateTuningJob(ctx, jobName, config)
		if err != nil {
			b.Fatalf("CreateTuningJob() error = %v", err)
		}
	}
}

func BenchmarkService_simulateEpochTraining(b *testing.B) {
	service := &Service{}
	job := &TuningJob{
		Name:             "bench-job",
		StartTime:        time.Now(),
		TrainingProgress: &TrainingProgress{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.simulateEpochTraining(job, 1, 3)
	}
}

// Integration test that would require actual API keys (skipped by default)
func TestService_Integration(t *testing.T) {
	t.Skip("Integration test requires API keys - enable manually for testing")

	ctx := context.Background()
	service, err := NewService(ctx, "your-project-id", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create a simple tuning job
	config := NewTuningConfig("gemini-2.0-flash-001", MethodLoRA)
	config.Dataset = NewDatasetConfig("gs://your-bucket/train.jsonl", DataFormatJSONL)
	config.LoRAConfig = NewLoRAConfig()
	config.Hyperparameters.Epochs = 1 // Quick test

	job, err := service.CreateTuningJob(ctx, "integration-test", config)
	if err != nil {
		t.Fatalf("Failed to create tuning job: %v", err)
	}

	// Wait for completion
	err = service.WaitForCompletion(ctx, job.Name, 10*time.Minute)
	if err != nil {
		t.Fatalf("Failed to wait for completion: %v", err)
	}

	// Get the tuned model
	model, err := service.GetTunedModel(ctx, job.Name)
	if err != nil {
		t.Fatalf("Failed to get tuned model: %v", err)
	}

	if model.Name == "" {
		t.Error("Tuned model should have a name")
	}

	// Deploy the model
	deployConfig := &DeploymentConfig{
		MachineType:  "n1-standard-2",
		MinReplicas:  1,
		MaxReplicas:  3,
		TrafficSplit: 100,
	}

	endpoint, err := service.DeployModel(ctx, model.Name, deployConfig)
	if err != nil {
		t.Fatalf("Failed to deploy model: %v", err)
	}

	// Make a prediction
	request := &PredictRequest{
		Instances: []map[string]any{
			{"input_text": "Hello, how are you?"},
		},
	}

	response, err := service.Predict(ctx, endpoint.Name, request)
	if err != nil {
		t.Fatalf("Failed to make prediction: %v", err)
	}

	if len(response.Predictions) == 0 {
		t.Error("Prediction response should contain predictions")
	}

	t.Logf("Integration test completed successfully. Model: %s, Endpoint: %s",
		model.Name, endpoint.Name)
}
