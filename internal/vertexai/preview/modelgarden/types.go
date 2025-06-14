// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package modelgarden

import (
	"context"
	"time"

	"github.com/go-a2a/adk-go/types"
)

// ModelCategory represents the category of a model in Model Garden.
type ModelCategory string

const (
	// ModelCategoryFoundation represents base foundation models.
	ModelCategoryFoundation ModelCategory = "foundation"

	// ModelCategoryExperimental represents experimental and preview models.
	ModelCategoryExperimental ModelCategory = "experimental"

	// ModelCategoryCommunity represents community-contributed models.
	ModelCategoryCommunity ModelCategory = "community"

	// ModelCategoryCustom represents custom user models.
	ModelCategoryCustom ModelCategory = "custom"

	// ModelCategoryMultimodal represents multimodal models.
	ModelCategoryMultimodal ModelCategory = "multimodal"

	// ModelCategorySpecialized represents task-specific models.
	ModelCategorySpecialized ModelCategory = "specialized"
)

// ModelStatus represents the status of a model in Model Garden.
type ModelStatus string

const (
	// ModelStatusAvailable indicates the model is available for deployment.
	ModelStatusAvailable ModelStatus = "available"

	// ModelStatusPreview indicates the model is in preview status.
	ModelStatusPreview ModelStatus = "preview"

	// ModelStatusExperimental indicates the model is experimental.
	ModelStatusExperimental ModelStatus = "experimental"

	// ModelStatusDeprecated indicates the model is deprecated.
	ModelStatusDeprecated ModelStatus = "deprecated"

	// ModelStatusUnavailable indicates the model is temporarily unavailable.
	ModelStatusUnavailable ModelStatus = "unavailable"
)

// DeploymentStatus represents the status of a model deployment.
type DeploymentStatus string

const (
	// DeploymentStatusCreating indicates the deployment is being created.
	DeploymentStatusCreating DeploymentStatus = "creating"

	// DeploymentStatusActive indicates the deployment is active and serving.
	DeploymentStatusActive DeploymentStatus = "active"

	// DeploymentStatusUpdating indicates the deployment is being updated.
	DeploymentStatusUpdating DeploymentStatus = "updating"

	// DeploymentStatusError indicates the deployment is in an error state.
	DeploymentStatusError DeploymentStatus = "error"

	// DeploymentStatusDeleting indicates the deployment is being deleted.
	DeploymentStatusDeleting DeploymentStatus = "deleting"
)

// ModelInfo represents comprehensive information about a model in Model Garden.
type ModelInfo struct {
	// Name is the full resource name of the model.
	// Format: publishers/{publisher}/models/{model}
	Name string `json:"name,omitempty"`

	// DisplayName is the human-readable name of the model.
	DisplayName string `json:"display_name,omitempty"`

	// Description provides a detailed description of the model.
	Description string `json:"description,omitempty"`

	// Version is the version of the model.
	Version string `json:"version,omitempty"`

	// Publisher is information about the model publisher.
	Publisher *PublisherInfo `json:"publisher,omitempty"`

	// Category is the category of the model.
	Category ModelCategory `json:"category,omitempty"`

	// Status is the current status of the model.
	Status ModelStatus `json:"status,omitempty"`

	// Capabilities describes what the model can do.
	Capabilities *ModelCapabilities `json:"capabilities,omitempty"`

	// Specifications provides technical specifications.
	Specifications *ModelSpecifications `json:"specifications,omitempty"`

	// Pricing contains pricing information for the model.
	Pricing *ModelPricing `json:"pricing,omitempty"`

	// CreateTime is when the model was added to Model Garden.
	CreateTime time.Time `json:"create_time,omitempty"`

	// UpdateTime is when the model was last updated.
	UpdateTime time.Time `json:"update_time,omitempty"`

	// Tags are labels associated with the model.
	Tags []string `json:"tags,omitempty"`

	// Metadata contains additional model metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PublisherInfo contains information about a model publisher.
type PublisherInfo struct {
	// Name is the name of the publisher.
	Name string `json:"name,omitempty"`

	// DisplayName is the human-readable publisher name.
	DisplayName string `json:"display_name,omitempty"`

	// Description describes the publisher.
	Description string `json:"description,omitempty"`

	// Website is the publisher's website URL.
	Website string `json:"website,omitempty"`

	// Contact provides contact information.
	Contact string `json:"contact,omitempty"`

	// Verified indicates if the publisher is verified.
	Verified bool `json:"verified,omitempty"`
}

// ModelCapabilities describes what a model can do.
type ModelCapabilities struct {
	// TextGeneration indicates if the model supports text generation.
	TextGeneration bool `json:"text_generation,omitempty"`

	// TextEmbedding indicates if the model supports text embeddings.
	TextEmbedding bool `json:"text_embedding,omitempty"`

	// ImageGeneration indicates if the model supports image generation.
	ImageGeneration bool `json:"image_generation,omitempty"`

	// ImageUnderstanding indicates if the model supports image understanding.
	ImageUnderstanding bool `json:"image_understanding,omitempty"`

	// AudioGeneration indicates if the model supports audio generation.
	AudioGeneration bool `json:"audio_generation,omitempty"`

	// AudioUnderstanding indicates if the model supports audio understanding.
	AudioUnderstanding bool `json:"audio_understanding,omitempty"`

	// VideoGeneration indicates if the model supports video generation.
	VideoGeneration bool `json:"video_generation,omitempty"`

	// VideoUnderstanding indicates if the model supports video understanding.
	VideoUnderstanding bool `json:"video_understanding,omitempty"`

	// FunctionCalling indicates if the model supports function calling.
	FunctionCalling bool `json:"function_calling,omitempty"`

	// CodeGeneration indicates if the model supports code generation.
	CodeGeneration bool `json:"code_generation,omitempty"`

	// FineTuning indicates if the model supports fine-tuning.
	FineTuning bool `json:"fine_tuning,omitempty"`

	// SupportedLanguages lists the languages supported by the model.
	SupportedLanguages []string `json:"supported_languages,omitempty"`

	// SupportedFormats lists the input/output formats supported.
	SupportedFormats []string `json:"supported_formats,omitempty"`
}

// ModelSpecifications provides technical specifications for a model.
type ModelSpecifications struct {
	// MaxContextLength is the maximum context length supported.
	MaxContextLength int32 `json:"max_context_length,omitempty"`

	// MaxOutputLength is the maximum output length.
	MaxOutputLength int32 `json:"max_output_length,omitempty"`

	// ParameterCount is the number of parameters in the model.
	ParameterCount int64 `json:"parameter_count,omitempty"`

	// ModelSize is the size of the model in bytes.
	ModelSize int64 `json:"model_size,omitempty"`

	// RequiredMemory is the minimum memory required for deployment.
	RequiredMemory string `json:"required_memory,omitempty"`

	// RecommendedMachineType is the recommended machine type for deployment.
	RecommendedMachineType string `json:"recommended_machine_type,omitempty"`

	// MinReplicas is the minimum number of replicas recommended.
	MinReplicas int32 `json:"min_replicas,omitempty"`

	// MaxReplicas is the maximum number of replicas supported.
	MaxReplicas int32 `json:"max_replicas,omitempty"`

	// Throughput provides throughput characteristics.
	Throughput *ThroughputSpecs `json:"throughput,omitempty"`

	// Latency provides latency characteristics.
	Latency *LatencySpecs `json:"latency,omitempty"`
}

// ThroughputSpecs describes model throughput characteristics.
type ThroughputSpecs struct {
	// TokensPerSecond is the expected tokens per second.
	TokensPerSecond float64 `json:"tokens_per_second,omitempty"`

	// RequestsPerSecond is the expected requests per second.
	RequestsPerSecond float64 `json:"requests_per_second,omitempty"`

	// MaxBatchSize is the maximum batch size supported.
	MaxBatchSize int32 `json:"max_batch_size,omitempty"`
}

// LatencySpecs describes model latency characteristics.
type LatencySpecs struct {
	// TimeToFirstToken is the time to first token in milliseconds.
	TimeToFirstToken float64 `json:"time_to_first_token,omitempty"`

	// InterTokenLatency is the inter-token latency in milliseconds.
	InterTokenLatency float64 `json:"inter_token_latency,omitempty"`

	// AverageLatency is the average end-to-end latency in milliseconds.
	AverageLatency float64 `json:"average_latency,omitempty"`
}

// ModelPricing contains pricing information for a model.
type ModelPricing struct {
	// InputPricePerToken is the price per input token.
	InputPricePerToken float64 `json:"input_price_per_token,omitempty"`

	// OutputPricePerToken is the price per output token.
	OutputPricePerToken float64 `json:"output_price_per_token,omitempty"`

	// DeploymentCostPerHour is the deployment cost per hour.
	DeploymentCostPerHour float64 `json:"deployment_cost_per_hour,omitempty"`

	// Currency is the currency for pricing (e.g., "USD").
	Currency string `json:"currency,omitempty"`

	// BillingUnit describes the billing unit (e.g., "1K tokens").
	BillingUnit string `json:"billing_unit,omitempty"`

	// FreeTier contains free tier information if available.
	FreeTier *FreeTierInfo `json:"free_tier,omitempty"`
}

// FreeTierInfo describes free tier availability for a model.
type FreeTierInfo struct {
	// Available indicates if a free tier is available.
	Available bool `json:"available,omitempty"`

	// TokenLimit is the token limit for the free tier.
	TokenLimit int64 `json:"token_limit,omitempty"`

	// TimeLimit is the time limit for the free tier.
	TimeLimit time.Duration `json:"time_limit,omitempty"`

	// RequestLimit is the request limit for the free tier.
	RequestLimit int32 `json:"request_limit,omitempty"`
}

// DeploymentInfo represents information about a model deployment.
type DeploymentInfo struct {
	// Name is the resource name of the deployment.
	// Format: projects/{project}/locations/{location}/endpoints/{endpoint}/deployedModels/{deployed_model}
	Name string `json:"name,omitempty"`

	// DisplayName is the human-readable name of the deployment.
	DisplayName string `json:"display_name,omitempty"`

	// ModelName is the name of the deployed model.
	ModelName string `json:"model_name,omitempty"`

	// ModelVersion is the version of the deployed model.
	ModelVersion string `json:"model_version,omitempty"`

	// Status is the current status of the deployment.
	Status DeploymentStatus `json:"status,omitempty"`

	// EndpointName is the name of the endpoint serving the deployment.
	EndpointName string `json:"endpoint_name,omitempty"`

	// MachineType is the machine type used for deployment.
	MachineType string `json:"machine_type,omitempty"`

	// MinReplicas is the minimum number of replicas.
	MinReplicas int32 `json:"min_replicas,omitempty"`

	// MaxReplicas is the maximum number of replicas.
	MaxReplicas int32 `json:"max_replicas,omitempty"`

	// CurrentReplicas is the current number of replicas.
	CurrentReplicas int32 `json:"current_replicas,omitempty"`

	// CreateTime is when the deployment was created.
	CreateTime time.Time `json:"create_time,omitempty"`

	// UpdateTime is when the deployment was last updated.
	UpdateTime time.Time `json:"update_time,omitempty"`

	// Config contains deployment configuration.
	Config *DeploymentConfig `json:"config,omitempty"`

	// Metrics contains deployment metrics.
	Metrics *DeploymentMetrics `json:"metrics,omitempty"`
}

// DeploymentConfig contains configuration for a model deployment.
type DeploymentConfig struct {
	// AutoScaling contains auto-scaling configuration.
	AutoScaling *AutoScalingConfig `json:"auto_scaling,omitempty"`

	// ResourceRequirements specifies resource requirements.
	ResourceRequirements *ResourceRequirements `json:"resource_requirements,omitempty"`

	// Environment contains environment variables.
	Environment map[string]string `json:"environment,omitempty"`

	// Annotations contains deployment annotations.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// AutoScalingConfig contains auto-scaling configuration.
type AutoScalingConfig struct {
	// Enabled indicates if auto-scaling is enabled.
	Enabled bool `json:"enabled,omitempty"`

	// MetricType is the metric used for scaling decisions.
	MetricType string `json:"metric_type,omitempty"`

	// TargetValue is the target value for the scaling metric.
	TargetValue float64 `json:"target_value,omitempty"`

	// ScaleUpCooldown is the cooldown period for scaling up.
	ScaleUpCooldown time.Duration `json:"scale_up_cooldown,omitempty"`

	// ScaleDownCooldown is the cooldown period for scaling down.
	ScaleDownCooldown time.Duration `json:"scale_down_cooldown,omitempty"`
}

// ResourceRequirements specifies resource requirements for deployment.
type ResourceRequirements struct {
	// CPU is the CPU requirement.
	CPU string `json:"cpu,omitempty"`

	// Memory is the memory requirement.
	Memory string `json:"memory,omitempty"`

	// GPU is the GPU requirement.
	GPU string `json:"gpu,omitempty"`

	// Storage is the storage requirement.
	Storage string `json:"storage,omitempty"`
}

// DeploymentMetrics contains metrics for a deployment.
type DeploymentMetrics struct {
	// RequestsPerSecond is the current requests per second.
	RequestsPerSecond float64 `json:"requests_per_second,omitempty"`

	// AverageLatency is the average latency in milliseconds.
	AverageLatency float64 `json:"average_latency,omitempty"`

	// ErrorRate is the current error rate as a percentage.
	ErrorRate float64 `json:"error_rate,omitempty"`

	// CPUUtilization is the current CPU utilization as a percentage.
	CPUUtilization float64 `json:"cpu_utilization,omitempty"`

	// MemoryUtilization is the current memory utilization as a percentage.
	MemoryUtilization float64 `json:"memory_utilization,omitempty"`

	// LastUpdated is when the metrics were last updated.
	LastUpdated time.Time `json:"last_updated,omitempty"`
}

// Request and Response Types

// ListModelsRequest represents a request to list models in Model Garden.
type ListModelsRequest struct {
	// PageSize is the maximum number of models to return per page.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for retrieving the next page.
	PageToken string `json:"page_token,omitempty"`

	// Filter is an optional filter expression.
	Filter string `json:"filter,omitempty"`

	// OrderBy is an optional field for ordering results.
	OrderBy string `json:"order_by,omitempty"`
}

// ListModelsResponse represents a response containing model information.
type ListModelsResponse struct {
	// Models are the model information entries.
	Models []*ModelInfo `json:"models,omitempty"`

	// NextPageToken is the token for retrieving the next page.
	NextPageToken string `json:"next_page_token,omitempty"`

	// TotalSize is the total number of models (if known).
	TotalSize int32 `json:"total_size,omitempty"`
}

// ListModelsOptions provides options for listing models.
type ListModelsOptions struct {
	// PageSize is the maximum number of models to return per page.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for retrieving a specific page.
	PageToken string `json:"page_token,omitempty"`

	// Publisher filters models by publisher.
	Publisher string `json:"publisher,omitempty"`

	// Category filters models by category.
	Category ModelCategory `json:"category,omitempty"`

	// Status filters models by status.
	Status ModelStatus `json:"status,omitempty"`

	// Tags filters models by tags.
	Tags []string `json:"tags,omitempty"`

	// Capabilities filters models by required capabilities.
	Capabilities []string `json:"capabilities,omitempty"`
}

// DeployModelRequest represents a request to deploy a model.
type DeployModelRequest struct {
	// ModelName is the name of the model to deploy.
	ModelName string `json:"model_name,omitempty"`

	// DeploymentName is the name for the deployment.
	DeploymentName string `json:"deployment_name,omitempty"`

	// MachineType is the machine type to use for deployment.
	MachineType string `json:"machine_type,omitempty"`

	// MinReplicas is the minimum number of replicas.
	MinReplicas int32 `json:"min_replicas,omitempty"`

	// MaxReplicas is the maximum number of replicas.
	MaxReplicas int32 `json:"max_replicas,omitempty"`

	// Config contains deployment configuration.
	Config *DeploymentConfig `json:"config,omitempty"`

	// DedicatedResources indicates if dedicated resources should be used.
	DedicatedResources bool `json:"dedicated_resources,omitempty"`
}

// ListDeploymentsOptions provides options for listing deployments.
type ListDeploymentsOptions struct {
	// PageSize is the maximum number of deployments to return per page.
	PageSize int32 `json:"page_size,omitempty"`

	// PageToken is the token for retrieving a specific page.
	PageToken string `json:"page_token,omitempty"`

	// Status filters deployments by status.
	Status DeploymentStatus `json:"status,omitempty"`

	// ModelName filters deployments by model name.
	ModelName string `json:"model_name,omitempty"`
}

// ListDeploymentsResponse represents a response containing deployment information.
type ListDeploymentsResponse struct {
	// Deployments are the deployment information entries.
	Deployments []*DeploymentInfo `json:"deployments,omitempty"`

	// NextPageToken is the token for retrieving the next page.
	NextPageToken string `json:"next_page_token,omitempty"`

	// TotalSize is the total number of deployments (if known).
	TotalSize int32 `json:"total_size,omitempty"`
}

// ModelGardenService defines the interface for Model Garden operations.
type ModelGardenService interface {
	// ListModels lists available models in Model Garden.
	ListModels(ctx context.Context, opts *ListModelsOptions) (*ListModelsResponse, error)

	// GetModel retrieves detailed information about a specific model.
	GetModel(ctx context.Context, modelName string) (*ModelInfo, error)

	// DeployModel deploys a model from Model Garden.
	DeployModel(ctx context.Context, req *DeployModelRequest) (*DeploymentInfo, error)

	// GetDeployment retrieves information about a specific deployment.
	GetDeployment(ctx context.Context, deploymentName string) (*DeploymentInfo, error)

	// ListDeployments lists all deployments.
	ListDeployments(ctx context.Context, opts *ListDeploymentsOptions) (*ListDeploymentsResponse, error)

	// GetDeployedModel returns a model interface for a deployed model.
	GetDeployedModel(ctx context.Context, deploymentName string) (types.Model, error)

	// UpdateDeployment updates an existing deployment.
	UpdateDeployment(ctx context.Context, deploymentName string, config *DeploymentConfig) (*DeploymentInfo, error)

	// DeleteDeployment deletes a deployment.
	DeleteDeployment(ctx context.Context, deploymentName string) error

	// Close closes the service and releases resources.
	Close() error
}
