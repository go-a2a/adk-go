// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package generativemodels

import (
	"context"
	"iter"
	"time"

	"google.golang.org/genai"
)

// PreviewGenerateRequest extends the standard GenerateContentRequest with preview features.
//
// This request type provides access to experimental and preview capabilities
// that are not available in the standard Vertex AI API.
type PreviewGenerateRequest struct {
	// Contents are the input contents for generation.
	Contents []*genai.Content `json:"contents,omitempty"`

	// Tools are the tools available to the model.
	Tools []*genai.Tool `json:"tools,omitempty"`

	// SystemInstruction is the system instruction for the model.
	SystemInstruction *genai.Content `json:"system_instruction,omitempty"`

	// GenerationConfig contains configuration for generation.
	GenerationConfig *genai.GenerationConfig `json:"generation_config,omitempty"`

	// SafetySettings contains safety configuration.
	SafetySettings []*genai.SafetySetting `json:"safety_settings,omitempty"`

	// UseContentCache indicates whether to use content caching for this request.
	UseContentCache bool `json:"use_content_cache,omitempty"`

	// CacheID is the resource name of the cached content to use.
	// Format: projects/{project}/locations/{location}/cachedContents/{cached_content}
	CacheID string `json:"cache_id,omitempty"`

	// EnhancedSafety provides advanced safety configuration options.
	EnhancedSafety *SafetyConfig `json:"enhanced_safety,omitempty"`

	// ExperimentalOpts contains experimental options for model generation.
	// These options are subject to change and may not be available in all models.
	ExperimentalOpts map[string]any `json:"experimental_opts,omitempty"`

	// AdvancedToolConfig provides enhanced tool calling configuration.
	AdvancedToolConfig *AdvancedToolConfig `json:"advanced_tool_config,omitempty"`

	// ResponseFormat specifies the desired response format for structured output.
	ResponseFormat *ResponseFormat `json:"response_format,omitempty"`

	// PreviewModelParams contains model-specific preview parameters.
	PreviewModelParams *PreviewModelParams `json:"preview_model_params,omitempty"`
}

// PreviewGenerateResponse extends the standard GenerateContentResponse with preview features.
type PreviewGenerateResponse struct {
	// Candidates are the response candidates.
	Candidates []*genai.Candidate `json:"candidates,omitempty"`

	// UsageMetadata contains token usage information.
	UsageMetadata *genai.UsageMetadata `json:"usage_metadata,omitempty"`

	// CacheHit indicates whether the response used cached content.
	CacheHit bool `json:"cache_hit,omitempty"`

	// CacheID is the ID of the cache used (if any).
	CacheID string `json:"cache_id,omitempty"`

	// SafetyMetadata contains detailed safety evaluation results.
	SafetyMetadata *SafetyMetadata `json:"safety_metadata,omitempty"`

	// ModelMetadata contains metadata about the model used for generation.
	ModelMetadata *ModelMetadata `json:"model_metadata,omitempty"`

	// ExperimentalMetadata contains experimental metadata from preview features.
	ExperimentalMetadata map[string]any `json:"experimental_metadata,omitempty"`
}

// SafetyConfig provides enhanced safety configuration options.
type SafetyConfig struct {
	// StrictMode enables the most restrictive safety settings.
	StrictMode bool `json:"strict_mode,omitempty"`

	// CustomThresholds allows custom safety thresholds for specific categories.
	CustomThresholds map[string]string `json:"custom_thresholds,omitempty"`

	// EnableAdvancedDetection enables experimental safety detection features.
	EnableAdvancedDetection bool `json:"enable_advanced_detection,omitempty"`

	// SafetyFilters specifies additional safety filters to apply.
	SafetyFilters []string `json:"safety_filters,omitempty"`

	// AllowedCategories specifies categories that are explicitly allowed.
	AllowedCategories []string `json:"allowed_categories,omitempty"`

	// BlockedCategories specifies categories that are explicitly blocked.
	BlockedCategories []string `json:"blocked_categories,omitempty"`
}

// SafetyMetadata contains detailed safety evaluation results.
type SafetyMetadata struct {
	// CategoryScores contains safety scores for each category.
	CategoryScores map[string]float64 `json:"category_scores,omitempty"`

	// FilteredReasons contains reasons why content was filtered (if any).
	FilteredReasons []string `json:"filtered_reasons,omitempty"`

	// SafetyLevel indicates the overall safety level of the response.
	SafetyLevel string `json:"safety_level,omitempty"`

	// AdvancedDetections contains results from advanced safety detection.
	AdvancedDetections map[string]any `json:"advanced_detections,omitempty"`
}

// AdvancedToolConfig provides enhanced tool calling configuration.
type AdvancedToolConfig struct {
	// ParallelCalling enables parallel execution of tool calls.
	ParallelCalling bool `json:"parallel_calling,omitempty"`

	// MaxConcurrency limits the number of concurrent tool calls.
	MaxConcurrency int `json:"max_concurrency,omitempty"`

	// TimeoutPerTool sets the timeout for individual tool calls.
	TimeoutPerTool time.Duration `json:"timeout_per_tool,omitempty"`

	// RetryPolicy specifies retry behavior for failed tool calls.
	RetryPolicy *ToolRetryPolicy `json:"retry_policy,omitempty"`

	// ToolSelection specifies which tools can be called in this request.
	ToolSelection *ToolSelection `json:"tool_selection,omitempty"`
}

// ToolRetryPolicy defines retry behavior for tool calls.
type ToolRetryPolicy struct {
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int `json:"max_retries,omitempty"`

	// BackoffMultiplier is the backoff multiplier for retry delays.
	BackoffMultiplier float64 `json:"backoff_multiplier,omitempty"`

	// InitialDelay is the initial delay before the first retry.
	InitialDelay time.Duration `json:"initial_delay,omitempty"`

	// MaxDelay is the maximum delay between retries.
	MaxDelay time.Duration `json:"max_delay,omitempty"`
}

// ToolSelection specifies which tools can be called.
type ToolSelection struct {
	// AllowedTools contains names of tools that can be called.
	AllowedTools []string `json:"allowed_tools,omitempty"`

	// BlockedTools contains names of tools that cannot be called.
	BlockedTools []string `json:"blocked_tools,omitempty"`

	// RequiredTools contains names of tools that must be available.
	RequiredTools []string `json:"required_tools,omitempty"`
}

// ResponseFormat specifies the desired response format for structured output.
type ResponseFormat struct {
	// Type specifies the response format type (e.g., "json", "text", "structured").
	Type string `json:"type,omitempty"`

	// Schema provides a JSON schema for structured responses.
	Schema map[string]any `json:"schema,omitempty"`

	// StrictValidation enables strict validation against the schema.
	StrictValidation bool `json:"strict_validation,omitempty"`
}

// PreviewModelParams contains model-specific preview parameters.
type PreviewModelParams struct {
	// ExperimentalFeatures enables specific experimental features by name.
	ExperimentalFeatures []string `json:"experimental_features,omitempty"`

	// ModelVariant specifies a specific model variant to use.
	ModelVariant string `json:"model_variant,omitempty"`

	// CustomParameters contains custom model parameters.
	CustomParameters map[string]any `json:"custom_parameters,omitempty"`

	// PerformanceMode specifies performance optimization mode.
	PerformanceMode string `json:"performance_mode,omitempty"`
}

// ModelMetadata contains metadata about the model used for generation.
type ModelMetadata struct {
	// ModelName is the name of the model used.
	ModelName string `json:"model_name,omitempty"`

	// ModelVersion is the version of the model used.
	ModelVersion string `json:"model_version,omitempty"`

	// ModelType indicates the type of model (e.g., "base", "fine_tuned", "experimental").
	ModelType string `json:"model_type,omitempty"`

	// Capabilities lists the capabilities supported by this model.
	Capabilities []string `json:"capabilities,omitempty"`

	// Limitations lists any limitations of this model version.
	Limitations []string `json:"limitations,omitempty"`
}

// TokenCountRequest represents a request to count tokens with preview features.
type TokenCountRequest struct {
	// Contents are the content pieces to count tokens for.
	Contents []*genai.Content `json:"contents,omitempty"`

	// Model is the name of the model to use for token counting.
	Model string `json:"model,omitempty"`

	// UseContentCache indicates whether to use cached content for counting.
	UseContentCache bool `json:"use_content_cache,omitempty"`

	// CacheID is the resource name of the cached content to use.
	CacheID string `json:"cache_id,omitempty"`
}

// TokenCountResponse represents a response containing token count information.
type TokenCountResponse struct {
	// TotalTokens is the total number of tokens.
	TotalTokens int32 `json:"total_tokens,omitempty"`

	// CachedTokens is the number of tokens that were cached.
	CachedTokens int32 `json:"cached_tokens,omitempty"`

	// BillableTokens is the number of tokens that will be billed.
	BillableTokens int32 `json:"billable_tokens,omitempty"`

	// TokenBreakdown provides detailed token breakdown by content type.
	TokenBreakdown map[string]int32 `json:"token_breakdown,omitempty"`
}

// ToolGenerateRequest represents a request for enhanced tool calling.
type ToolGenerateRequest struct {
	// PreviewGenerateRequest is the base request.
	*PreviewGenerateRequest

	// Tools are the tools available for the model to call.
	Tools []*genai.Tool `json:"tools,omitempty"`

	// ForcedToolCall specifies a specific tool that must be called.
	ForcedToolCall *ForcedToolCall `json:"forced_tool_call,omitempty"`
}

// ForcedToolCall specifies a tool that must be called.
type ForcedToolCall struct {
	// ToolName is the name of the tool to call.
	ToolName string `json:"tool_name,omitempty"`

	// Parameters are the parameters to pass to the tool.
	Parameters map[string]any `json:"parameters,omitempty"`
}

// ToolGenerateResponse represents a response from enhanced tool calling.
type ToolGenerateResponse struct {
	// PreviewGenerateResponse is the base response.
	*PreviewGenerateResponse

	// ToolCalls contains information about tool calls made.
	ToolCalls []*ToolCallMetadata `json:"tool_calls,omitempty"`

	// ToolResults contains the results of tool calls.
	ToolResults []*ToolResult `json:"tool_results,omitempty"`
}

// ToolCallMetadata contains metadata about a tool call.
type ToolCallMetadata struct {
	// ToolName is the name of the tool that was called.
	ToolName string `json:"tool_name,omitempty"`

	// CallID is a unique identifier for this tool call.
	CallID string `json:"call_id,omitempty"`

	// StartTime is when the tool call started.
	StartTime time.Time `json:"start_time,omitempty"`

	// EndTime is when the tool call completed.
	EndTime time.Time `json:"end_time,omitempty"`

	// Success indicates whether the tool call was successful.
	Success bool `json:"success,omitempty"`

	// Error contains error information if the tool call failed.
	Error string `json:"error,omitempty"`
}

// ToolResult contains the result of a tool call.
type ToolResult struct {
	// CallID is the identifier of the tool call this result belongs to.
	CallID string `json:"call_id,omitempty"`

	// Result is the result data from the tool call.
	Result any `json:"result,omitempty"`

	// Metadata contains additional metadata about the result.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// StreamingConfig provides configuration for streaming responses.
type StreamingConfig struct {
	// BufferSize is the size of the streaming buffer.
	BufferSize int `json:"buffer_size,omitempty"`

	// FlushInterval is the interval for flushing streaming responses.
	FlushInterval time.Duration `json:"flush_interval,omitempty"`

	// EnablePartialResults enables streaming of partial results.
	EnablePartialResults bool `json:"enable_partial_results,omitempty"`
}

// PreviewGenerativeModelService defines the interface for preview generative model operations.
type PreviewGenerativeModelService interface {
	// GenerateContentWithPreview generates content with preview features.
	GenerateContentWithPreview(ctx context.Context, modelName string, req *PreviewGenerateRequest) (*PreviewGenerateResponse, error)

	// GenerateContentStreamWithPreview generates content with streaming and preview features.
	GenerateContentStreamWithPreview(ctx context.Context, modelName string, req *PreviewGenerateRequest) iter.Seq2[*PreviewGenerateResponse, error]

	// GenerateContentWithTools generates content with enhanced tool calling.
	GenerateContentWithTools(ctx context.Context, modelName string, req *ToolGenerateRequest) (*ToolGenerateResponse, error)

	// CountTokensPreview counts tokens with preview features.
	CountTokensPreview(ctx context.Context, req *TokenCountRequest) (*TokenCountResponse, error)

	// Close closes the service and releases resources.
	Close() error
}
