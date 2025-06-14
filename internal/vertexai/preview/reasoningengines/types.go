// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package reasoningengines

import (
	"context"
	"time"

	"google.golang.org/genai"
)

// Runtime represents the runtime environment for agents.
type Runtime string

const (
	RuntimeGo     Runtime = "go"
	RuntimePython Runtime = "python"
	RuntimeNode   Runtime = "nodejs"
	RuntimeCustom Runtime = "custom"
)

// State represents the state of a reasoning engine.
type State string

const (
	StateCreating State = "CREATING"
	StateActive   State = "ACTIVE"
	StateUpdating State = "UPDATING"
	StateDeleting State = "DELETING"
	StateFailed   State = "FAILED"
	StateInactive State = "INACTIVE"
)

// AuthType represents the authentication type for agents.
type AuthType string

const (
	AuthTypeServiceAccount AuthType = "service_account"
	AuthTypeAPIKey         AuthType = "api_key"
	AuthTypeNone           AuthType = "none"
)

// LogLevel represents logging levels.
type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
)

// AgentRequest represents an incoming request to an agent.
type AgentRequest struct {
	// Input is the user input/query
	Input string `json:"input"`

	// Context provides additional context for the request
	Context map[string]any `json:"context,omitempty"`

	// SessionID identifies the conversation session
	SessionID string `json:"session_id,omitempty"`

	// UserID identifies the user making the request
	UserID string `json:"user_id,omitempty"`

	// Metadata contains request metadata
	Metadata map[string]any `json:"metadata,omitempty"`

	// Tools available for this request
	Tools []Tool `json:"tools,omitempty"`

	// Memory context for multi-turn conversations
	Memory Memory `json:"memory,omitempty"`
}

// AgentResponse represents a response from an agent.
type AgentResponse struct {
	// Content is the agent's response content
	Content string `json:"content"`

	// ToolCalls are any tool calls made by the agent
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	// Metadata contains response metadata
	Metadata map[string]any `json:"metadata,omitempty"`

	// Confidence indicates the agent's confidence in the response
	Confidence float64 `json:"confidence,omitempty"`

	// Sources lists information sources used
	Sources []Source `json:"sources,omitempty"`

	// UpdatedMemory contains updated conversation memory
	UpdatedMemory Memory `json:"updated_memory,omitempty"`

	// Error contains any error information
	Error string `json:"error,omitempty"`
}

// Tool represents a tool available to an agent.
type Tool struct {
	// Name is the tool identifier
	Name string `json:"name"`

	// Description describes the tool's purpose
	Description string `json:"description"`

	// Parameters defines the tool's input parameters
	Parameters map[string]ParameterSpec `json:"parameters"`

	// Handler is the function that implements the tool
	Handler ToolHandler `json:"-"`
}

// ParameterSpec defines a tool parameter specification.
type ParameterSpec struct {
	// Type is the parameter type (string, number, boolean, object, array)
	Type string `json:"type"`

	// Description describes the parameter
	Description string `json:"description,omitempty"`

	// Required indicates if the parameter is required
	Required bool `json:"required,omitempty"`

	// Default is the default value
	Default any `json:"default,omitempty"`

	// Enum lists allowed values for enumerated parameters
	Enum []any `json:"enum,omitempty"`
}

// ToolCall represents a call to a tool.
type ToolCall struct {
	// ID uniquely identifies the tool call
	ID string `json:"id"`

	// Name is the tool name
	Name string `json:"name"`

	// Arguments contains the tool arguments
	Arguments map[string]any `json:"arguments"`

	// Result contains the tool execution result
	Result any `json:"result,omitempty"`

	// Error contains any execution error
	Error string `json:"error,omitempty"`
}

// ToolHandler is a function that implements a tool.
type ToolHandler func(ctx context.Context, args map[string]any) (any, error)

// Memory represents conversation memory for agents.
type Memory interface {
	// Get retrieves a value from memory
	Get(key string) (any, bool)

	// Set stores a value in memory
	Set(key string, value any)

	// Delete removes a value from memory
	Delete(key string)

	// Clear clears all memory
	Clear()

	// ToMap returns memory as a map
	ToMap() map[string]any

	// FromMap loads memory from a map
	FromMap(data map[string]any)
}

// SimpleMemory is a basic in-memory implementation.
type SimpleMemory struct {
	data map[string]any
}

// Get retrieves a value from memory.
func (m *SimpleMemory) Get(key string) (any, bool) {
	if m.data == nil {
		return nil, false
	}
	val, exists := m.data[key]
	return val, exists
}

// Set stores a value in memory.
func (m *SimpleMemory) Set(key string, value any) {
	if m.data == nil {
		m.data = make(map[string]any)
	}
	m.data[key] = value
}

// Delete removes a value from memory.
func (m *SimpleMemory) Delete(key string) {
	if m.data != nil {
		delete(m.data, key)
	}
}

// Clear clears all memory.
func (m *SimpleMemory) Clear() {
	m.data = make(map[string]any)
}

// ToMap returns memory as a map.
func (m *SimpleMemory) ToMap() map[string]any {
	if m.data == nil {
		return make(map[string]any)
	}
	result := make(map[string]any, len(m.data))
	for k, v := range m.data {
		result[k] = v
	}
	return result
}

// FromMap loads memory from a map.
func (m *SimpleMemory) FromMap(data map[string]any) {
	m.data = make(map[string]any, len(data))
	for k, v := range data {
		m.data[k] = v
	}
}

// Source represents an information source.
type Source struct {
	// Name is the source identifier
	Name string `json:"name"`

	// URL is the source URL
	URL string `json:"url,omitempty"`

	// Content is relevant content from the source
	Content string `json:"content,omitempty"`

	// Confidence indicates confidence in this source
	Confidence float64 `json:"confidence,omitempty"`
}

// AgentHandler is the function signature for agent handlers.
type AgentHandler func(ctx context.Context, request *AgentRequest) (*AgentResponse, error)

// AgentConfig represents agent configuration.
type AgentConfig struct {
	// Name is the agent identifier
	Name string `json:"name"`

	// DisplayName is the human-readable name
	DisplayName string `json:"display_name"`

	// Description describes the agent
	Description string `json:"description"`

	// Runtime specifies the runtime environment
	Runtime Runtime `json:"runtime"`

	// EntryPoint is the main handler function
	EntryPoint string `json:"entry_point"`

	// Requirements lists package dependencies
	Requirements []string `json:"requirements,omitempty"`

	// ExtraPackages lists additional packages
	ExtraPackages []string `json:"extra_packages,omitempty"`

	// Environment variables for the agent
	Environment map[string]string `json:"environment,omitempty"`

	// Tools available to the agent
	Tools []Tool `json:"tools,omitempty"`

	// Model configuration
	Model *ModelConfig `json:"model,omitempty"`

	// Timeout for agent requests
	Timeout time.Duration `json:"timeout,omitempty"`
}

// ModelConfig represents model configuration for agents.
type ModelConfig struct {
	// Name is the model identifier
	Name string `json:"name"`

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

	// SafetySettings configures content filtering
	SafetySettings []genai.SafetySetting `json:"safety_settings,omitempty"`
}

// DeploymentSpec represents deployment specifications.
type DeploymentSpec struct {
	// Resources specifies compute resources
	Resources *ResourceSpec `json:"resources,omitempty"`

	// Scaling configures auto-scaling
	Scaling *ScalingSpec `json:"scaling,omitempty"`

	// Environment variables
	Environment map[string]string `json:"environment,omitempty"`

	// Secrets configuration
	Secrets map[string]string `json:"secrets,omitempty"`

	// Network configuration
	Network *NetworkSpec `json:"network,omitempty"`

	// Container configuration
	Container *ContainerSpec `json:"container,omitempty"`
}

// ResourceSpec defines compute resource requirements.
type ResourceSpec struct {
	// CPU allocation (e.g., "1", "2", "0.5")
	CPU string `json:"cpu,omitempty"`

	// Memory allocation (e.g., "1Gi", "512Mi")
	Memory string `json:"memory,omitempty"`

	// GPU allocation
	GPU *GPUSpec `json:"gpu,omitempty"`

	// Disk storage
	Disk string `json:"disk,omitempty"`
}

// GPUSpec defines GPU resource requirements.
type GPUSpec struct {
	// Type is the GPU type (e.g., "nvidia-tesla-t4")
	Type string `json:"type"`

	// Count is the number of GPUs
	Count int `json:"count"`
}

// ScalingSpec defines auto-scaling configuration.
type ScalingSpec struct {
	// MinInstances is the minimum number of instances
	MinInstances int `json:"min_instances"`

	// MaxInstances is the maximum number of instances
	MaxInstances int `json:"max_instances"`

	// TargetCPUUtilization triggers scaling
	TargetCPUUtilization int `json:"target_cpu_utilization,omitempty"`

	// TargetConcurrency triggers scaling
	TargetConcurrency int `json:"target_concurrency,omitempty"`
}

// NetworkSpec defines network configuration.
type NetworkSpec struct {
	// VPC network configuration
	VPC string `json:"vpc,omitempty"`

	// Subnet configuration
	Subnet string `json:"subnet,omitempty"`

	// AllowedIPs restricts access
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// ContainerSpec defines container configuration.
type ContainerSpec struct {
	// Image is the container image
	Image string `json:"image,omitempty"`

	// Port is the container port
	Port int `json:"port,omitempty"`

	// HealthCheck configures health checking
	HealthCheck *HealthCheckSpec `json:"health_check,omitempty"`
}

// HealthCheckSpec defines health check configuration.
type HealthCheckSpec struct {
	// Path is the health check endpoint
	Path string `json:"path"`

	// InitialDelaySeconds before first check
	InitialDelaySeconds int `json:"initial_delay_seconds,omitempty"`

	// PeriodSeconds between checks
	PeriodSeconds int `json:"period_seconds,omitempty"`

	// TimeoutSeconds for each check
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`

	// FailureThreshold before marking unhealthy
	FailureThreshold int `json:"failure_threshold,omitempty"`
}

// ReasoningEngine represents a deployed agent instance.
type ReasoningEngine struct {
	// Name is the unique identifier
	Name string `json:"name"`

	// DisplayName is the human-readable name
	DisplayName string `json:"display_name"`

	// Description describes the agent
	Description string `json:"description"`

	// State is the current deployment state
	State State `json:"state"`

	// Config is the agent configuration
	Config *AgentConfig `json:"config"`

	// DeploymentSpec is the deployment specification
	DeploymentSpec *DeploymentSpec `json:"deployment_spec"`

	// Endpoint is the API endpoint URL
	Endpoint string `json:"endpoint,omitempty"`

	// Version is the deployment version
	Version string `json:"version"`

	// CreateTime is when the agent was created
	CreateTime time.Time `json:"create_time"`

	// UpdateTime is when the agent was last updated
	UpdateTime time.Time `json:"update_time"`

	// Labels for organization and filtering
	Labels map[string]string `json:"labels,omitempty"`

	// Metadata contains additional information
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ListOptions defines options for listing reasoning engines.
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

// UpdateSpec defines update specifications.
type UpdateSpec struct {
	// DisplayName to update
	DisplayName string `json:"display_name,omitempty"`

	// Description to update
	Description string `json:"description,omitempty"`

	// Resources to update
	Resources *ResourceSpec `json:"resources,omitempty"`

	// Scaling to update
	Scaling *ScalingSpec `json:"scaling,omitempty"`

	// Environment variables to update
	Environment map[string]string `json:"environment,omitempty"`

	// Labels to update
	Labels map[string]string `json:"labels,omitempty"`
}

// MetricsOptions defines options for retrieving metrics.
type MetricsOptions struct {
	// StartTime for metrics range
	StartTime time.Time `json:"start_time"`

	// EndTime for metrics range
	EndTime time.Time `json:"end_time"`

	// MetricNames to retrieve
	MetricNames []string `json:"metric_names,omitempty"`

	// Granularity of metrics (e.g., "1m", "5m", "1h")
	Granularity string `json:"granularity,omitempty"`
}

// Metrics represents agent performance metrics.
type Metrics struct {
	// Name is the agent name
	Name string `json:"name"`

	// TimeRange is the metrics time range
	TimeRange TimeRange `json:"time_range"`

	// RequestCount is the total number of requests
	RequestCount int64 `json:"request_count"`

	// SuccessCount is the number of successful requests
	SuccessCount int64 `json:"success_count"`

	// ErrorCount is the number of failed requests
	ErrorCount int64 `json:"error_count"`

	// AverageLatency is the average response latency
	AverageLatency time.Duration `json:"average_latency"`

	// P95Latency is the 95th percentile latency
	P95Latency time.Duration `json:"p95_latency"`

	// P99Latency is the 99th percentile latency
	P99Latency time.Duration `json:"p99_latency"`

	// ThroughputRPS is requests per second
	ThroughputRPS float64 `json:"throughput_rps"`

	// ResourceUtilization shows resource usage
	ResourceUtilization *ResourceUtilization `json:"resource_utilization"`

	// CustomMetrics contains application-specific metrics
	CustomMetrics map[string]float64 `json:"custom_metrics,omitempty"`
}

// TimeRange represents a time range.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ResourceUtilization represents resource usage metrics.
type ResourceUtilization struct {
	// CPUUtilization as a percentage
	CPUUtilization float64 `json:"cpu_utilization"`

	// MemoryUtilization as a percentage
	MemoryUtilization float64 `json:"memory_utilization"`

	// GPUUtilization as a percentage (if applicable)
	GPUUtilization float64 `json:"gpu_utilization,omitempty"`

	// NetworkInBytes ingress traffic
	NetworkInBytes int64 `json:"network_in_bytes"`

	// NetworkOutBytes egress traffic
	NetworkOutBytes int64 `json:"network_out_bytes"`
}

// LogOptions defines options for retrieving logs.
type LogOptions struct {
	// Level filters by log level
	Level LogLevel `json:"level,omitempty"`

	// StartTime for log range
	StartTime time.Time `json:"start_time,omitempty"`

	// EndTime for log range
	EndTime time.Time `json:"end_time,omitempty"`

	// Filter expression for filtering logs
	Filter string `json:"filter,omitempty"`

	// PageSize limits the number of logs per page
	PageSize int `json:"page_size,omitempty"`

	// PageToken for pagination
	PageToken string `json:"page_token,omitempty"`
}

// LogEntry represents a log entry.
type LogEntry struct {
	// Timestamp is when the log was created
	Timestamp time.Time `json:"timestamp"`

	// Level is the log level
	Level LogLevel `json:"level"`

	// Message is the log message
	Message string `json:"message"`

	// Source identifies the log source
	Source string `json:"source,omitempty"`

	// SessionID identifies the session
	SessionID string `json:"session_id,omitempty"`

	// RequestID identifies the request
	RequestID string `json:"request_id,omitempty"`

	// Metadata contains additional log data
	Metadata map[string]any `json:"metadata,omitempty"`
}

// AlertConfig defines alert configuration.
type AlertConfig struct {
	// Name is the alert identifier
	Name string `json:"name"`

	// Condition is the alert condition expression
	Condition string `json:"condition"`

	// Actions to take when alert triggers
	Actions []string `json:"actions"`

	// Enabled indicates if the alert is active
	Enabled bool `json:"enabled"`

	// Severity of the alert
	Severity string `json:"severity,omitempty"`

	// Description of the alert
	Description string `json:"description,omitempty"`
}

// AuthConfig defines authentication configuration.
type AuthConfig struct {
	// Type is the authentication type
	Type AuthType `json:"type"`

	// Config contains auth-specific configuration
	Config map[string]string `json:"config"`
}

// AccessPolicy defines access control policies.
type AccessPolicy struct {
	// AllowedDomains restricts access by domain
	AllowedDomains []string `json:"allowed_domains,omitempty"`

	// AllowedIPs restricts access by IP address
	AllowedIPs []string `json:"allowed_ips,omitempty"`

	// RateLimit configures rate limiting
	RateLimit *RateLimit `json:"rate_limit,omitempty"`

	// RequireAuth indicates if authentication is required
	RequireAuth bool `json:"require_auth"`
}

// RateLimit defines rate limiting configuration.
type RateLimit struct {
	// RequestsPerMinute limits requests per minute
	RequestsPerMinute int `json:"requests_per_minute"`

	// BurstSize allows bursts above the rate limit
	BurstSize int `json:"burst_size,omitempty"`

	// PerUser applies limits per user
	PerUser bool `json:"per_user,omitempty"`
}

// QueryStream represents a bidirectional streaming connection.
type QueryStream interface {
	// Send sends a request to the agent
	Send(*AgentRequest) error

	// Recv receives a response from the agent
	Recv() (*AgentResponse, error)

	// Close closes the stream
	Close() error
}

// Operation represents a long-running operation.
type Operation struct {
	// Name is the operation identifier
	Name string `json:"name"`

	// Done indicates if the operation is complete
	Done bool `json:"done"`

	// Error contains any operation error
	Error string `json:"error,omitempty"`

	// Metadata contains operation metadata
	Metadata map[string]any `json:"metadata,omitempty"`

	// Response contains the operation result
	Response any `json:"response,omitempty"`
}
