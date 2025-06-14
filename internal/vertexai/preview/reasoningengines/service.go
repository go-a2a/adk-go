// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package reasoningengines

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

// Service provides reasoning engine functionality for Vertex AI.
//
// The service manages agent deployment, runtime, and lifecycle operations.
// It supports containerized deployment of agents with auto-scaling, monitoring,
// and API gateway functionality.
type Service struct {
	client    *aiplatform.PredictionClient
	projectID string
	location  string
	logger    *slog.Logger

	// Registry of agent handlers
	handlers map[string]AgentHandler
	mu       sync.RWMutex

	// Active deployments
	deployments map[string]*ReasoningEngine
	deployMu    sync.RWMutex
}

// ServiceOption is a functional option for configuring the reasoning engine service.
type ServiceOption func(*Service)

// WithLogger sets a custom logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// NewService creates a new reasoning engine service.
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
// Returns a fully initialized reasoning engine service or an error if initialization fails.
func NewService(ctx context.Context, projectID, location string, opts ...ServiceOption) (*Service, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID is required")
	}
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	service := &Service{
		projectID:   projectID,
		location:    location,
		logger:      slog.Default(),
		handlers:    make(map[string]AgentHandler),
		deployments: make(map[string]*ReasoningEngine),
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

	service.logger.InfoContext(ctx, "Reasoning engine service initialized successfully",
		slog.String("project_id", projectID),
		slog.String("location", location),
	)

	return service, nil
}

// Close closes the reasoning engine service and releases all resources.
func (s *Service) Close() error {
	s.logger.Info("Closing reasoning engine service")

	if s.client != nil {
		if err := s.client.Close(); err != nil {
			s.logger.Error("Failed to close prediction client", slog.String("error", err.Error()))
			return fmt.Errorf("failed to close prediction client: %w", err)
		}
	}

	s.logger.Info("Reasoning engine service closed successfully")
	return nil
}

// RegisterHandler registers an agent handler for local execution.
//
// This is useful for development and testing before deploying to the managed environment.
//
// Parameters:
//   - name: Agent name identifier
//   - handler: Function that implements the agent logic
func (s *Service) RegisterHandler(name string, handler AgentHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.handlers[name] = handler
	s.logger.Info("Agent handler registered",
		slog.String("name", name),
	)
}

// UnregisterHandler removes an agent handler from the registry.
func (s *Service) UnregisterHandler(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.handlers, name)
	s.logger.Info("Agent handler unregistered",
		slog.String("name", name),
	)
}

// CreateReasoningEngine deploys a new agent to the managed environment.
//
// This creates a containerized deployment of the agent with the specified
// configuration and deployment specifications.
//
// Parameters:
//   - ctx: Context for the operation
//   - config: Agent configuration
//   - deploySpec: Deployment specifications
//
// Returns the created reasoning engine or an error if deployment fails.
func (s *Service) CreateReasoningEngine(ctx context.Context, config *AgentConfig, deploySpec *DeploymentSpec) (*ReasoningEngine, error) {
	s.logger.InfoContext(ctx, "Creating reasoning engine",
		slog.String("name", config.Name),
		slog.String("runtime", string(config.Runtime)),
	)

	// Validate configuration
	if err := s.validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create reasoning engine instance
	engine := &ReasoningEngine{
		Name:           config.Name,
		DisplayName:    config.DisplayName,
		Description:    config.Description,
		State:          StateCreating,
		Config:         config,
		DeploymentSpec: deploySpec,
		Version:        "1.0.0",
		CreateTime:     time.Now(),
		UpdateTime:     time.Now(),
		Labels:         make(map[string]string),
		Metadata:       make(map[string]any),
	}

	// Set default deployment spec if not provided
	if deploySpec == nil {
		engine.DeploymentSpec = s.getDefaultDeploymentSpec()
	}

	// Store in deployments registry
	s.deployMu.Lock()
	s.deployments[config.Name] = engine
	s.deployMu.Unlock()

	// In a real implementation, this would:
	// 1. Build a container image with the agent code
	// 2. Deploy to Cloud Run or GKE
	// 3. Set up API gateway and monitoring
	// 4. Return the actual deployment details

	// For now, simulate deployment
	go s.simulateDeployment(ctx, engine)

	s.logger.InfoContext(ctx, "Reasoning engine creation initiated",
		slog.String("name", config.Name),
	)

	return engine, nil
}

// GetReasoningEngine retrieves information about a deployed agent.
func (s *Service) GetReasoningEngine(ctx context.Context, name string) (*ReasoningEngine, error) {
	s.deployMu.RLock()
	engine, exists := s.deployments[name]
	s.deployMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("reasoning engine %s not found", name)
	}

	// Return a copy to prevent external modification
	engineCopy := *engine
	return &engineCopy, nil
}

// ListReasoningEngines lists all deployed agents.
func (s *Service) ListReasoningEngines(ctx context.Context, opts *ListOptions) ([]*ReasoningEngine, error) {
	s.deployMu.RLock()
	defer s.deployMu.RUnlock()

	var engines []*ReasoningEngine
	for _, engine := range s.deployments {
		// Apply filter if specified
		if opts != nil && opts.Filter != "" {
			if !s.matchesFilter(engine, opts.Filter) {
				continue
			}
		}

		// Return a copy to prevent external modification
		engineCopy := *engine
		engines = append(engines, &engineCopy)
	}

	// Apply pagination if specified
	if opts != nil && opts.PageSize > 0 {
		start := 0
		if opts.PageToken != "" {
			// In a real implementation, decode the page token
			// For now, ignore pagination
		}

		end := start + opts.PageSize
		if end > len(engines) {
			end = len(engines)
		}

		if start < len(engines) {
			engines = engines[start:end]
		} else {
			engines = []*ReasoningEngine{}
		}
	}

	return engines, nil
}

// UpdateReasoningEngine updates a deployed agent's configuration.
func (s *Service) UpdateReasoningEngine(ctx context.Context, name string, updateSpec *UpdateSpec) (*ReasoningEngine, error) {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()

	engine, exists := s.deployments[name]
	if !exists {
		return nil, fmt.Errorf("reasoning engine %s not found", name)
	}

	s.logger.InfoContext(ctx, "Updating reasoning engine",
		slog.String("name", name),
	)

	// Update fields from spec
	if updateSpec.DisplayName != "" {
		engine.DisplayName = updateSpec.DisplayName
	}
	if updateSpec.Description != "" {
		engine.Description = updateSpec.Description
	}
	if updateSpec.Resources != nil {
		if engine.DeploymentSpec == nil {
			engine.DeploymentSpec = &DeploymentSpec{}
		}
		engine.DeploymentSpec.Resources = updateSpec.Resources
	}
	if updateSpec.Scaling != nil {
		if engine.DeploymentSpec == nil {
			engine.DeploymentSpec = &DeploymentSpec{}
		}
		engine.DeploymentSpec.Scaling = updateSpec.Scaling
	}
	if updateSpec.Environment != nil {
		if engine.DeploymentSpec == nil {
			engine.DeploymentSpec = &DeploymentSpec{}
		}
		if engine.DeploymentSpec.Environment == nil {
			engine.DeploymentSpec.Environment = make(map[string]string)
		}
		for k, v := range updateSpec.Environment {
			engine.DeploymentSpec.Environment[k] = v
		}
	}
	if updateSpec.Labels != nil {
		if engine.Labels == nil {
			engine.Labels = make(map[string]string)
		}
		for k, v := range updateSpec.Labels {
			engine.Labels[k] = v
		}
	}

	engine.UpdateTime = time.Now()
	engine.State = StateUpdating

	// In a real implementation, this would trigger a deployment update
	go s.simulateUpdate(ctx, engine)

	s.logger.InfoContext(ctx, "Reasoning engine update initiated",
		slog.String("name", name),
	)

	// Return a copy
	engineCopy := *engine
	return &engineCopy, nil
}

// DeleteReasoningEngine deletes a deployed agent.
func (s *Service) DeleteReasoningEngine(ctx context.Context, name string) error {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()

	engine, exists := s.deployments[name]
	if !exists {
		return fmt.Errorf("reasoning engine %s not found", name)
	}

	s.logger.InfoContext(ctx, "Deleting reasoning engine",
		slog.String("name", name),
	)

	engine.State = StateDeleting

	// In a real implementation, this would:
	// 1. Stop the container deployment
	// 2. Clean up resources
	// 3. Remove from registry

	// For now, simulate deletion
	go func() {
		time.Sleep(2 * time.Second)
		s.deployMu.Lock()
		delete(s.deployments, name)
		s.deployMu.Unlock()
	}()

	s.logger.InfoContext(ctx, "Reasoning engine deletion initiated",
		slog.String("name", name),
	)

	return nil
}

// Query sends a request to a deployed agent and returns the response.
func (s *Service) Query(ctx context.Context, name string, input map[string]any) (*AgentResponse, error) {
	// Convert input to AgentRequest
	request := &AgentRequest{
		Input:    fmt.Sprintf("%v", input["input"]),
		Context:  input,
		Metadata: make(map[string]any),
		Memory:   &SimpleMemory{},
	}

	// First, try local handler
	s.mu.RLock()
	handler, hasLocal := s.handlers[name]
	s.mu.RUnlock()

	if hasLocal {
		s.logger.InfoContext(ctx, "Using local handler",
			slog.String("name", name),
		)
		return handler(ctx, request)
	}

	// Check if deployed
	s.deployMu.RLock()
	engine, exists := s.deployments[name]
	s.deployMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("reasoning engine %s not found", name)
	}

	if engine.State != StateActive {
		return nil, fmt.Errorf("reasoning engine %s is not active (state: %s)", name, engine.State)
	}

	// In a real implementation, this would make an HTTP request to the deployed agent
	// For now, return a mock response
	response := &AgentResponse{
		Content: fmt.Sprintf("Mock response from deployed agent %s for input: %s", name, request.Input),
		Metadata: map[string]any{
			"agent_name": name,
			"version":    engine.Version,
			"timestamp":  time.Now(),
		},
		Confidence: 0.95,
	}

	return response, nil
}

// QueryStream creates a streaming connection to a deployed agent.
func (s *Service) QueryStream(ctx context.Context, name string) (QueryStream, error) {
	// Check if agent exists
	s.deployMu.RLock()
	engine, exists := s.deployments[name]
	s.deployMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("reasoning engine %s not found", name)
	}

	if engine.State != StateActive {
		return nil, fmt.Errorf("reasoning engine %s is not active (state: %s)", name, engine.State)
	}

	// In a real implementation, this would establish a WebSocket or gRPC stream
	// For now, return a mock stream
	return &mockQueryStream{
		name: name,
		ctx:  ctx,
	}, nil
}

// WaitForDeployment waits for a deployment to complete.
func (s *Service) WaitForDeployment(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		engine, err := s.GetReasoningEngine(ctx, name)
		if err != nil {
			return err
		}

		switch engine.State {
		case StateActive:
			return nil
		case StateFailed:
			return fmt.Errorf("deployment failed for reasoning engine %s", name)
		default:
			// Still deploying, wait and check again
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				continue
			}
		}
	}

	return fmt.Errorf("timeout waiting for deployment of reasoning engine %s", name)
}

// GetMetrics retrieves performance metrics for a deployed agent.
func (s *Service) GetMetrics(ctx context.Context, name string, opts *MetricsOptions) (*Metrics, error) {
	s.deployMu.RLock()
	_, exists := s.deployments[name]
	s.deployMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("reasoning engine %s not found", name)
	}

	// In a real implementation, this would query the monitoring system
	// For now, return mock metrics
	metrics := &Metrics{
		Name: name,
		TimeRange: TimeRange{
			Start: opts.StartTime,
			End:   opts.EndTime,
		},
		RequestCount:   1000,
		SuccessCount:   950,
		ErrorCount:     50,
		AverageLatency: 250 * time.Millisecond,
		P95Latency:     500 * time.Millisecond,
		P99Latency:     1000 * time.Millisecond,
		ThroughputRPS:  10.5,
		ResourceUtilization: &ResourceUtilization{
			CPUUtilization:    45.2,
			MemoryUtilization: 62.8,
			NetworkInBytes:    1024 * 1024 * 100, // 100 MB
			NetworkOutBytes:   1024 * 1024 * 150, // 150 MB
		},
		CustomMetrics: map[string]float64{
			"model_calls":      500,
			"tool_invocations": 150,
		},
	}

	return metrics, nil
}

// GetLogs retrieves logs for a deployed agent.
func (s *Service) GetLogs(ctx context.Context, name string, opts *LogOptions) ([]*LogEntry, error) {
	s.deployMu.RLock()
	engine, exists := s.deployments[name]
	s.deployMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("reasoning engine %s not found", name)
	}

	// In a real implementation, this would query the logging system
	// For now, return mock logs
	logs := []*LogEntry{
		{
			Timestamp: time.Now().Add(-1 * time.Hour),
			Level:     LogLevelInfo,
			Message:   "Agent started successfully",
			Source:    "agent-runtime",
			Metadata: map[string]any{
				"version": engine.Version,
			},
		},
		{
			Timestamp: time.Now().Add(-30 * time.Minute),
			Level:     LogLevelInfo,
			Message:   "Processed user request",
			Source:    "agent-handler",
			SessionID: "session-123",
			RequestID: "req-456",
			Metadata: map[string]any{
				"latency_ms": 250,
				"success":    true,
			},
		},
		{
			Timestamp: time.Now().Add(-15 * time.Minute),
			Level:     LogLevelWarn,
			Message:   "High latency detected",
			Source:    "agent-monitor",
			Metadata: map[string]any{
				"latency_ms": 1200,
				"threshold":  1000,
			},
		},
	}

	// Apply filtering
	if opts != nil {
		if opts.Level != "" {
			filtered := make([]*LogEntry, 0)
			for _, log := range logs {
				if log.Level == opts.Level {
					filtered = append(filtered, log)
				}
			}
			logs = filtered
		}

		if opts.PageSize > 0 && len(logs) > opts.PageSize {
			logs = logs[:opts.PageSize]
		}
	}

	return logs, nil
}

// CreateAlert creates a monitoring alert for an agent.
func (s *Service) CreateAlert(ctx context.Context, name string, alertConfig *AlertConfig) error {
	s.deployMu.RLock()
	_, exists := s.deployments[name]
	s.deployMu.RUnlock()

	if !exists {
		return fmt.Errorf("reasoning engine %s not found", name)
	}

	s.logger.InfoContext(ctx, "Creating alert",
		slog.String("agent", name),
		slog.String("alert", alertConfig.Name),
		slog.String("condition", alertConfig.Condition),
	)

	// In a real implementation, this would configure monitoring alerts
	// For now, just log the configuration
	return nil
}

// SetAccessPolicy sets access control policies for an agent.
func (s *Service) SetAccessPolicy(ctx context.Context, name string, policy *AccessPolicy) error {
	s.deployMu.RLock()
	_, exists := s.deployments[name]
	s.deployMu.RUnlock()

	if !exists {
		return fmt.Errorf("reasoning engine %s not found", name)
	}

	s.logger.InfoContext(ctx, "Setting access policy",
		slog.String("agent", name),
		slog.Bool("require_auth", policy.RequireAuth),
	)

	// In a real implementation, this would configure API gateway policies
	// For now, just log the configuration
	return nil
}

// validateConfig validates agent configuration.
func (s *Service) validateConfig(config *AgentConfig) error {
	if config.Name == "" {
		return fmt.Errorf("name is required")
	}
	if config.Runtime == "" {
		return fmt.Errorf("runtime is required")
	}
	if config.EntryPoint == "" {
		return fmt.Errorf("entry point is required")
	}
	return nil
}

// getDefaultDeploymentSpec returns default deployment specifications.
func (s *Service) getDefaultDeploymentSpec() *DeploymentSpec {
	return &DeploymentSpec{
		Resources: &ResourceSpec{
			CPU:    "1",
			Memory: "2Gi",
		},
		Scaling: &ScalingSpec{
			MinInstances:         0,
			MaxInstances:         10,
			TargetCPUUtilization: 70,
		},
		Environment: make(map[string]string),
		Container: &ContainerSpec{
			Port: 8080,
			HealthCheck: &HealthCheckSpec{
				Path:                "/health",
				InitialDelaySeconds: 30,
				PeriodSeconds:       10,
				TimeoutSeconds:      5,
				FailureThreshold:    3,
			},
		},
	}
}

// simulateDeployment simulates the deployment process.
func (s *Service) simulateDeployment(ctx context.Context, engine *ReasoningEngine) {
	// Simulate deployment time
	time.Sleep(10 * time.Second)

	s.deployMu.Lock()
	defer s.deployMu.Unlock()

	if deployedEngine, exists := s.deployments[engine.Name]; exists {
		deployedEngine.State = StateActive
		deployedEngine.Endpoint = fmt.Sprintf("https://%s-agent-dot-%s.appspot.com", engine.Name, s.projectID)
		deployedEngine.UpdateTime = time.Now()

		s.logger.Info("Reasoning engine deployment completed",
			slog.String("name", engine.Name),
			slog.String("endpoint", deployedEngine.Endpoint),
		)
	}
}

// simulateUpdate simulates the update process.
func (s *Service) simulateUpdate(ctx context.Context, engine *ReasoningEngine) {
	// Simulate update time
	time.Sleep(5 * time.Second)

	s.deployMu.Lock()
	defer s.deployMu.Unlock()

	if deployedEngine, exists := s.deployments[engine.Name]; exists {
		deployedEngine.State = StateActive
		deployedEngine.UpdateTime = time.Now()

		s.logger.Info("Reasoning engine update completed",
			slog.String("name", engine.Name),
		)
	}
}

// matchesFilter checks if an engine matches the given filter.
func (s *Service) matchesFilter(engine *ReasoningEngine, filter string) bool {
	// Simple filter implementation - in practice, this would be more sophisticated
	switch filter {
	case "state=ACTIVE":
		return engine.State == StateActive
	case "state=CREATING":
		return engine.State == StateCreating
	case "state=FAILED":
		return engine.State == StateFailed
	default:
		return true
	}
}

// mockQueryStream is a mock implementation of QueryStream.
type mockQueryStream struct {
	name string
	ctx  context.Context
}

func (m *mockQueryStream) Send(request *AgentRequest) error {
	// Mock implementation - in practice, this would send over WebSocket/gRPC
	return nil
}

func (m *mockQueryStream) Recv() (*AgentResponse, error) {
	// Mock implementation - in practice, this would receive over WebSocket/gRPC
	response := &AgentResponse{
		Content: "Mock streaming response from " + m.name,
		Metadata: map[string]any{
			"timestamp": time.Now(),
			"stream":    true,
		},
	}
	return response, nil
}

func (m *mockQueryStream) Close() error {
	// Mock implementation
	return nil
}

// Helper functions for creating common configurations

// NewAgentConfig creates a new agent configuration with common defaults.
func NewAgentConfig(name, displayName, description string) *AgentConfig {
	return &AgentConfig{
		Name:         name,
		DisplayName:  displayName,
		Description:  description,
		Runtime:      RuntimeGo,
		EntryPoint:   "main.Handler",
		Requirements: []string{},
		Environment:  make(map[string]string),
		Tools:        []Tool{},
		Timeout:      30 * time.Second,
	}
}

// NewDeploymentSpec creates a new deployment specification with common defaults.
func NewDeploymentSpec() *DeploymentSpec {
	return &DeploymentSpec{
		Resources: &ResourceSpec{
			CPU:    "1",
			Memory: "2Gi",
		},
		Scaling: &ScalingSpec{
			MinInstances:         0,
			MaxInstances:         10,
			TargetCPUUtilization: 70,
		},
		Environment: make(map[string]string),
		Container: &ContainerSpec{
			Port: 8080,
			HealthCheck: &HealthCheckSpec{
				Path:                "/health",
				InitialDelaySeconds: 30,
				PeriodSeconds:       10,
				TimeoutSeconds:      5,
				FailureThreshold:    3,
			},
		},
	}
}
