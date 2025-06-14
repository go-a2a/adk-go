// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package reasoningengines

import (
	"context"
	"testing"
	"time"
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

func TestService_RegisterHandler(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test handler function
	testHandler := func(ctx context.Context, request *AgentRequest) (*AgentResponse, error) {
		return &AgentResponse{
			Content: "Test response for: " + request.Input,
		}, nil
	}

	// Register handler
	service.RegisterHandler("test-agent", testHandler)

	// Check that handler is registered
	service.mu.RLock()
	_, exists := service.handlers["test-agent"]
	service.mu.RUnlock()

	if !exists {
		t.Error("Handler was not registered")
	}

	// Unregister handler
	service.UnregisterHandler("test-agent")

	// Check that handler is unregistered
	service.mu.RLock()
	_, exists = service.handlers["test-agent"]
	service.mu.RUnlock()

	if exists {
		t.Error("Handler was not unregistered")
	}
}

func TestService_validateConfig(t *testing.T) {
	service := &Service{}

	tests := []struct {
		name    string
		config  *AgentConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &AgentConfig{
				Name:       "test-agent",
				Runtime:    RuntimeGo,
				EntryPoint: "main.Handler",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			config: &AgentConfig{
				Runtime:    RuntimeGo,
				EntryPoint: "main.Handler",
			},
			wantErr: true,
		},
		{
			name: "missing runtime",
			config: &AgentConfig{
				Name:       "test-agent",
				EntryPoint: "main.Handler",
			},
			wantErr: true,
		},
		{
			name: "missing entry point",
			config: &AgentConfig{
				Name:    "test-agent",
				Runtime: RuntimeGo,
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

func TestService_CreateReasoningEngine(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	config := &AgentConfig{
		Name:        "test-agent",
		DisplayName: "Test Agent",
		Description: "A test agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	deploySpec := &DeploymentSpec{
		Resources: &ResourceSpec{
			CPU:    "1",
			Memory: "2Gi",
		},
	}

	engine, err := service.CreateReasoningEngine(ctx, config, deploySpec)
	if err != nil {
		t.Fatalf("CreateReasoningEngine() error = %v", err)
	}

	if engine.Name != config.Name {
		t.Errorf("CreateReasoningEngine() name = %v, want %v", engine.Name, config.Name)
	}

	if engine.State != StateCreating {
		t.Errorf("CreateReasoningEngine() state = %v, want %v", engine.State, StateCreating)
	}

	// Check that engine is in deployments registry
	service.deployMu.RLock()
	_, exists := service.deployments[config.Name]
	service.deployMu.RUnlock()

	if !exists {
		t.Error("Engine was not added to deployments registry")
	}
}

func TestService_GetReasoningEngine(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create an engine first
	config := &AgentConfig{
		Name:        "test-agent",
		DisplayName: "Test Agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	createdEngine, err := service.CreateReasoningEngine(ctx, config, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Get the engine
	retrievedEngine, err := service.GetReasoningEngine(ctx, "test-agent")
	if err != nil {
		t.Fatalf("GetReasoningEngine() error = %v", err)
	}

	if retrievedEngine.Name != createdEngine.Name {
		t.Errorf("GetReasoningEngine() name = %v, want %v", retrievedEngine.Name, createdEngine.Name)
	}

	// Test getting non-existent engine
	_, err = service.GetReasoningEngine(ctx, "non-existent")
	if err == nil {
		t.Error("GetReasoningEngine() should return error for non-existent engine")
	}
}

func TestService_ListReasoningEngines(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create multiple engines
	configs := []*AgentConfig{
		{
			Name:        "agent-1",
			DisplayName: "Agent 1",
			Runtime:     RuntimeGo,
			EntryPoint:  "main.Handler",
		},
		{
			Name:        "agent-2",
			DisplayName: "Agent 2",
			Runtime:     RuntimePython,
			EntryPoint:  "main.handler",
		},
	}

	for _, config := range configs {
		_, err := service.CreateReasoningEngine(ctx, config, nil)
		if err != nil {
			t.Fatalf("Failed to create engine %s: %v", config.Name, err)
		}
	}

	// List all engines
	engines, err := service.ListReasoningEngines(ctx, nil)
	if err != nil {
		t.Fatalf("ListReasoningEngines() error = %v", err)
	}

	if len(engines) != 2 {
		t.Errorf("ListReasoningEngines() returned %d engines, want 2", len(engines))
	}

	// Test with filter
	opts := &ListOptions{
		Filter: "state=CREATING",
	}

	filteredEngines, err := service.ListReasoningEngines(ctx, opts)
	if err != nil {
		t.Fatalf("ListReasoningEngines() with filter error = %v", err)
	}

	if len(filteredEngines) != 2 {
		t.Errorf("ListReasoningEngines() with filter returned %d engines, want 2", len(filteredEngines))
	}

	// Test with pagination
	paginatedOpts := &ListOptions{
		PageSize: 1,
	}

	paginatedEngines, err := service.ListReasoningEngines(ctx, paginatedOpts)
	if err != nil {
		t.Fatalf("ListReasoningEngines() with pagination error = %v", err)
	}

	if len(paginatedEngines) != 1 {
		t.Errorf("ListReasoningEngines() with pagination returned %d engines, want 1", len(paginatedEngines))
	}
}

func TestService_UpdateReasoningEngine(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create an engine first
	config := &AgentConfig{
		Name:        "test-agent",
		DisplayName: "Test Agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	_, err = service.CreateReasoningEngine(ctx, config, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Update the engine
	updateSpec := &UpdateSpec{
		DisplayName: "Updated Test Agent",
		Description: "Updated description",
		Resources: &ResourceSpec{
			CPU:    "2",
			Memory: "4Gi",
		},
		Labels: map[string]string{
			"environment": "test",
		},
	}

	updatedEngine, err := service.UpdateReasoningEngine(ctx, "test-agent", updateSpec)
	if err != nil {
		t.Fatalf("UpdateReasoningEngine() error = %v", err)
	}

	if updatedEngine.DisplayName != updateSpec.DisplayName {
		t.Errorf("UpdateReasoningEngine() display name = %v, want %v", updatedEngine.DisplayName, updateSpec.DisplayName)
	}

	if updatedEngine.Description != updateSpec.Description {
		t.Errorf("UpdateReasoningEngine() description = %v, want %v", updatedEngine.Description, updateSpec.Description)
	}

	if updatedEngine.State != StateUpdating {
		t.Errorf("UpdateReasoningEngine() state = %v, want %v", updatedEngine.State, StateUpdating)
	}

	// Test updating non-existent engine
	_, err = service.UpdateReasoningEngine(ctx, "non-existent", updateSpec)
	if err == nil {
		t.Error("UpdateReasoningEngine() should return error for non-existent engine")
	}
}

func TestService_DeleteReasoningEngine(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create an engine first
	config := &AgentConfig{
		Name:        "test-agent",
		DisplayName: "Test Agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	_, err = service.CreateReasoningEngine(ctx, config, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Delete the engine
	err = service.DeleteReasoningEngine(ctx, "test-agent")
	if err != nil {
		t.Fatalf("DeleteReasoningEngine() error = %v", err)
	}

	// Check that engine state is updated to deleting
	engine, err := service.GetReasoningEngine(ctx, "test-agent")
	if err != nil {
		t.Fatalf("Failed to get engine after deletion: %v", err)
	}

	if engine.State != StateDeleting {
		t.Errorf("DeleteReasoningEngine() state = %v, want %v", engine.State, StateDeleting)
	}

	// Test deleting non-existent engine
	err = service.DeleteReasoningEngine(ctx, "non-existent")
	if err == nil {
		t.Error("DeleteReasoningEngine() should return error for non-existent engine")
	}
}

func TestService_Query(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Test with local handler
	testHandler := func(ctx context.Context, request *AgentRequest) (*AgentResponse, error) {
		return &AgentResponse{
			Content: "Local response for: " + request.Input,
		}, nil
	}

	service.RegisterHandler("local-agent", testHandler)

	response, err := service.Query(ctx, "local-agent", map[string]any{
		"input": "test question",
	})
	if err != nil {
		t.Fatalf("Query() with local handler error = %v", err)
	}

	expected := "Local response for: test question"
	if response.Content != expected {
		t.Errorf("Query() content = %v, want %v", response.Content, expected)
	}

	// Test with deployed agent
	config := &AgentConfig{
		Name:        "deployed-agent",
		DisplayName: "Deployed Agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	_, err = service.CreateReasoningEngine(ctx, config, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Manually set state to active for testing
	service.deployMu.Lock()
	service.deployments["deployed-agent"].State = StateActive
	service.deployMu.Unlock()

	response, err = service.Query(ctx, "deployed-agent", map[string]any{
		"input": "test question",
	})
	if err != nil {
		t.Fatalf("Query() with deployed agent error = %v", err)
	}

	if response.Content == "" {
		t.Error("Query() returned empty content")
	}

	// Test with non-existent agent
	_, err = service.Query(ctx, "non-existent", map[string]any{
		"input": "test",
	})
	if err == nil {
		t.Error("Query() should return error for non-existent agent")
	}

	// Test with inactive agent
	service.deployMu.Lock()
	service.deployments["deployed-agent"].State = StateCreating
	service.deployMu.Unlock()

	_, err = service.Query(ctx, "deployed-agent", map[string]any{
		"input": "test",
	})
	if err == nil {
		t.Error("Query() should return error for inactive agent")
	}
}

func TestService_QueryStream(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create and activate an agent
	config := &AgentConfig{
		Name:        "stream-agent",
		DisplayName: "Stream Agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	_, err = service.CreateReasoningEngine(ctx, config, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Set state to active
	service.deployMu.Lock()
	service.deployments["stream-agent"].State = StateActive
	service.deployMu.Unlock()

	// Create stream
	stream, err := service.QueryStream(ctx, "stream-agent")
	if err != nil {
		t.Fatalf("QueryStream() error = %v", err)
	}
	defer stream.Close()

	// Test sending and receiving
	request := &AgentRequest{
		Input: "test streaming",
	}

	err = stream.Send(request)
	if err != nil {
		t.Fatalf("Stream.Send() error = %v", err)
	}

	response, err := stream.Recv()
	if err != nil {
		t.Fatalf("Stream.Recv() error = %v", err)
	}

	if response.Content == "" {
		t.Error("Stream.Recv() returned empty content")
	}

	// Test with non-existent agent
	_, err = service.QueryStream(ctx, "non-existent")
	if err == nil {
		t.Error("QueryStream() should return error for non-existent agent")
	}
}

func TestService_GetMetrics(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create an agent
	config := &AgentConfig{
		Name:        "metrics-agent",
		DisplayName: "Metrics Agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	_, err = service.CreateReasoningEngine(ctx, config, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Get metrics
	opts := &MetricsOptions{
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
	}

	metrics, err := service.GetMetrics(ctx, "metrics-agent", opts)
	if err != nil {
		t.Fatalf("GetMetrics() error = %v", err)
	}

	if metrics.Name != "metrics-agent" {
		t.Errorf("GetMetrics() name = %v, want %v", metrics.Name, "metrics-agent")
	}

	if metrics.RequestCount == 0 {
		t.Error("GetMetrics() should return non-zero request count")
	}

	if metrics.ResourceUtilization == nil {
		t.Error("GetMetrics() should return resource utilization")
	}

	// Test with non-existent agent
	_, err = service.GetMetrics(ctx, "non-existent", opts)
	if err == nil {
		t.Error("GetMetrics() should return error for non-existent agent")
	}
}

func TestService_GetLogs(t *testing.T) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Create an agent
	config := &AgentConfig{
		Name:        "logs-agent",
		DisplayName: "Logs Agent",
		Runtime:     RuntimeGo,
		EntryPoint:  "main.Handler",
	}

	_, err = service.CreateReasoningEngine(ctx, config, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Get logs
	opts := &LogOptions{
		Level:     LogLevelInfo,
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
		PageSize:  10,
	}

	logs, err := service.GetLogs(ctx, "logs-agent", opts)
	if err != nil {
		t.Fatalf("GetLogs() error = %v", err)
	}

	if len(logs) == 0 {
		t.Error("GetLogs() should return at least one log entry")
	}

	// Check log structure
	for _, log := range logs {
		if log.Timestamp.IsZero() {
			t.Error("Log entry should have timestamp")
		}
		if log.Level == "" {
			t.Error("Log entry should have level")
		}
		if log.Message == "" {
			t.Error("Log entry should have message")
		}
	}

	// Test with non-existent agent
	_, err = service.GetLogs(ctx, "non-existent", opts)
	if err == nil {
		t.Error("GetLogs() should return error for non-existent agent")
	}
}

func TestSimpleMemory(t *testing.T) {
	memory := &SimpleMemory{}

	// Test Set and Get
	memory.Set("key1", "value1")
	memory.Set("key2", 42)

	val, exists := memory.Get("key1")
	if !exists || val != "value1" {
		t.Errorf("Get() = %v, %v, want value1, true", val, exists)
	}

	val, exists = memory.Get("key2")
	if !exists || val != 42 {
		t.Errorf("Get() = %v, %v, want 42, true", val, exists)
	}

	// Test non-existent key
	_, exists = memory.Get("nonexistent")
	if exists {
		t.Error("Get() should return false for non-existent key")
	}

	// Test Delete
	memory.Delete("key1")
	_, exists = memory.Get("key1")
	if exists {
		t.Error("Get() should return false for deleted key")
	}

	// Test ToMap
	memMap := memory.ToMap()
	if len(memMap) != 1 {
		t.Errorf("ToMap() returned %d items, want 1", len(memMap))
	}

	// Test FromMap
	newData := map[string]any{
		"new1": "newvalue1",
		"new2": "newvalue2",
	}
	memory.FromMap(newData)

	val, exists = memory.Get("new1")
	if !exists || val != "newvalue1" {
		t.Errorf("Get() after FromMap() = %v, %v, want newvalue1, true", val, exists)
	}

	// Test Clear
	memory.Clear()
	memMap = memory.ToMap()
	if len(memMap) != 0 {
		t.Errorf("ToMap() after Clear() returned %d items, want 0", len(memMap))
	}
}

func TestNewAgentConfig(t *testing.T) {
	config := NewAgentConfig("test-agent", "Test Agent", "A test agent")

	if config.Name != "test-agent" {
		t.Errorf("NewAgentConfig() name = %v, want test-agent", config.Name)
	}

	if config.DisplayName != "Test Agent" {
		t.Errorf("NewAgentConfig() display name = %v, want Test Agent", config.DisplayName)
	}

	if config.Description != "A test agent" {
		t.Errorf("NewAgentConfig() description = %v, want A test agent", config.Description)
	}

	if config.Runtime != RuntimeGo {
		t.Errorf("NewAgentConfig() runtime = %v, want %v", config.Runtime, RuntimeGo)
	}

	if config.EntryPoint != "main.Handler" {
		t.Errorf("NewAgentConfig() entry point = %v, want main.Handler", config.EntryPoint)
	}
}

func TestNewDeploymentSpec(t *testing.T) {
	spec := NewDeploymentSpec()

	if spec.Resources == nil {
		t.Error("NewDeploymentSpec() should set default resources")
	}

	if spec.Resources.CPU != "1" {
		t.Errorf("NewDeploymentSpec() CPU = %v, want 1", spec.Resources.CPU)
	}

	if spec.Resources.Memory != "2Gi" {
		t.Errorf("NewDeploymentSpec() Memory = %v, want 2Gi", spec.Resources.Memory)
	}

	if spec.Scaling == nil {
		t.Error("NewDeploymentSpec() should set default scaling")
	}

	if spec.Container == nil {
		t.Error("NewDeploymentSpec() should set default container")
	}

	if spec.Container.Port != 8080 {
		t.Errorf("NewDeploymentSpec() port = %v, want 8080", spec.Container.Port)
	}
}

// Benchmark tests
func BenchmarkService_Query(b *testing.B) {
	ctx := context.Background()
	service, err := NewService(ctx, "test-project", "us-central1")
	if err != nil {
		b.Fatalf("Failed to create service: %v", err)
	}
	defer service.Close()

	// Register a simple handler
	service.RegisterHandler("bench-agent", func(ctx context.Context, request *AgentRequest) (*AgentResponse, error) {
		return &AgentResponse{Content: "response"}, nil
	})

	input := map[string]any{"input": "test"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.Query(ctx, "bench-agent", input)
		if err != nil {
			b.Fatalf("Query() error = %v", err)
		}
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

	// Create a simple agent
	config := NewAgentConfig("integration-agent", "Integration Test Agent", "An agent for integration testing")
	config.Environment["MODEL_NAME"] = "gemini-2.0-flash-001"

	deploySpec := NewDeploymentSpec()

	engine, err := service.CreateReasoningEngine(ctx, config, deploySpec)
	if err != nil {
		t.Fatalf("Failed to create reasoning engine: %v", err)
	}

	// Wait for deployment
	err = service.WaitForDeployment(ctx, engine.Name, 5*time.Minute)
	if err != nil {
		t.Fatalf("Failed to wait for deployment: %v", err)
	}

	// Query the agent
	response, err := service.Query(ctx, engine.Name, map[string]any{
		"input": "Hello, how are you?",
	})
	if err != nil {
		t.Fatalf("Failed to query agent: %v", err)
	}

	if response.Content == "" {
		t.Error("Agent returned empty response")
	}

	// Get metrics
	metrics, err := service.GetMetrics(ctx, engine.Name, &MetricsOptions{
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}

	t.Logf("Agent metrics: %+v", metrics)

	// Clean up
	err = service.DeleteReasoningEngine(ctx, engine.Name)
	if err != nil {
		t.Fatalf("Failed to delete reasoning engine: %v", err)
	}
}
