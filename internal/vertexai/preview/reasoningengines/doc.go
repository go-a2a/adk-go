// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package reasoning_engines provides Agent Engine functionality for Vertex AI.
//
// This package is a port of the Python vertexai.preview.reasoning_engines module, providing
// comprehensive support for deploying and managing AI agents in a managed runtime environment.
// Agent Engine (formerly known as Reasoning Engine) enables developers to create agents using
// orchestration frameworks and deploy them with the security, privacy, observability, and
// scalability benefits of Vertex AI integration.
//
// # Core Features
//
// The package provides comprehensive agent deployment and management capabilities:
//   - Agent Deployment: Deploy custom agents to managed runtime environments
//   - LangChain Integration: Native support for LangChain-based agent frameworks
//   - Containerized Runtime: Secure, scalable container-based execution
//   - API Gateway: RESTful API endpoints for agent interaction
//   - Resource Management: Automatic scaling and resource optimization
//   - Monitoring & Logging: Built-in observability for agent performance
//   - Version Control: Agent versioning and rollback capabilities
//
// # Supported Frameworks
//
// Agent orchestration frameworks supported:
//   - Custom Go Agents: Native Go agent implementations
//   - LangChain Compatibility: Support for LangChain-style agent patterns
//   - Function Calling: Tool-based agent architectures
//   - Multi-Modal Agents: Text, image, and video processing capabilities
//   - Streaming Agents: Real-time interaction support
//
// # Architecture
//
// The package provides:
//   - ReasoningEngineService: Core service for agent deployment and management
//   - ReasoningEngine: Individual agent instance configuration and runtime
//   - AgentConfig: Agent configuration including dependencies and resources
//   - DeploymentSpec: Deployment specifications for containerized agents
//   - RuntimeEnvironment: Execution environment configuration
//   - APIEndpoint: RESTful API endpoint management
//
// # Usage
//
// Basic agent deployment workflow:
//
//	service, err := reasoning_engines.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Define agent configuration
//	config := &reasoning_engines.AgentConfig{
//		Name:         "my-agent",
//		DisplayName:  "My Custom Agent",
//		Description:  "A simple demonstration agent",
//		Runtime:      reasoning_engines.RuntimeGo,
//		EntryPoint:   "main.Handler",
//		Requirements: []string{"github.com/go-a2a/adk-go"},
//	}
//
//	// Create deployment specification
//	deploySpec := &reasoning_engines.DeploymentSpec{
//		Resources: &reasoning_engines.ResourceSpec{
//			CPU:    "1",
//			Memory: "2Gi",
//		},
//		Scaling: &reasoning_engines.ScalingSpec{
//			MinInstances: 0,
//			MaxInstances: 10,
//		},
//		Environment: map[string]string{
//			"MODEL_NAME": "gemini-2.0-flash-001",
//		},
//	}
//
//	// Deploy the agent
//	engine, err := service.CreateReasoningEngine(ctx, config, deploySpec)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Wait for deployment to complete
//	err = service.WaitForDeployment(ctx, engine.Name, 5*time.Minute)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Query the deployed agent
//	response, err := service.Query(ctx, engine.Name, map[string]any{
//		"input": "What is the weather today?",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Agent Implementation
//
// Creating custom agents for deployment:
//
//		type WeatherAgent struct {
//			modelName string
//		}
//
//		func (a *WeatherAgent) Handle(ctx context.Context, request *reasoning_engines.AgentRequest) (*reasoning_engines.AgentResponse, error) {
//			// Process the request using your agent logic
//			response := &reasoning_engines.AgentResponse{
//				Content: "Today's weather is sunny with a high of 75°F.",
//				Metadata: map[string]any{
//					"confidence": 0.95,
//					"source":     "weather_api",
//				},
//		}
//
//		return response, nil
//	}
//
//	// Register agent for deployment
//	func main() {
//		agent := &WeatherAgent{modelName: "gemini-2.0-flash-001"}
//		reasoning_engines.RegisterHandler("weather", agent.Handle)
//	}
//
// # LangChain-Style Agents
//
// Support for LangChain-style agent patterns:
//
//	type LangChainAgent struct {
//		model  *genai.GenerativeModel
//		tools  []reasoning_engines.Tool
//		memory reasoning_engines.Memory
//	}
//
//	func (a *LangChainAgent) Handle(ctx context.Context, request *reasoning_engines.AgentRequest) (*reasoning_engines.AgentResponse, error) {
//		// Implement LangChain-style reasoning loop
//		thought := a.think(ctx, request.Input)
//		action := a.plan(ctx, thought)
//		observation := a.act(ctx, action)
//		response := a.respond(ctx, observation)
//
//		return response, nil
//	}
//
// # Deployment Management
//
// Managing deployed agents:
//
//	// List all deployed agents
//	engines, err := service.ListReasoningEngines(ctx, &reasoning_engines.ListOptions{
//		Filter: "state=ACTIVE",
//	})
//
//	// Get agent details
//	engine, err := service.GetReasoningEngine(ctx, "my-agent")
//
//	// Update agent configuration
//	updated, err := service.UpdateReasoningEngine(ctx, "my-agent", &reasoning_engines.UpdateSpec{
//		Resources: &reasoning_engines.ResourceSpec{
//			CPU:    "2",
//			Memory: "4Gi",
//		},
//	})
//
//	// Delete agent
//	err = service.DeleteReasoningEngine(ctx, "my-agent")
//
// # Monitoring and Observability
//
// Built-in monitoring capabilities:
//
//	// Get agent metrics
//	metrics, err := service.GetMetrics(ctx, "my-agent", &reasoning_engines.MetricsOptions{
//		StartTime: time.Now().Add(-24 * time.Hour),
//		EndTime:   time.Now(),
//	})
//
//	// Get agent logs
//	logs, err := service.GetLogs(ctx, "my-agent", &reasoning_engines.LogOptions{
//		Level:     reasoning_engines.LogLevelInfo,
//		StartTime: time.Now().Add(-1 * time.Hour),
//	})
//
//	// Set up alerts
//	alert := &reasoning_engines.AlertConfig{
//		Name:      "high_latency",
//		Condition: "latency > 5s",
//		Actions:   []string{"email:admin@company.com"},
//	}
//	err = service.CreateAlert(ctx, "my-agent", alert)
//
// # Streaming Interactions
//
// Real-time streaming support:
//
//	// Stream requests to agent
//	stream, err := service.QueryStream(ctx, "my-agent")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer stream.Close()
//
//	// Send request
//	err = stream.Send(&reasoning_engines.AgentRequest{
//		Input: "Tell me a story",
//	})
//
//	// Receive streaming responses
//	for {
//		response, err := stream.Recv()
//		if err == io.EOF {
//			break
//		}
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Print(response.Content)
//	}
//
// # Security and Access Control
//
// Security features and access management:
//
//	// Configure authentication
//	authConfig := &reasoning_engines.AuthConfig{
//		Type:   reasoning_engines.AuthTypeServiceAccount,
//		Config: map[string]string{
//			"service_account": "agent-sa@project.iam.gserviceaccount.com",
//		},
//	}
//
//	// Set access policies
//	policy := &reasoning_engines.AccessPolicy{
//		AllowedDomains: []string{"company.com"},
//		RateLimit: &reasoning_engines.RateLimit{
//			RequestsPerMinute: 1000,
//			BurstSize:        50,
//		},
//	}
//
//	err = service.SetAccessPolicy(ctx, "my-agent", policy)
//
// # Advanced Features
//
// Advanced deployment capabilities:
//
//   - Blue-Green Deployments: Zero-downtime deployments with traffic splitting
//   - A/B Testing: Traffic routing for experiment and evaluation
//   - Multi-Region: Deploy agents across multiple geographic regions
//   - Custom Containers: Use custom Docker images for specialized environments
//   - GPU Support: Hardware acceleration for compute-intensive agents
//   - Batch Processing: Process multiple requests efficiently
//
// # Performance Optimization
//
// The package provides several optimizations:
//   - Connection pooling for model clients
//   - Request batching for improved throughput
//   - Intelligent caching of model responses
//   - Auto-scaling based on load patterns
//   - Resource optimization recommendations
//
// # Error Handling
//
// The package provides detailed error information for deployment and runtime
// operations, including deployment failures, runtime errors, and resource
// constraint violations.
//
// # Thread Safety
//
// All service operations are safe for concurrent use across multiple goroutines.
// Individual agent instances run in isolated containers for security and stability.
package reasoningengines
