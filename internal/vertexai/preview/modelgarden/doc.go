// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package model_garden provides access to Vertex AI Model Garden experimental and community models.
//
// Model Garden is a repository of foundation models and experimental models that extends
// beyond the standard Vertex AI model offerings. This package provides Go access to
// discover, deploy, and interact with models from Model Garden, including experimental
// variants, community contributions, and preview model releases.
//
// # Model Garden Features
//
// The package provides access to:
//   - Foundation models from various publishers
//   - Experimental model variants and architectures
//   - Community-contributed models and fine-tunes
//   - Preview releases of upcoming models
//   - Custom model deployments and endpoints
//   - Model metadata and capability information
//   - Deployment management and scaling
//
// # Architecture
//
// The package is structured around:
//   - ModelGardenService: Core service for model discovery and deployment
//   - ModelInfo: Comprehensive model metadata and capabilities
//   - DeploymentManager: Handles model deployment lifecycle
//   - ModelRegistry: Catalogues available models and their status
//   - PublisherInfo: Information about model publishers and sources
//
// # Usage
//
// Basic model discovery and deployment:
//
//	service, err := model_garden.NewService(ctx, "my-project", "us-central1")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Discover available models
//	models, err := service.ListModels(ctx, &model_garden.ListModelsOptions{
//		Publisher: "google",
//		Category:  "experimental",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Get detailed model information
//	modelInfo, err := service.GetModel(ctx, "publishers/google/models/experimental-llm-v1")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Deploy a model
//	deployment, err := service.DeployModel(ctx, &model_garden.DeployModelRequest{
//		ModelName:      modelInfo.Name,
//		DeploymentName: "my-experimental-deployment",
//		MachineType:    "n1-standard-4",
//		MinReplicas:    1,
//		MaxReplicas:    3,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Get the deployed model for inference
//	model, err := service.GetDeployedModel(ctx, deployment.Name)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Model Categories
//
// Model Garden organizes models into categories:
//   - Foundation: Base models from major publishers
//   - Experimental: Preview and experimental model variants
//   - Community: Community-contributed models and fine-tunes
//   - Custom: User-uploaded and trained models
//   - Multimodal: Models supporting text, image, audio, and video
//   - Specialized: Task-specific and domain-specific models
//
// # Publishers
//
// Model Garden supports models from various publishers:
//   - Google: Google's foundation and experimental models
//   - Anthropic: Claude models and variants
//   - Meta: Llama and other Meta models
//   - Mistral: Mistral AI models
//   - Cohere: Cohere's language models
//   - Community: Open-source and community models
//
// # Deployment Management
//
// The package provides comprehensive deployment management:
//   - Automatic scaling based on traffic
//   - Multi-region deployment support
//   - Cost optimization and instance management
//   - Health monitoring and alerting
//   - Version management and rollback capabilities
//
// # Model Capabilities
//
// Models in Model Garden expose detailed capability information:
//   - Supported input/output formats
//   - Maximum context lengths
//   - Language support and specializations
//   - Multimodal capabilities (text, image, audio, video)
//   - Fine-tuning support and options
//   - Pricing and performance characteristics
//
// # Integration with Other Services
//
// Model Garden integrates seamlessly with other preview services:
//   - Content caching for optimized inference
//   - Enhanced safety features for responsible AI
//   - RAG integration for knowledge-augmented generation
//   - Evaluation tools for model performance assessment
//
// # Experimental Features
//
// As a preview service, Model Garden provides access to experimental features:
//   - Early access to upcoming model releases
//   - Beta features and capabilities
//   - Experimental deployment configurations
//   - Advanced model customization options
//
// # Error Handling
//
// The package provides detailed error information for Model Garden operations,
// including model availability errors, deployment failures, quota limitations,
// and compatibility issues.
//
// # Thread Safety
//
// All service operations are safe for concurrent use across multiple goroutines.
package modelgarden
