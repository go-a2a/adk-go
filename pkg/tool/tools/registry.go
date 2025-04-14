// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"github.com/go-a2a/adk-go/pkg/artifacts"
	"github.com/go-a2a/adk-go/pkg/tool"
)

// RegisterStandardTools registers all standard tools with the given registry.
func RegisterStandardTools(registry *tool.ToolRegistry, artifactService artifacts.ArtifactService) {
	// Register standard tools
	registry.Register(NewGoogleSearchTool())
	registry.Register(NewLoadWebPageTool())
	registry.Register(NewOpenAPITool())
	
	// Register memory and artifact tools if artifact service is provided
	if artifactService != nil {
		registry.Register(NewLoadMemoryTool(artifactService))
		registry.Register(NewSaveMemoryTool(artifactService))
		registry.Register(NewLoadArtifactsTool(artifactService))
	}
}

// RegisterAgentTools registers agent-related tools with the given registry.
func RegisterAgentTools(registry *tool.ToolRegistry, agentRegistry AgentTransferRegistry) {
	if agentRegistry != nil {
		registry.Register(NewTransferToAgentTool(agentRegistry))
		registry.Register(NewListAgentsTool(agentRegistry))
	}
}

// RegisterUserInteractionTools registers tools that enable user interaction.
func RegisterUserInteractionTools(registry *tool.ToolRegistry, userChoiceHandler UserChoiceHandler) {
	if userChoiceHandler != nil {
		registry.Register(NewGetUserChoiceTool(userChoiceHandler))
	} else {
		// Register with default handler
		registry.Register(NewGetUserChoiceTool(&DefaultUserChoiceHandler{}))
	}
}

// RegisterAllTools registers all available tools with the given registry.
func RegisterAllTools(
	registry *tool.ToolRegistry, 
	artifactService artifacts.ArtifactService,
	agentRegistry AgentTransferRegistry,
	userChoiceHandler UserChoiceHandler,
) {
	RegisterStandardTools(registry, artifactService)
	RegisterAgentTools(registry, agentRegistry)
	RegisterUserInteractionTools(registry, userChoiceHandler)
}