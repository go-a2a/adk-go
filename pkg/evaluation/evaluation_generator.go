// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package evaluation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// ToolCallback is a function that receives and modifies tool calls.
type ToolCallback func(toolName string, toolInput map[string]interface{}) (interface{}, bool)

// AgentRunner defines the interface for running an agent.
type AgentRunner interface {
	// Run executes the agent with a query and returns the response.
	Run(ctx context.Context, query string) (string, []ToolUse, error)
	
	// SetBeforeToolCallback sets a callback to intercept tool calls.
	SetBeforeToolCallback(callback ToolCallback)
}

// EvaluationGenerator handles the generation of evaluation responses.
type EvaluationGenerator struct {
	Logger *slog.Logger
}

// NewEvaluationGenerator creates a new EvaluationGenerator.
func NewEvaluationGenerator(logger *slog.Logger) *EvaluationGenerator {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &EvaluationGenerator{
		Logger: logger,
	}
}

// GenerateResponses runs evaluation queries through an agent.
func (g *EvaluationGenerator) GenerateResponses(
	ctx context.Context,
	dataset EvaluationDataset,
	agent AgentRunner,
	runs int,
) (EvaluationDataset, error) {
	if runs <= 0 {
		runs = 1
	}
	
	// Create a copy of the dataset to populate with responses
	resultDataset := make(EvaluationDataset, len(dataset))
	
	// Set up tool callback to intercept tool calls
	agent.SetBeforeToolCallback(func(toolName string, toolInput map[string]interface{}) (interface{}, bool) {
		// This is a stub - in a real implementation, it would check for expected tool use
		// and return mock outputs for evaluation purposes
		return nil, false
	})
	
	// Process each session
	for sessionIdx, session := range dataset {
		resultSession := make(Session, len(session))
		
		// Process each query in the session
		for queryIdx, query := range session {
			// Copy the original query
			resultQuery := query
			
			// Run the agent on this query
			response, toolUses, err := agent.Run(ctx, query.Text)
			if err != nil {
				g.Logger.Error("Failed to run agent",
					slog.String("query", query.Text),
					slog.String("error", err.Error()))
				return nil, fmt.Errorf("agent run failed: %w", err)
			}
			
			// Update the result query with the response and tool uses
			resultQuery.Response = response
			resultQuery.ActualTools = toolUses
			resultQuery.EvaluationTime = time.Now()
			
			resultSession[queryIdx] = resultQuery
		}
		
		resultDataset[sessionIdx] = resultSession
	}
	
	return resultDataset, nil
}

// GenerateResponsesFromSession combines session data with evaluation dataset.
func (g *EvaluationGenerator) GenerateResponsesFromSession(
	ctx context.Context,
	dataset EvaluationDataset,
	sessionFilePath string,
	agent AgentRunner,
) (EvaluationDataset, error) {
	// Load session data from file
	_, err := g.loadSessionData(sessionFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load session data: %w", err)
	}
	// Note: In a full implementation, sessionData would be used to provide context
	
	// Create a copy of the dataset to populate with responses
	resultDataset := make(EvaluationDataset, len(dataset))
	
	// Set up tool callback to intercept tool calls
	agent.SetBeforeToolCallback(func(toolName string, toolInput map[string]interface{}) (interface{}, bool) {
		// This is a stub - in a real implementation, it would check against session data
		return nil, false
	})
	
	// Process each session, combining with session data
	// This is a simplified implementation - in a real scenario, it would use 
	// the session data to build context for the agent
	
	for sessionIdx, session := range dataset {
		resultSession := make(Session, len(session))
		
		for queryIdx, query := range session {
			// Process query using session data context
			resultQuery := query
			
			// Run agent with context from session data
			response, toolUses, err := agent.Run(ctx, query.Text)
			if err != nil {
				g.Logger.Error("Failed to run agent with session context",
					slog.String("query", query.Text),
					slog.String("error", err.Error()))
				return nil, fmt.Errorf("agent run with session failed: %w", err)
			}
			
			resultQuery.Response = response
			resultQuery.ActualTools = toolUses
			resultQuery.EvaluationTime = time.Now()
			
			resultSession[queryIdx] = resultQuery
		}
		
		resultDataset[sessionIdx] = resultSession
	}
	
	return resultDataset, nil
}

// loadSessionData loads session data from a JSON file.
func (g *EvaluationGenerator) loadSessionData(filePath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}
	
	var sessionData map[string]interface{}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}
	
	return sessionData, nil
}

// ApplyBeforeToolCallback recursively applies tool callbacks to an agent and its subagents.
func (g *EvaluationGenerator) ApplyBeforeToolCallback(
	agent AgentRunner,
	callback ToolCallback,
) {
	agent.SetBeforeToolCallback(callback)
	
	// Note: In a real implementation, this would recursively find subagents 
	// and apply the callback to them as well
}