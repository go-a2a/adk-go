// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent provides an Agent Development Kit (ADK) implementation in Go.
// It is inspired by the Python ADK library from Google.
package agent

import (
	"fmt"
)

// Version is the current version of the ADK.
var Version = "v0.1.0"

// Initialize sets up the ADK.
func Initialize() error {
	fmt.Printf("ADK Go %s initialized\n", Version)
	return nil
}

// AgentType represents the type of an agent.
type AgentType string

// Agent types
const (
	AgentTypeLLM        AgentType = "llm"
	AgentTypeSequential AgentType = "sequential"
	AgentTypeParallel   AgentType = "parallel"
	AgentTypeLoop       AgentType = "loop"
	AgentTypeRemote     AgentType = "remote"
)

// CreateAgent creates an agent of the specified type.
func CreateAgent(agentType AgentType, name string, options ...any) (Agent, error) {
	switch agentType {
	case AgentTypeLLM:
		// Convert generic options to LLMAgentOption
		opts := make([]LLMAgentOption, 0, len(options))
		for _, opt := range options {
			if llmOpt, ok := opt.(LLMAgentOption); ok {
				opts = append(opts, llmOpt)
			}
		}
		return NewLLMAgent(name, opts...), nil

	case AgentTypeSequential:
		// Convert generic options to SequentialAgentOption
		opts := make([]SequentialAgentOption, 0, len(options))
		for _, opt := range options {
			if seqOpt, ok := opt.(SequentialAgentOption); ok {
				opts = append(opts, seqOpt)
			}
		}
		return NewSequentialAgent(name, opts...), nil

	case AgentTypeParallel:
		// Convert generic options to ParallelAgentOption
		opts := make([]ParallelAgentOption, 0, len(options))
		for _, opt := range options {
			if parOpt, ok := opt.(ParallelAgentOption); ok {
				opts = append(opts, parOpt)
			}
		}
		return NewParallelAgent(name, opts...), nil

	case AgentTypeLoop:
		// Convert generic options to LoopAgentOption
		opts := make([]LoopAgentOption, 0, len(options))
		for _, opt := range options {
			if loopOpt, ok := opt.(LoopAgentOption); ok {
				opts = append(opts, loopOpt)
			}
		}
		return NewLoopAgent(name, opts...), nil

	case AgentTypeRemote:
		// Convert generic options to RemoteAgentOption
		opts := make([]RemoteAgentOption, 0, len(options))
		for _, opt := range options {
			if remoteOpt, ok := opt.(RemoteAgentOption); ok {
				opts = append(opts, remoteOpt)
			}
		}
		return NewRemoteAgent(name, opts...), nil

	default:
		return nil, fmt.Errorf("unknown agent type: %s", agentType)
	}
}
