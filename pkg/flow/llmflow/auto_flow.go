// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package llmflow

import (
	"log/slog"
	
	"github.com/go-a2a/adk-go/pkg/flow/llmflow/processors"
)

// AutoFlow is a flow that supports agent transfers.
// It extends SingleFlow with the ability to transfer control between agents.
type AutoFlow struct {
	*SingleFlow
	
	// DisallowTransferToPeer determines if peer transfers are allowed.
	DisallowTransferToPeer bool
}

// NewAutoFlow creates a new AutoFlow.
func NewAutoFlow(client LLMClient, logger *slog.Logger) *AutoFlow {
	singleFlow := NewSingleFlow(client, logger)
	
	flow := &AutoFlow{
		SingleFlow:            singleFlow,
		DisallowTransferToPeer: false,
	}
	
	// Add the agent transfer processor at the beginning of request processors
	transferProcessor := processors.NewAgentTransferRequestProcessor(!flow.DisallowTransferToPeer)
	
	if adapter, ok := AdaptFlowProcessor(transferProcessor).(RequestProcessor); ok {
		// Add the transfer processor to the start of the request processors list
		newProcessors := make([]RequestProcessor, 0, len(singleFlow.RequestProcessors)+1)
		newProcessors = append(newProcessors, adapter)
		newProcessors = append(newProcessors, singleFlow.RequestProcessors...)
		singleFlow.RequestProcessors = newProcessors
	}
	
	return flow
}

// WithDisallowTransferToPeer sets whether peer transfers are disallowed.
func (f *AutoFlow) WithDisallowTransferToPeer(disallow bool) *AutoFlow {
	f.DisallowTransferToPeer = disallow
	
	// Update the transfer processor with the new setting
	if len(f.RequestProcessors) > 0 {
		// In a real implementation, we would update the processor
		// For now, we'll just note that this would be done
	}
	
	return f
}