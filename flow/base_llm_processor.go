// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"iter"

	"github.com/go-a2a/adk-go/types"
)

// BaseLLMRequestProcessor represents a base class for LLM request processor.
type BaseLLMRequestProcessor interface {
	// Run runs the processor.
	Run(ctx context.Context, ic *types.InvocationContext, req *types.LLMRequest) iter.Seq2[*types.Event, error]
}

// BaseLLMResponseProcessor represents a base class for LLM response processor.
type BaseLLMResponseProcessor interface {
	// Run processes the LLM response.
	Run(ctx context.Context, ic *types.InvocationContext, resp *types.LLMResponse) iter.Seq2[*types.Event, error]
}
